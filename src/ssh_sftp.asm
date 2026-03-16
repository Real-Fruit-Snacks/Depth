; ssh_sftp.asm - SFTP v3 subsystem implementation
; Handles SFTP protocol (draft-ietf-secsh-filexfer-02) over SSH channel
; Pure x86-64 Linux syscalls, no libc
;
; Main entry: ssh_sftp_dispatch(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr)
; Called when client requests "subsystem" with name "sftp"
; Runs synchronous request/response loop until channel closes or error

%include "ssh.inc"
%include "syscall.inc"

; External functions
extern ssh_channel_send_data
extern ssh_channel_recv
extern ssh_channel_send_eof_close
extern ssh_channel_send_window_adjust
extern encode_uint32
extern encode_string
extern decode_uint32
extern stack_probe

; ============================================================================
; Stack frame layout for ssh_sftp_dispatch
; ============================================================================
; We need a large frame for buffers:
;   [rsp + 0]      : SFTP recv buffer (8192 bytes) - channel data in
;   [rsp + 8192]   : SFTP send buffer (8192 bytes) - response out
;   [rsp + 16384]  : stat buffer (144 bytes, struct stat)
;   [rsp + 16528]  : path buffer (4096 bytes, null-terminated paths)
;   [rsp + 20624]  : getdents64 buffer (4096 bytes)
;   [rsp + 24720]  : readdir stat buf (144 bytes)
;   [rsp + 24864]  : readdir path buf (4096+256 = 4352 bytes)
;   [rsp + 29216]  : saved registers area (64 bytes)
;   [rsp + 29272]  : mode flag (1 byte: 0=loop, 1=oneshot)
;   Total: 29280 (round up to 29280, 16-byte aligned = 29280)
%define SFTP_FRAME_SIZE    29280
%define SFTP_RECV_BUF      0
%define SFTP_SEND_BUF      8192
%define SFTP_STAT_BUF      16384
%define SFTP_PATH_BUF      16528
%define SFTP_DENTS_BUF     20624
%define SFTP_RSTAT_BUF     24720
%define SFTP_RPATH_BUF     24864
%define SFTP_MODE          29272

; struct stat offsets (x86-64 Linux)
%define STAT_DEV       0
%define STAT_INO       8
%define STAT_NLINK     16
%define STAT_MODE      24
%define STAT_UID       28
%define STAT_GID       32
%define STAT_RDEV      40
%define STAT_SIZE      48
%define STAT_BLKSIZE   56
%define STAT_BLOCKS    64
%define STAT_ATIME     72
%define STAT_ATIME_NS  80
%define STAT_MTIME     88
%define STAT_MTIME_NS  96
%define STAT_SIZE_STRUCT 144

; linux_dirent64 offsets
%define DIRENT_INO     0
%define DIRENT_OFF     8
%define DIRENT_RECLEN  16
%define DIRENT_TYPE    18
%define DIRENT_NAME    19

section .bss
align 16
sftp_handles: resb SFTP_MAX_HANDLES * SFTP_HANDLE_SIZE  ; 128 bytes
sftp_oneshot_ptr: resq 1        ; pointer to pre-received data (0 = blocking mode)
sftp_oneshot_len: resd 1        ; length of pre-received data

section .text

; ============================================================================
; ssh_sftp_dispatch(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr)
;
; Main SFTP dispatch loop. Reads SFTP packets from channel data,
; dispatches by type, sends responses.
; Returns 0 when channel closes, -1 on error.
; ============================================================================
; ============================================================================
; ssh_sftp_init_handles()
; Zeros the SFTP handle table. Call once when SFTP subsystem starts.
; ============================================================================
global ssh_sftp_init_handles
ssh_sftp_init_handles:
    lea rdi, [rel sftp_handles]
    xor eax, eax
    mov ecx, SFTP_MAX_HANDLES * SFTP_HANDLE_SIZE
    rep stosb
    ret

; ============================================================================
; ssh_sftp_process_one(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;                      rcx=data, r8d=data_len) -> rax=0 or -1
;
; Non-blocking: processes one SFTP packet from pre-received channel data.
; Called from event loop when CHANNEL_DATA arrives for a CHAN_TYPE_SFTP channel.
; Handle table state persists between calls (global sftp_handles).
; ============================================================================
; ============================================================================
; ssh_sftp_process_one(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;                      rcx=data, r8d=data_len) -> rax=0 or -1
;
; Non-blocking: sets oneshot globals, calls ssh_sftp_dispatch which processes
; one packet then returns. Handle table persists between calls.
; ============================================================================
global ssh_sftp_process_one
ssh_sftp_process_one:
    mov [rel sftp_oneshot_ptr], rcx
    mov [rel sftp_oneshot_len], r8d
    call ssh_sftp_dispatch
    ; Clear oneshot state
    mov qword [rel sftp_oneshot_ptr], 0
    mov dword [rel sftp_oneshot_len], 0
    ret

global ssh_sftp_dispatch
ssh_sftp_dispatch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, SFTP_FRAME_SIZE
    call stack_probe
    sub rsp, SFTP_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr

    ; Check if oneshot mode — skip handle init (handles persist between calls)
    cmp qword [rel sftp_oneshot_ptr], 0
    jnz .sftp_skip_init

    ; Blocking mode: zero handle table
    call ssh_sftp_init_handles

.sftp_skip_init:
    ; Set blocking mode flag on stack (oneshot mode overrides in .sftp_oneshot_copy)
    mov byte [rsp + SFTP_MODE], 0

.sftp_loop:
    ; Check if oneshot mode (pre-received data via globals)
    mov rax, [rel sftp_oneshot_ptr]
    test rax, rax
    jnz .sftp_oneshot_copy

    ; If we already processed a oneshot packet, exit
    cmp byte [rsp + SFTP_MODE], 1
    je .sftp_done_no_cleanup

    ; Blocking mode: receive channel data containing SFTP packet
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_RECV_BUF]
    mov r8d, 8192
    call ssh_channel_recv
    ; rax > 0: data bytes, -96: EOF, -97: CLOSE, -98: REQUEST, -1: error

    cmp rax, -97
    je .sftp_done               ; channel closed
    cmp rax, -96
    je .sftp_done               ; EOF
    cmp rax, 0
    jle .sftp_done              ; error or other control
    jmp .sftp_dispatch_body

.sftp_oneshot_copy:
    ; Copy pre-received data to recv buffer
    lea rdi, [rsp + SFTP_RECV_BUF]
    mov rsi, rax                ; sftp_oneshot_ptr
    mov ecx, [rel sftp_oneshot_len]
    mov eax, ecx                ; rax = data_len for dispatch
    rep movsb
    ; Clear oneshot ptr and set mode flag so we exit after processing
    mov qword [rel sftp_oneshot_ptr], 0
    mov byte [rsp + SFTP_MODE], 1

.sftp_dispatch_body:
    ; rax = number of bytes received/provided
    ; SFTP packet format: [uint32 length][uint8 type][uint32 request_id][...data]
    ; Minimum packet: 4 (length) + 1 (type) = 5 bytes
    cmp rax, 5
    jl .sftp_done

    ; Parse SFTP packet length
    lea rdi, [rsp + SFTP_RECV_BUF]
    call decode_uint32          ; eax = sftp_pkt_len
    mov ebx, eax                ; save pkt_len

    ; Parse type byte
    movzx eax, byte [rsp + SFTP_RECV_BUF + 4]
    mov ebp, eax                ; ebp = type

    ; For INIT, there's no request_id (just version)
    cmp ebp, SSH_FXP_INIT
    je .sftp_init

    ; Parse request_id (at offset 5)
    cmp ebx, 5                  ; need at least type(1) + request_id(4) = 5 in pkt_len
    jl .sftp_done
    lea rdi, [rsp + SFTP_RECV_BUF + 5]
    call decode_uint32
    mov r15d, eax               ; r15d = request_id

    ; Dispatch by type
    cmp ebp, SSH_FXP_OPEN
    je .sftp_open
    cmp ebp, SSH_FXP_CLOSE
    je .sftp_close
    cmp ebp, SSH_FXP_READ
    je .sftp_read
    cmp ebp, SSH_FXP_WRITE
    je .sftp_write
    cmp ebp, SSH_FXP_STAT
    je .sftp_stat
    cmp ebp, SSH_FXP_LSTAT
    je .sftp_lstat
    cmp ebp, SSH_FXP_FSTAT
    je .sftp_fstat
    cmp ebp, SSH_FXP_OPENDIR
    je .sftp_opendir
    cmp ebp, SSH_FXP_READDIR
    je .sftp_readdir
    cmp ebp, SSH_FXP_REMOVE
    je .sftp_remove
    cmp ebp, SSH_FXP_MKDIR
    je .sftp_mkdir
    cmp ebp, SSH_FXP_RMDIR
    je .sftp_rmdir
    cmp ebp, SSH_FXP_REALPATH
    je .sftp_realpath
    cmp ebp, SSH_FXP_RENAME
    je .sftp_rename
    cmp ebp, SSH_FXP_SETSTAT
    je .sftp_setstat

    ; Unknown type: send STATUS(OP_UNSUPPORTED)
    mov esi, SSH_FX_OP_UNSUPPORTED
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_INIT handler
; Client sends: [uint32 len=5][uint8 type=1][uint32 version=3]
; Server responds: [uint32 len=5][uint8 type=2][uint32 version=3]
; ============================================================================
.sftp_init:
    lea rdi, [rsp + SFTP_SEND_BUF]
    ; length = 5 (type + version)
    mov dword [rdi], 0x05000000     ; big-endian 5
    mov byte [rdi + 4], SSH_FXP_VERSION
    ; version = 3
    mov dword [rdi + 5], 0x03000000 ; big-endian 3

    ; Send 9 bytes
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    mov r8d, 9
    call ssh_channel_send_data
    jmp .sftp_loop

; ============================================================================
; SSH_FXP_OPEN handler
; Client sends: [uint32 id][string filename][uint32 pflags][ATTRS]
; Payload starts at offset 9 (after length+type+id)
; ============================================================================
.sftp_open:
    ; Parse filename string
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32          ; eax = filename_len
    mov ecx, eax                ; ecx = filename_len

    ; Copy filename to path buf and null-terminate
    cmp ecx, 4095
    ja .sftp_open_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0           ; null terminate
    pop rcx

    ; pflags at offset 9 + 4 + filename_len
    lea eax, [ecx + 13]        ; offset in recv buf
    lea rdi, [rsp + rax]
    push rcx
    call decode_uint32          ; eax = pflags
    pop rcx
    mov ebx, eax                ; ebx = pflags

    ; Convert SFTP pflags to Linux O_* flags
    call sftp_pflags_to_oflags  ; eax = O_flags from ebx
    mov ebp, eax                ; ebp = O_flags

    ; Get mode from attrs (after pflags)
    ; ATTRS at offset 9+4+filename_len+4
    ; For simplicity: use 0644 as default mode
    mov edx, 0o644              ; default mode

    ; Parse attrs to check for permissions
    lea eax, [ecx + 17]        ; offset past pflags
    lea rdi, [rsp + rax]
    call decode_uint32          ; eax = attr_flags
    test eax, SSH_FILEXFER_ATTR_SIZE
    jz .sftp_open_no_size
    add rdi, 12                 ; skip attr_flags(4) + size(8)
    jmp .sftp_open_check_uidgid
.sftp_open_no_size:
    add rdi, 4                  ; skip attr_flags only
.sftp_open_check_uidgid:
    ; We skip parsing uid/gid/permissions for open - use default mode
    ; (full attrs parsing is complex and most clients don't send it for open)

    ; openat(AT_FDCWD, path, flags, mode)
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    mov edx, ebp                ; O_flags
    mov r10d, 0o644             ; mode
    syscall
    test rax, rax
    js .sftp_open_fail

    ; rax = fd, allocate handle
    mov edi, eax                ; fd
    mov esi, 1                  ; type=file
    call sftp_handle_alloc      ; eax = handle index or -1
    cmp eax, -1
    je .sftp_open_close_fail

    ; Send SSH_FXP_HANDLE response
    mov ebx, eax                ; handle index
    jmp .sftp_send_handle

.sftp_open_close_fail:
    ; Close the fd we just opened since we can't allocate a handle
    mov eax, SYS_CLOSE
    syscall
.sftp_open_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_CLOSE handler
; Client sends: [uint32 id][string handle]
; ============================================================================
.sftp_close:
    ; Parse handle
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call sftp_parse_handle      ; eax = handle index or -1
    cmp eax, -1
    je .sftp_close_fail

    ; Free the handle (closes fd)
    mov edi, eax
    call sftp_handle_free

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_close_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_READ handler
; Client sends: [uint32 id][string handle][uint64 offset][uint32 len]
; ============================================================================
.sftp_read:
    ; Parse handle
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call sftp_parse_handle
    cmp eax, -1
    je .sftp_read_fail

    ; Get fd from handle
    mov edi, eax
    call sftp_handle_get_fd     ; eax = fd
    cmp eax, -1
    je .sftp_read_fail
    mov ebx, eax                ; ebx = fd

    ; Parse offset (uint64 at recv+9+4+4 = recv+17)
    ; Handle string: [uint32 len=4][4 bytes data] = 8 bytes
    lea rdi, [rsp + SFTP_RECV_BUF + 17]
    mov eax, [rdi]
    bswap eax
    mov ecx, eax                ; high 32 bits of offset
    mov eax, [rdi + 4]
    bswap eax
    mov edx, eax                ; low 32 bits of offset
    ; Combine into 64-bit: rcx:rdx -> but actually we need shl rcx, 32 | rdx
    shl rcx, 32
    or rcx, rdx                 ; rcx = 64-bit offset

    ; Parse read length (uint32 at recv+25)
    lea rdi, [rsp + SFTP_RECV_BUF + 25]
    push rcx
    call decode_uint32          ; eax = requested len
    pop rcx
    mov ebp, eax                ; ebp = requested len

    ; Cap at buffer size (leave room for SFTP framing: 4+1+4+4+data = 13+data)
    cmp ebp, 8000
    jbe .sftp_read_len_ok
    mov ebp, 8000
.sftp_read_len_ok:

    ; lseek(fd, offset, SEEK_SET)
    mov eax, SYS_LSEEK
    mov edi, ebx                ; fd
    mov rsi, rcx                ; offset
    xor edx, edx                ; SEEK_SET = 0
    syscall
    test rax, rax
    js .sftp_read_fail

    ; read(fd, buf, len)
    mov eax, SYS_READ
    mov edi, ebx
    lea rsi, [rsp + SFTP_SEND_BUF + 13]  ; leave room for header
    mov edx, ebp
    syscall
    cmp rax, 0
    jl .sftp_read_fail
    je .sftp_read_eof

    ; rax = bytes read, build SSH_FXP_DATA response
    mov ebx, eax                ; bytes read

    lea rdi, [rsp + SFTP_SEND_BUF]
    ; pkt_len = 1(type) + 4(id) + 4(string_len) + data_len = 9 + ebx
    lea eax, [ebx + 9]
    bswap eax
    mov [rdi], eax              ; uint32 pkt_len

    mov byte [rdi + 4], SSH_FXP_DATA

    ; request_id
    mov eax, r15d
    bswap eax
    mov [rdi + 5], eax

    ; string data: [uint32 len][data]
    mov eax, ebx
    bswap eax
    mov [rdi + 9], eax          ; data string length

    ; Data is already at rdi+13 from the read syscall

    ; Total response: 4 + 1 + 4 + 4 + ebx = 13 + ebx
    lea r8d, [ebx + 13]
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    call ssh_channel_send_data

    ; Replenish window after sending large data
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    mov ecx, 0x100000           ; 1MB
    call ssh_channel_send_window_adjust

    jmp .sftp_loop

.sftp_read_eof:
    mov esi, SSH_FX_EOF
    jmp .sftp_send_status

.sftp_read_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_WRITE handler
; Client sends: [uint32 id][string handle][uint64 offset][string data]
; ============================================================================
.sftp_write:
    ; Parse handle
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call sftp_parse_handle
    cmp eax, -1
    je .sftp_write_fail

    mov edi, eax
    call sftp_handle_get_fd
    cmp eax, -1
    je .sftp_write_fail
    mov ebx, eax                ; ebx = fd

    ; Parse offset (at recv+17)
    lea rdi, [rsp + SFTP_RECV_BUF + 17]
    mov eax, [rdi]
    bswap eax
    mov ecx, eax
    mov eax, [rdi + 4]
    bswap eax
    mov edx, eax
    shl rcx, 32
    or rcx, rdx                 ; rcx = offset

    ; lseek
    mov eax, SYS_LSEEK
    mov edi, ebx
    mov rsi, rcx
    xor edx, edx               ; SEEK_SET
    syscall
    test rax, rax
    js .sftp_write_fail

    ; Parse data string (at recv+25)
    lea rdi, [rsp + SFTP_RECV_BUF + 25]
    call decode_uint32          ; eax = data_len
    mov ebp, eax                ; data_len

    ; write(fd, data, data_len)
    mov eax, SYS_WRITE
    mov edi, ebx
    lea rsi, [rsp + SFTP_RECV_BUF + 29]
    mov edx, ebp
    syscall
    cmp rax, 0
    jl .sftp_write_fail

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_write_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_STAT / SSH_FXP_LSTAT handlers
; Client sends: [uint32 id][string path]
; ============================================================================
.sftp_stat:
    ; newfstatat(AT_FDCWD, path, &statbuf, 0)
    mov ebp, 0                  ; flags = 0 (follow symlinks)
    jmp .sftp_stat_common

.sftp_lstat:
    ; newfstatat(AT_FDCWD, path, &statbuf, AT_SYMLINK_NOFOLLOW)
    mov ebp, AT_SYMLINK_NOFOLLOW

.sftp_stat_common:
    ; Parse path string at recv+9
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32          ; eax = path_len
    mov ecx, eax

    ; Copy path to buf and null-terminate
    cmp ecx, 4095
    ja .sftp_stat_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; newfstatat(AT_FDCWD, path, statbuf, flags)
    mov eax, SYS_NEWFSTATAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    lea rdx, [rsp + SFTP_STAT_BUF]
    mov r10d, ebp               ; flags
    syscall
    test rax, rax
    js .sftp_stat_fail

    ; Build SSH_FXP_ATTRS response
    jmp .sftp_send_attrs

.sftp_stat_fail:
    ; Check errno for better status code
    cmp rax, -2                 ; ENOENT
    je .sftp_stat_noent
    cmp rax, -13                ; EACCES
    je .sftp_stat_perm
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status
.sftp_stat_noent:
    mov esi, SSH_FX_NO_SUCH_FILE
    jmp .sftp_send_status
.sftp_stat_perm:
    mov esi, SSH_FX_PERMISSION_DENIED
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_FSTAT handler
; Client sends: [uint32 id][string handle]
; ============================================================================
.sftp_fstat:
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call sftp_parse_handle
    cmp eax, -1
    je .sftp_fstat_fail

    mov edi, eax
    call sftp_handle_get_fd
    cmp eax, -1
    je .sftp_fstat_fail

    ; fstat(fd, &statbuf)
    mov edi, eax
    mov eax, SYS_FSTAT
    lea rsi, [rsp + SFTP_STAT_BUF]
    syscall
    test rax, rax
    js .sftp_fstat_fail

    jmp .sftp_send_attrs

.sftp_fstat_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_OPENDIR handler
; Client sends: [uint32 id][string path]
; ============================================================================
.sftp_opendir:
    ; Parse path
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax

    cmp ecx, 4095
    ja .sftp_opendir_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY)
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    mov edx, O_RDONLY | O_DIRECTORY
    xor r10d, r10d
    syscall
    test rax, rax
    js .sftp_opendir_fail

    ; Allocate handle (type=dir)
    mov edi, eax
    mov esi, 2                  ; type=dir
    call sftp_handle_alloc
    cmp eax, -1
    je .sftp_opendir_fail

    mov ebx, eax
    jmp .sftp_send_handle

.sftp_opendir_fail:
    ; Check for ENOENT
    cmp rax, -2
    je .sftp_opendir_noent
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status
.sftp_opendir_noent:
    mov esi, SSH_FX_NO_SUCH_FILE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_READDIR handler
; Client sends: [uint32 id][string handle]
; Responds with SSH_FXP_NAME or SSH_FXP_STATUS(EOF)
; ============================================================================
.sftp_readdir:
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call sftp_parse_handle
    cmp eax, -1
    je .sftp_readdir_fail

    mov edi, eax
    call sftp_handle_get_fd
    cmp eax, -1
    je .sftp_readdir_fail
    mov ebx, eax                ; ebx = dir fd

    ; getdents64(fd, buf, bufsize)
    mov eax, SYS_GETDENTS64
    mov edi, ebx
    lea rsi, [rsp + SFTP_DENTS_BUF]
    mov edx, 4096
    syscall
    cmp rax, 0
    jl .sftp_readdir_fail
    je .sftp_readdir_eof        ; no more entries

    ; rax = bytes of dirent data
    mov ebp, eax                ; ebp = total bytes from getdents64

    ; Build SSH_FXP_NAME response
    ; Format: [uint32 pkt_len][uint8 SSH_FXP_NAME][uint32 request_id][uint32 count]
    ;         [for each: string filename, string longname, ATTRS]
    ; We'll build the entries first, then prepend the header

    ; Start building at send_buf + 13 (leave room for pkt_len(4)+type(1)+id(4)+count(4))
    lea rdi, [rsp + SFTP_SEND_BUF + 13]
    xor ecx, ecx               ; entry count
    xor r8d, r8d               ; offset into dents buf
    ; rdi = current write position in send buf
    ; Max send buf usage: ~7000 bytes to leave headroom

.readdir_entry_loop:
    cmp r8d, ebp
    jge .readdir_entries_done

    ; Parse dirent entry
    lea rsi, [rsp + SFTP_DENTS_BUF + r8]
    movzx eax, word [rsi + DIRENT_RECLEN]
    mov r9d, eax                ; r9d = reclen

    ; Get name pointer and length
    lea r10, [rsi + DIRENT_NAME]  ; name pointer (null-terminated)

    ; Calculate name length (strlen)
    push rdi
    push rcx
    mov rdi, r10
    xor ecx, ecx
.readdir_strlen:
    cmp byte [rdi + rcx], 0
    je .readdir_strlen_done
    inc ecx
    cmp ecx, 255
    jl .readdir_strlen
.readdir_strlen_done:
    mov r11d, ecx               ; r11d = name_len
    pop rcx
    pop rdi

    ; Skip . and .. entries? No, SFTP clients expect them.

    ; Check if we have room in send buffer (rough check)
    ; Each entry: 4+name_len + 4+name_len + 4+4+8+4+4+4+4+4 = 8+2*name_len+36 = 44+2*name_len
    lea eax, [r11d * 2 + 80]
    push rdi
    lea rdi, [rdi + rax]
    lea rax, [rsp + SFTP_SEND_BUF + 7800]
    pop rdi
    push rdi
    add rdi, rax               ; this doesn't make sense, redo
    pop rdi

    ; Simpler room check: current position vs limit
    lea rax, [rsp + SFTP_SEND_BUF + 7800]
    cmp rdi, rax
    jge .readdir_entries_done   ; no room, stop

    ; Max 32 entries per response
    cmp ecx, 32
    jge .readdir_entries_done

    ; Encode filename as string: [uint32 len][data]
    push rcx
    push r8
    push r9

    mov eax, r11d
    bswap eax
    mov [rdi], eax              ; string length
    add rdi, 4

    ; Copy name
    push rdi
    mov rsi, r10
    mov ecx, r11d
    rep movsb
    pop rax                     ; discard saved rdi, rdi now advanced
    ; rdi is now past the name data

    ; Encode longname (same as filename for simplicity)
    mov eax, r11d
    bswap eax
    mov [rdi], eax
    add rdi, 4
    mov rsi, r10
    mov ecx, r11d
    push rdi
    rep movsb
    pop rax                     ; discard, rdi advanced

    ; Now encode ATTRS for this entry
    ; We need to stat the file. Build full path: dir_path/name
    ; For simplicity, use fstatat on the dir fd with the name
    ; newfstatat(dir_fd, name, &statbuf, 0)
    ; name is already null-terminated in the dirent

    push rdi
    mov eax, SYS_NEWFSTATAT
    mov edi, ebx                ; dir fd
    mov rsi, r10                ; name (null-terminated from dirent)
    lea rdx, [rsp + SFTP_RSTAT_BUF + 32] ; +32: push rdi(8) + push rcx/r8/r9(24) above
    xor r10d, r10d              ; flags = 0
    syscall
    pop rdi

    test rax, rax
    js .readdir_zero_attrs

    ; Encode attrs from stat buf
    ; rsp here = original - 24 (rcx, r8, r9 still pushed)
    lea rsi, [rsp + SFTP_RSTAT_BUF + 24] ; +24: compensate for push rcx/r8/r9
    call sftp_encode_attrs_from_stat  ; rdi advanced, eax = bytes written
    jmp .readdir_attr_done

.readdir_zero_attrs:
    ; Write zero attrs: flags=0, 4 bytes
    mov dword [rdi], 0
    add rdi, 4

.readdir_attr_done:
    pop r9
    pop r8
    pop rcx

    inc ecx                     ; count++

    ; Advance to next dirent
    add r8d, r9d
    jmp .readdir_entry_loop

.readdir_entries_done:
    ; ecx = entry count, rdi = end of entries data

    ; If no entries were encoded (shouldn't happen since getdents returned data)
    test ecx, ecx
    jz .sftp_readdir_eof

    ; Calculate total data size
    lea rax, [rsp + SFTP_SEND_BUF + 13]
    sub rdi, rax                ; rdi = entries data size

    ; Now build the header
    lea rax, [rsp + SFTP_SEND_BUF]

    ; pkt_len = 1(type) + 4(id) + 4(count) + entries_size = 9 + entries_size
    lea edx, [edi + 9]         ; edi = entries data size (low 32)
    bswap edx
    mov [rax], edx              ; pkt_len

    mov byte [rax + 4], SSH_FXP_NAME

    mov edx, r15d
    bswap edx
    mov [rax + 5], edx          ; request_id

    bswap ecx
    mov [rax + 9], ecx          ; count

    ; Total send size: 4 + pkt_len = 4 + 9 + entries_size = 13 + entries_size
    lea r8d, [edi + 13]

    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    call ssh_channel_send_data

    ; Replenish window
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    mov ecx, 0x100000           ; 1MB
    call ssh_channel_send_window_adjust

    jmp .sftp_loop

.sftp_readdir_eof:
    mov esi, SSH_FX_EOF
    jmp .sftp_send_status

.sftp_readdir_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_REMOVE handler
; Client sends: [uint32 id][string path]
; ============================================================================
.sftp_remove:
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax

    cmp ecx, 4095
    ja .sftp_remove_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; unlinkat(AT_FDCWD, path, 0)
    mov eax, SYS_UNLINKAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    xor edx, edx               ; flags = 0 (not a directory)
    syscall
    test rax, rax
    js .sftp_remove_fail

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_remove_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_MKDIR handler
; Client sends: [uint32 id][string path][ATTRS]
; ============================================================================
.sftp_mkdir:
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax

    cmp ecx, 4095
    ja .sftp_mkdir_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; mkdirat(AT_FDCWD, path, 0755)
    mov eax, SYS_MKDIRAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    mov edx, 0o755
    syscall
    test rax, rax
    js .sftp_mkdir_fail

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_mkdir_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_RMDIR handler
; Client sends: [uint32 id][string path]
; ============================================================================
.sftp_rmdir:
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax

    cmp ecx, 4095
    ja .sftp_rmdir_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
    mov eax, SYS_UNLINKAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    mov edx, AT_REMOVEDIR
    syscall
    test rax, rax
    js .sftp_rmdir_fail

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_rmdir_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_REALPATH handler
; Client sends: [uint32 id][string path]
; Responds with SSH_FXP_NAME containing 1 entry
; ============================================================================
.sftp_realpath:
    ; Parse path
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax                ; path_len

    ; Copy path to buf
    cmp ecx, 4095
    ja .sftp_realpath_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; Check if path is "." - use getcwd
    cmp ecx, 1
    jne .sftp_realpath_use_path
    cmp byte [rsp + SFTP_PATH_BUF], '.'
    jne .sftp_realpath_use_path

    ; getcwd(buf, size)
    mov eax, SYS_GETCWD
    lea rdi, [rsp + SFTP_PATH_BUF]
    mov esi, 4095
    syscall
    test rax, rax
    js .sftp_realpath_fail

    ; Calculate length of cwd (it's null-terminated)
    lea rdi, [rsp + SFTP_PATH_BUF]
    xor ecx, ecx
.realpath_cwd_len:
    cmp byte [rdi + rcx], 0
    je .realpath_cwd_len_done
    inc ecx
    cmp ecx, 4095
    jl .realpath_cwd_len
.realpath_cwd_len_done:
    jmp .sftp_realpath_send

.sftp_realpath_use_path:
    ; For absolute paths, return as-is
    ; For relative paths, this is simplified (no actual resolution)
    ; ecx still has path_len from above

.sftp_realpath_send:
    ; Build SSH_FXP_NAME with 1 entry
    ; [uint32 pkt_len][uint8 SSH_FXP_NAME][uint32 request_id][uint32 count=1]
    ; [string filename][string longname][ATTRS(flags=0)]
    lea rdi, [rsp + SFTP_SEND_BUF]

    ; Skip header for now, build entries at offset 13
    lea rdi, [rsp + SFTP_SEND_BUF + 13]

    ; filename string
    mov eax, ecx
    bswap eax
    mov [rdi], eax
    add rdi, 4
    push rcx
    lea rsi, [rsp + SFTP_PATH_BUF + 8]  ; +8: compensate for push rcx above
    push rdi
    rep movsb
    pop rax
    pop rcx
    ; rdi is advanced past the name

    ; longname string (same)
    mov eax, ecx
    bswap eax
    mov [rdi], eax
    add rdi, 4
    push rcx
    lea rsi, [rsp + SFTP_PATH_BUF + 8]  ; +8: compensate for push rcx above
    push rdi
    rep movsb
    pop rax
    pop rcx

    ; ATTRS with flags=0 (no attributes)
    mov dword [rdi], 0
    add rdi, 4

    ; Calculate sizes
    lea rax, [rsp + SFTP_SEND_BUF + 13]
    sub rdi, rax                ; entries data size
    mov ebx, edi                ; save in ebx (low 32 bits)

    ; Build header
    lea rdi, [rsp + SFTP_SEND_BUF]

    ; pkt_len = 9 + entries_size
    lea eax, [ebx + 9]
    bswap eax
    mov [rdi], eax

    mov byte [rdi + 4], SSH_FXP_NAME

    mov eax, r15d
    bswap eax
    mov [rdi + 5], eax

    mov dword [rdi + 9], 0x01000000  ; count = 1 (big-endian)

    ; Send
    lea r8d, [ebx + 13]
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    call ssh_channel_send_data

    jmp .sftp_loop

.sftp_realpath_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_RENAME handler
; Client sends: [uint32 id][string oldpath][string newpath]
; ============================================================================
.sftp_rename:
    ; Parse oldpath
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax                ; oldpath_len

    cmp ecx, 2047
    ja .sftp_rename_fail

    ; Copy oldpath to path buf
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; Parse newpath (at recv+13+oldpath_len)
    lea eax, [ecx + 13]
    lea rdi, [rsp + rax]
    push rcx
    call decode_uint32          ; eax = newpath_len
    pop rcx
    mov ebx, eax                ; newpath_len

    cmp ebx, 2047
    ja .sftp_rename_fail

    ; Copy newpath to second half of path buf
    lea eax, [ecx + 17]        ; data starts at recv+13+oldpath_len+4
    lea rsi, [rsp + rax]
    lea rdi, [rsp + SFTP_PATH_BUF + 2048]
    mov ecx, ebx
    rep movsb
    mov byte [rdi], 0

    ; renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
    mov eax, SYS_RENAMEAT2
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF]
    mov edx, AT_FDCWD
    lea r10, [rsp + SFTP_PATH_BUF + 2048]
    xor r8d, r8d               ; flags = 0
    syscall
    test rax, rax
    js .sftp_rename_fail

    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_rename_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; SSH_FXP_SETSTAT handler
; Client sends: [uint32 id][string path][ATTRS]
; ============================================================================
.sftp_setstat:
    ; Parse path
    lea rdi, [rsp + SFTP_RECV_BUF + 9]
    call decode_uint32
    mov ecx, eax

    cmp ecx, 4095
    ja .sftp_setstat_fail
    lea rsi, [rsp + SFTP_RECV_BUF + 13]
    lea rdi, [rsp + SFTP_PATH_BUF]
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    ; Parse attrs (at recv+13+path_len)
    lea eax, [ecx + 13]
    lea rdi, [rsp + rax]
    call decode_uint32          ; eax = attr_flags
    mov ebx, eax                ; attr_flags

    ; Track offset into attrs data (past the flags field)
    lea eax, [ecx + 17]
    mov ebp, eax                ; ebp = offset into recv buf for attr data

    ; Check SIZE flag
    test ebx, SSH_FILEXFER_ATTR_SIZE
    jz .sftp_setstat_check_uidgid
    add ebp, 8                  ; skip uint64 size

.sftp_setstat_check_uidgid:
    test ebx, SSH_FILEXFER_ATTR_UIDGID
    jz .sftp_setstat_check_perms
    add ebp, 8                  ; skip uint32 uid + uint32 gid

.sftp_setstat_check_perms:
    test ebx, SSH_FILEXFER_ATTR_PERMISSIONS
    jz .sftp_setstat_check_time

    ; Parse permissions
    lea rdi, [rsp + rbp]
    push rbx
    call decode_uint32          ; eax = permissions
    pop rbx

    ; fchmodat(AT_FDCWD, path, mode, 0)
    push rbx
    push rbp
    mov r10d, eax               ; save mode
    mov eax, SYS_FCHMODAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF + 16]  ; +16 for two pushes
    mov edx, r10d
    xor r10d, r10d              ; flags
    syscall
    pop rbp
    pop rbx
    ; Ignore errors

    add ebp, 4                  ; skip permissions

.sftp_setstat_check_time:
    test ebx, SSH_FILEXFER_ATTR_ACMODTIME
    jz .sftp_setstat_done

    ; Parse atime and mtime
    lea rdi, [rsp + rbp]
    push rbx
    call decode_uint32          ; eax = atime
    pop rbx
    mov ecx, eax                ; ecx = atime

    lea rdi, [rsp + rbp + 4]
    push rbx
    push rcx
    call decode_uint32          ; eax = mtime
    pop rcx
    pop rbx

    ; Build timespec array on stack for utimensat
    ; timespec[0] = atime: {tv_sec, tv_nsec=0}
    ; timespec[1] = mtime: {tv_sec, tv_nsec=0}
    push rbx
    sub rsp, 32                 ; 2 * sizeof(struct timespec) = 2 * 16 = 32
    mov dword [rsp], ecx        ; atime.tv_sec (low 32)
    mov dword [rsp + 4], 0      ; atime.tv_sec (high 32)
    mov qword [rsp + 8], 0      ; atime.tv_nsec
    mov dword [rsp + 16], eax   ; mtime.tv_sec (low 32)
    mov dword [rsp + 20], 0     ; mtime.tv_sec (high 32)
    mov qword [rsp + 24], 0     ; mtime.tv_nsec

    ; utimensat(AT_FDCWD, path, times, 0)
    mov eax, SYS_UTIMENSAT
    mov edi, AT_FDCWD
    lea rsi, [rsp + SFTP_PATH_BUF + 40]  ; +40 for sub rsp,32 + push
    mov rdx, rsp                ; times
    xor r10d, r10d              ; flags
    syscall

    add rsp, 32
    pop rbx

.sftp_setstat_done:
    mov esi, SSH_FX_OK
    jmp .sftp_send_status

.sftp_setstat_fail:
    mov esi, SSH_FX_FAILURE
    jmp .sftp_send_status

; ============================================================================
; Common response builders
; ============================================================================

; Send SSH_FXP_STATUS response
; Input: esi = status code, r15d = request_id
.sftp_send_status:
    lea rdi, [rsp + SFTP_SEND_BUF]

    ; pkt_len = 1(type) + 4(id) + 4(status) + 4(msg_len=0) + 4(lang_len=0) = 17
    mov dword [rdi], 0x11000000     ; big-endian 17

    mov byte [rdi + 4], SSH_FXP_STATUS

    ; request_id
    mov eax, r15d
    bswap eax
    mov [rdi + 5], eax

    ; status code
    mov eax, esi
    bswap eax
    mov [rdi + 9], eax

    ; error message string (empty)
    mov dword [rdi + 13], 0         ; msg_len = 0

    ; language tag string (empty)
    mov dword [rdi + 17], 0         ; lang_len = 0

    ; Total: 4 + 17 = 21 bytes
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    mov r8d, 21
    call ssh_channel_send_data

    jmp .sftp_loop

; Send SSH_FXP_HANDLE response
; Input: ebx = handle index, r15d = request_id
.sftp_send_handle:
    lea rdi, [rsp + SFTP_SEND_BUF]

    ; pkt_len = 1(type) + 4(id) + 4(string_len) + 4(handle_data) = 13
    mov dword [rdi], 0x0D000000     ; big-endian 13

    mov byte [rdi + 4], SSH_FXP_HANDLE

    ; request_id
    mov eax, r15d
    bswap eax
    mov [rdi + 5], eax

    ; handle string: [uint32 len=4][uint32 handle_index_LE]
    mov dword [rdi + 9], 0x04000000 ; string length = 4 (big-endian)
    mov [rdi + 13], ebx             ; handle index (LE, 4 bytes)

    ; Total: 4 + 13 = 17 bytes
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    mov r8d, 17
    call ssh_channel_send_data

    jmp .sftp_loop

; Send SSH_FXP_ATTRS response from stat buf at [rsp + SFTP_STAT_BUF]
; Input: r15d = request_id
.sftp_send_attrs:
    lea rdi, [rsp + SFTP_SEND_BUF + 9]  ; leave room for pkt_len(4)+type(1)+id(4)
    lea rsi, [rsp + SFTP_STAT_BUF]
    call sftp_encode_attrs_from_stat  ; rdi advanced, eax = bytes written
    mov ebx, eax                ; attrs size

    ; Build header
    lea rdi, [rsp + SFTP_SEND_BUF]

    ; pkt_len = 1(type) + 4(id) + attrs_size = 5 + ebx
    lea eax, [ebx + 5]
    bswap eax
    mov [rdi], eax

    mov byte [rdi + 4], SSH_FXP_ATTRS

    mov eax, r15d
    bswap eax
    mov [rdi + 5], eax

    ; Total: 4 + 5 + ebx = 9 + ebx
    lea r8d, [ebx + 9]
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    lea rcx, [rsp + SFTP_SEND_BUF]
    call ssh_channel_send_data

    jmp .sftp_loop

; ============================================================================
; Exit (oneshot: no handle cleanup, handles persist between calls)
; ============================================================================
.sftp_done_no_cleanup:
    xor eax, eax
    add rsp, SFTP_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; Exit (blocking: close all handles on exit)
; ============================================================================
.sftp_done:
    ; Clean up: close all open handles
    xor ecx, ecx
.sftp_cleanup_handles:
    cmp ecx, SFTP_MAX_HANDLES
    jge .sftp_cleanup_done
    push rcx
    mov edi, ecx
    call sftp_handle_free_if_open
    pop rcx
    inc ecx
    jmp .sftp_cleanup_handles

.sftp_cleanup_done:
    xor eax, eax
    add rsp, SFTP_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; Helper functions
; ============================================================================

; sftp_pflags_to_oflags(ebx=sftp_pflags) -> eax=linux_oflags
sftp_pflags_to_oflags:
    xor eax, eax               ; start with 0

    ; Check read/write combination
    test ebx, SSH_FXF_READ
    jz .pflags_no_read
    test ebx, SSH_FXF_WRITE
    jz .pflags_read_only
    ; Both read and write
    mov eax, O_RDWR
    jmp .pflags_check_extras
.pflags_read_only:
    mov eax, O_RDONLY
    jmp .pflags_check_extras
.pflags_no_read:
    test ebx, SSH_FXF_WRITE
    jz .pflags_check_extras
    mov eax, O_WRONLY

.pflags_check_extras:
    test ebx, SSH_FXF_CREAT
    jz .pflags_no_creat
    or eax, O_CREAT
.pflags_no_creat:
    test ebx, SSH_FXF_TRUNC
    jz .pflags_no_trunc
    or eax, O_TRUNC
.pflags_no_trunc:
    test ebx, SSH_FXF_APPEND
    jz .pflags_no_append
    or eax, O_APPEND
.pflags_no_append:
    test ebx, SSH_FXF_EXCL
    jz .pflags_done
    or eax, O_EXCL
.pflags_done:
    ret

; sftp_handle_alloc(edi=fd, esi=type) -> eax=handle_index or -1
sftp_handle_alloc:
    push rbx
    lea rbx, [rel sftp_handles]
    xor ecx, ecx
.halloc_scan:
    cmp ecx, SFTP_MAX_HANDLES
    jge .halloc_full
    cmp byte [rbx + SFTP_HANDLE_TYPE], 0
    je .halloc_found
    add rbx, SFTP_HANDLE_SIZE
    inc ecx
    jmp .halloc_scan
.halloc_found:
    mov [rbx + SFTP_HANDLE_FD], edi
    mov [rbx + SFTP_HANDLE_TYPE], sil
    mov eax, ecx
    pop rbx
    ret
.halloc_full:
    mov eax, -1
    pop rbx
    ret

; sftp_handle_free(edi=handle_index) - closes fd and frees slot
sftp_handle_free:
    cmp edi, SFTP_MAX_HANDLES
    jge .hfree_done
    cmp edi, 0
    jl .hfree_done

    push rbx
    lea rbx, [rel sftp_handles]
    mov eax, edi
    imul eax, SFTP_HANDLE_SIZE
    add rbx, rax

    cmp byte [rbx + SFTP_HANDLE_TYPE], 0
    je .hfree_done2

    ; Close fd
    push rbx
    mov eax, SYS_CLOSE
    mov edi, [rbx + SFTP_HANDLE_FD]
    syscall
    pop rbx

    ; Clear slot
    mov dword [rbx + SFTP_HANDLE_FD], 0
    mov byte [rbx + SFTP_HANDLE_TYPE], 0

.hfree_done2:
    pop rbx
.hfree_done:
    ret

; sftp_handle_free_if_open(edi=handle_index) - same as free but no error on unused
sftp_handle_free_if_open:
    jmp sftp_handle_free

; sftp_handle_get_fd(edi=handle_index) -> eax=fd or -1
sftp_handle_get_fd:
    cmp edi, SFTP_MAX_HANDLES
    jge .hget_fail
    cmp edi, 0
    jl .hget_fail

    lea rax, [rel sftp_handles]
    mov ecx, edi
    imul ecx, SFTP_HANDLE_SIZE
    add rax, rcx

    cmp byte [rax + SFTP_HANDLE_TYPE], 0
    je .hget_fail

    mov eax, [rax + SFTP_HANDLE_FD]
    ret

.hget_fail:
    mov eax, -1
    ret

; sftp_parse_handle(rdi=pointer to handle string in packet) -> eax=handle_index or -1
; Handle string: [uint32 len][data]
; We expect len=4 and data is a LE uint32 handle index
sftp_parse_handle:
    push rbx
    call decode_uint32          ; eax = string length
    cmp eax, 4
    jne .hparse_fail
    mov eax, [rdi + 4]         ; LE handle index
    ; Validate range
    cmp eax, SFTP_MAX_HANDLES
    jge .hparse_fail
    cmp eax, 0
    jl .hparse_fail
    pop rbx
    ret
.hparse_fail:
    mov eax, -1
    pop rbx
    ret

; sftp_encode_attrs_from_stat(rdi=output, rsi=stat_buf) -> eax=bytes_written, rdi advanced
; Encodes SFTP v3 ATTRS from Linux struct stat
; Output: [uint32 flags][uint64 size][uint32 uid][uint32 gid][uint32 perms][uint32 atime][uint32 mtime]
sftp_encode_attrs_from_stat:
    push rbx
    mov rbx, rdi                ; save start

    ; flags = SIZE|UIDGID|PERMISSIONS|ACMODTIME = 0x0F
    mov dword [rdi], 0x0F000000     ; big-endian 0x0F
    add rdi, 4

    ; uint64 size (big-endian)
    mov rax, [rsi + STAT_SIZE]
    bswap rax
    mov [rdi], rax
    add rdi, 8

    ; uint32 uid
    mov eax, [rsi + STAT_UID]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; uint32 gid
    mov eax, [rsi + STAT_GID]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; uint32 permissions (st_mode)
    mov eax, [rsi + STAT_MODE]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; uint32 atime (truncate to 32-bit)
    mov eax, [rsi + STAT_ATIME]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; uint32 mtime (truncate to 32-bit)
    mov eax, [rsi + STAT_MTIME]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; Total: 4+8+4+4+4+4+4 = 32 bytes
    mov eax, 32
    pop rbx
    ret
