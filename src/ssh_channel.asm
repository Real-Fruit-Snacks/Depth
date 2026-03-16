; ssh_channel.asm - SSH channel multiplexing (RFC 4254)
; Works over the ENCRYPTED transport (after kex + auth)
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "syscall.inc"

; External functions
extern ssh_send_packet_enc
extern ssh_recv_packet_enc
extern encode_string
extern encode_uint32
extern decode_uint32
extern stack_probe

; SSH state structure offsets (must match ssh_transport.asm)
%define SSH_STATE_K1_C2S     0
%define SSH_STATE_K2_C2S     32
%define SSH_STATE_SEQ_C2S    64
%define SSH_STATE_K1_S2C     68
%define SSH_STATE_K2_S2C     100
%define SSH_STATE_SEQ_S2C    132
%define SSH_STATE_SESSION_ID 136
%define SSH_STATE_ROLE       168
%define SSH_STATE_SIZE       176

; Channel constants
%define SSH_INITIAL_WINDOW   0x200000    ; 2MB
%define SSH_MAX_PACKET_DATA  0x8000      ; 32KB

; Channel buffer layout
%define CHAN_BUF_SIZE    (SSH_MAX_PACKET_DATA + 64)  ; 32832 - one full packet + framing
%define CHAN_FRAME_SIZE  (CHAN_BUF_SIZE * 2 + 64)    ; send buf + recv buf + locals
%define CHAN_SEND_BUF    0                            ; offset for send buffer
%define CHAN_RECV_BUF    CHAN_BUF_SIZE                ; offset for recv buffer
%define CHAN_LOCALS      (CHAN_BUF_SIZE * 2)          ; offset for local variables

section .rodata
align 8
str_session:        db "session"
str_session_len     equ $ - str_session

section .text

; ============================================================================
; ssh_channel_table_init(rdi=table_ptr)
; Zeros the entire channel table (MAX_CHANNELS * CHAN_STATE_SIZE bytes)
; ============================================================================
global ssh_channel_table_init
ssh_channel_table_init:
    push rdi
    xor eax, eax
    mov ecx, CHAN_TABLE_SIZE
    rep stosb
    pop rdi
    ret


; ============================================================================
; ssh_channel_alloc(rdi=table_ptr) -> rax=chan_state_ptr or 0
; Finds first slot with CHAN_STATE_TYPE==CHAN_TYPE_UNUSED
; Sets the local_id to the slot index, type to CHAN_TYPE_SESSION
; Returns pointer to the allocated slot, or 0 if table full
; ============================================================================
global ssh_channel_alloc
ssh_channel_alloc:
    xor ecx, ecx               ; slot index = 0
    mov rax, rdi                ; current slot pointer

.alloc_scan:
    cmp ecx, MAX_CHANNELS
    jge .alloc_full

    cmp dword [rax + CHAN_STATE_TYPE], CHAN_TYPE_UNUSED
    je .alloc_found

    add rax, CHAN_STATE_SIZE
    inc ecx
    jmp .alloc_scan

.alloc_found:
    ; Zero the slot first
    push rax
    push rcx
    mov rdi, rax
    push rax
    xor eax, eax
    mov ecx, CHAN_STATE_SIZE
    rep stosb
    pop rax
    pop rcx
    pop rax

    ; Set local_id = slot index, type = SESSION
    mov dword [rax + CHAN_STATE_LOCAL_ID], ecx
    mov dword [rax + CHAN_STATE_TYPE], CHAN_TYPE_SESSION
    ret

.alloc_full:
    xor eax, eax               ; return 0 (NULL)
    ret


; ============================================================================
; ssh_channel_free(rdi=chan_state_ptr)
; Zeros the slot (CHAN_STATE_SIZE bytes), setting type back to UNUSED
; ============================================================================
global ssh_channel_free
ssh_channel_free:
    xor eax, eax
    mov ecx, CHAN_STATE_SIZE
    rep stosb
    ret


; ============================================================================
; ssh_channel_find_by_local_id(rdi=table_ptr, esi=local_id) -> rax=ptr or 0
; Scans table for matching CHAN_STATE_LOCAL_ID where type != UNUSED
; ============================================================================
global ssh_channel_find_by_local_id
ssh_channel_find_by_local_id:
    xor ecx, ecx               ; slot index = 0
    mov rax, rdi                ; current slot pointer

.find_local_scan:
    cmp ecx, MAX_CHANNELS
    jge .find_local_not_found

    cmp dword [rax + CHAN_STATE_TYPE], CHAN_TYPE_UNUSED
    je .find_local_next

    cmp dword [rax + CHAN_STATE_LOCAL_ID], esi
    je .find_local_found

.find_local_next:
    add rax, CHAN_STATE_SIZE
    inc ecx
    jmp .find_local_scan

.find_local_found:
    ret                         ; rax = pointer to matching slot

.find_local_not_found:
    xor eax, eax               ; return 0 (NULL)
    ret

; ============================================================================
; ssh_channel_open_session(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr) -> rax=0 or -1
;
; Client opens a session channel. Sends SSH_MSG_CHANNEL_OPEN("session"):
;   [byte 90][string "session"][uint32 sender_channel=0]
;   [uint32 initial_window_size=2MB][uint32 max_packet_size=32KB]
; Receives SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91):
;   [byte 91][uint32 recipient_channel][uint32 sender_channel]
;   [uint32 initial_window_size][uint32 max_packet_size]
; Or SSH_MSG_CHANNEL_OPEN_FAILURE (92) -> return -1
; Populates chan_state with remote_id, window sizes
; ============================================================================
global ssh_channel_open_session
ssh_channel_open_session:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr

    ; --- Build SSH_MSG_CHANNEL_OPEN payload ---
    lea rbp, [rsp]              ; payload buffer

    ; byte 90 = SSH_MSG_CHANNEL_OPEN
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN
    mov ebx, 1                  ; offset

    ; string "session"
    lea rdi, [rbp + rbx]
    lea rsi, [rel str_session]
    mov edx, str_session_len
    call encode_string
    add ebx, eax

    ; uint32 sender_channel = local_id from chan_state
    lea rdi, [rbp + rbx]
    mov esi, [r14 + CHAN_STATE_LOCAL_ID]
    call encode_uint32
    add ebx, 4

    ; uint32 initial_window_size = 2MB
    lea rdi, [rbp + rbx]
    mov esi, SSH_INITIAL_WINDOW
    call encode_uint32
    add ebx, 4

    ; uint32 max_packet_size = 32KB
    lea rdi, [rbp + rbx]
    mov esi, SSH_MAX_PACKET_DATA
    call encode_uint32
    add ebx, 4

    ; Send encrypted packet
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .open_fail

    ; --- Receive response ---
    lea rsi, [rsp + CHAN_RECV_BUF]
    mov edi, r12d
    mov edx, CHAN_BUF_SIZE
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .open_fail

    lea rbp, [rsp + CHAN_RECV_BUF]

    ; Check for CHANNEL_OPEN_CONFIRMATION (91) or FAILURE (92)
    cmp byte [rbp], SSH_MSG_CHANNEL_OPEN_CONFIRM
    jne .open_fail

    ; Parse confirmation:
    ; [byte 91][uint32 recipient_channel][uint32 sender_channel]
    ; [uint32 initial_window_size][uint32 max_packet_size]

    ; recipient_channel (this is our channel, should match our local_id)
    lea rdi, [rbp + 1]
    call decode_uint32
    ; eax = recipient_channel (should match our local_id, but we don't enforce)

    ; sender_channel = remote's channel ID
    lea rdi, [rbp + 5]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_ID], eax

    ; initial_window_size (remote's window - bytes we can send)
    lea rdi, [rbp + 9]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_WINDOW], eax

    ; max_packet_size (remote's max packet)
    lea rdi, [rbp + 13]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_MAXPKT], eax

    ; Set our local state (local_id already set, preserve it)
    mov dword [r14 + CHAN_STATE_LOCAL_WINDOW], SSH_INITIAL_WINDOW
    mov dword [r14 + CHAN_STATE_LOCAL_MAXPKT], SSH_MAX_PACKET_DATA
    mov dword [r14 + CHAN_STATE_TYPE], CHAN_TYPE_SESSION

    ; Success
    xor eax, eax
    jmp .open_done

.open_fail:
    mov rax, -1

.open_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_channel_accept(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr) -> rax=0 or -1
;
; Server accepts a session channel. Receives SSH_MSG_CHANNEL_OPEN("session"):
;   Parses remote channel id, window size, max packet size
; Sends SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
;   [byte 91][uint32 recipient(=remote_id)][uint32 sender(=0)]
;   [uint32 initial_window=2MB][uint32 max_packet=32KB]
; Populates chan_state
; ============================================================================
global ssh_channel_accept
ssh_channel_accept:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr

    ; --- Receive SSH_MSG_CHANNEL_OPEN ---
    lea rsi, [rsp + CHAN_RECV_BUF]
    mov edi, r12d
    mov edx, CHAN_BUF_SIZE
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .accept_fail

    lea rbp, [rsp + CHAN_RECV_BUF]
    cmp byte [rbp], SSH_MSG_CHANNEL_OPEN
    jne .accept_fail

    ; Parse: [byte 90][string channel_type][uint32 sender_channel]
    ;        [uint32 initial_window][uint32 max_packet]

    ; Skip channel type string: at offset 1, uint32 len + data
    lea rdi, [rbp + 1]
    call decode_uint32          ; eax = channel_type string length
    lea ebx, [eax + 5]         ; offset past msg_type(1) + string header(4) + string data

    ; sender_channel (remote's channel ID)
    lea rdi, [rbp + rbx]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_ID], eax
    add ebx, 4

    ; initial_window_size (remote's window - bytes we can send)
    lea rdi, [rbp + rbx]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_WINDOW], eax
    add ebx, 4

    ; max_packet_size (remote's max packet)
    lea rdi, [rbp + rbx]
    call decode_uint32
    mov [r14 + CHAN_STATE_REMOTE_MAXPKT], eax

    ; Set our local state (local_id already set by caller or alloc, preserve it)
    mov dword [r14 + CHAN_STATE_LOCAL_WINDOW], SSH_INITIAL_WINDOW
    mov dword [r14 + CHAN_STATE_LOCAL_MAXPKT], SSH_MAX_PACKET_DATA
    mov dword [r14 + CHAN_STATE_TYPE], CHAN_TYPE_SESSION

    ; --- Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION ---
    lea rbp, [rsp]

    ; byte 91
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN_CONFIRM
    mov ebx, 1

    ; uint32 recipient_channel = remote's sender channel
    lea rdi, [rbp + rbx]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32
    add ebx, 4

    ; uint32 sender_channel = our local id
    lea rdi, [rbp + rbx]
    mov esi, [r14 + CHAN_STATE_LOCAL_ID]
    call encode_uint32
    add ebx, 4

    ; uint32 initial_window_size = 2MB
    lea rdi, [rbp + rbx]
    mov esi, SSH_INITIAL_WINDOW
    call encode_uint32
    add ebx, 4

    ; uint32 max_packet_size = 32KB
    lea rdi, [rbp + rbx]
    mov esi, SSH_MAX_PACKET_DATA
    call encode_uint32
    add ebx, 4

    ; Send encrypted packet
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .accept_fail

    ; Success
    xor eax, eax
    jmp .accept_done

.accept_fail:
    mov rax, -1

.accept_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_channel_send_data(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;                       rcx=data, r8d=data_len) -> rax=0 or -1
;
; Sends SSH_MSG_CHANNEL_DATA:
;   [byte 94][uint32 recipient_channel][string data]
; Respects remote window size (decrements). If window exhausted, returns -1.
; ============================================================================
global ssh_channel_send_data
ssh_channel_send_data:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr
    mov r15, rcx                ; data ptr
    mov [rsp + CHAN_LOCALS], r8d       ; data_len

    ; Check remote window
    mov eax, [rsp + CHAN_LOCALS]       ; data_len
    cmp eax, [r14 + CHAN_STATE_REMOTE_WINDOW]
    ja .send_data_fail          ; not enough window

    ; --- Build SSH_MSG_CHANNEL_DATA payload ---
    lea rbp, [rsp]

    ; byte 94 = SSH_MSG_CHANNEL_DATA
    mov byte [rbp], SSH_MSG_CHANNEL_DATA
    mov ebx, 1

    ; uint32 recipient_channel
    lea rdi, [rbp + rbx]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32
    add ebx, 4

    ; string data
    lea rdi, [rbp + rbx]
    mov rsi, r15                ; data ptr
    mov edx, [rsp + CHAN_LOCALS]      ; data_len
    call encode_string
    add ebx, eax

    ; Send encrypted packet
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .send_data_fail

    ; Decrement remote window
    mov eax, [rsp + CHAN_LOCALS]
    sub [r14 + CHAN_STATE_REMOTE_WINDOW], eax

    ; Success
    xor eax, eax
    jmp .send_data_done

.send_data_fail:
    mov rax, -1

.send_data_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_channel_recv(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;                  rcx=buf, r8d=max_len) -> rax=bytes or msg_type(-96..-100)
;
; Receives next encrypted packet and dispatches:
;   CHANNEL_DATA (94)          -> copy data to buf, return data_len
;   CHANNEL_WINDOW_ADJUST (93) -> update local window, loop to recv again
;   CHANNEL_EOF (96)           -> return -96
;   CHANNEL_CLOSE (97)         -> return -97
;   CHANNEL_REQUEST (98)       -> return -98 (caller handles)
; Returns: positive = data bytes, negative = -msg_type for control messages
; ============================================================================
global ssh_channel_recv
ssh_channel_recv:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr
    mov r15, rcx                ; output buf
    mov [rsp + CHAN_LOCALS], r8d       ; max_len

.recv_loop:
    ; Receive encrypted packet
    lea rsi, [rsp + CHAN_RECV_BUF]
    mov edi, r12d
    mov edx, CHAN_BUF_SIZE
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .recv_fail

    lea rbp, [rsp + CHAN_RECV_BUF]
    movzx eax, byte [rbp]

    ; Dispatch on message type
    cmp al, SSH_MSG_CHANNEL_DATA
    je .recv_data
    cmp al, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je .recv_window_adjust
    cmp al, SSH_MSG_CHANNEL_EOF
    je .recv_eof
    cmp al, SSH_MSG_CHANNEL_CLOSE
    je .recv_close
    cmp al, SSH_MSG_CHANNEL_REQUEST
    je .recv_request

    ; Unknown message type - fail
    jmp .recv_fail

.recv_data:
    ; Parse: [byte 94][uint32 recipient_channel][string data]
    ; Skip recipient_channel (4 bytes at offset 1)
    ; Data string at offset 5: [uint32 len][data bytes]
    lea rdi, [rbp + 5]
    call decode_uint32          ; eax = data_len
    mov ebx, eax                ; save data_len

    ; Check against max_len
    cmp ebx, [rsp + CHAN_LOCALS]
    ja .recv_fail               ; data too large for buffer

    ; Copy data to output buffer
    ; src = rbp + 9, dst = r15, len = ebx
    mov ecx, ebx
    lea rsi, [rbp + 9]
    mov rdi, r15
    rep movsb

    ; Decrement local window by data_len
    sub [r14 + CHAN_STATE_LOCAL_WINDOW], ebx

    ; Return data_len
    mov eax, ebx
    jmp .recv_done

.recv_window_adjust:
    ; Parse: [byte 93][uint32 recipient_channel][uint32 bytes_to_add]
    lea rdi, [rbp + 5]         ; skip msg_type(1) + recipient_channel(4)
    call decode_uint32          ; eax = bytes_to_add
    add [r14 + CHAN_STATE_REMOTE_WINDOW], eax

    ; Loop to receive next packet
    jmp .recv_loop

.recv_eof:
    mov rax, -96
    jmp .recv_done

.recv_close:
    mov rax, -97
    jmp .recv_done

.recv_request:
    mov rax, -98
    jmp .recv_done

.recv_fail:
    mov rax, -1

.recv_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_channel_send_eof_close(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr) -> rax=0
;
; Sends SSH_MSG_CHANNEL_EOF then SSH_MSG_CHANNEL_CLOSE
; ============================================================================
global ssh_channel_send_eof_close
ssh_channel_send_eof_close:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr

    ; --- Send SSH_MSG_CHANNEL_EOF ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_CHANNEL_EOF

    ; uint32 recipient_channel
    lea rdi, [rbp + 1]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    ; Send: 1 + 4 = 5 bytes
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .eof_close_fail

    ; --- Send SSH_MSG_CHANNEL_CLOSE ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_CHANNEL_CLOSE

    ; uint32 recipient_channel
    lea rdi, [rbp + 1]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    ; Send: 1 + 4 = 5 bytes
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .eof_close_fail

    xor eax, eax
    jmp .eof_close_done

.eof_close_fail:
    mov rax, -1

.eof_close_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_channel_send_window_adjust(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;                                 ecx=bytes_to_add) -> rax=0 or -1
;
; Sends SSH_MSG_CHANNEL_WINDOW_ADJUST:
;   [byte 93][uint32 recipient_channel][uint32 bytes_to_add]
; ============================================================================
global ssh_channel_send_window_adjust
ssh_channel_send_window_adjust:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, CHAN_FRAME_SIZE
    call stack_probe
    sub rsp, CHAN_FRAME_SIZE

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr
    mov r15d, ecx               ; bytes_to_add

    ; --- Build SSH_MSG_CHANNEL_WINDOW_ADJUST payload ---
    lea rbp, [rsp]

    ; byte 93
    mov byte [rbp], SSH_MSG_CHANNEL_WINDOW_ADJUST
    mov ebx, 1

    ; uint32 recipient_channel
    lea rdi, [rbp + rbx]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32
    add ebx, 4

    ; uint32 bytes_to_add
    lea rdi, [rbp + rbx]
    mov esi, r15d
    call encode_uint32
    add ebx, 4

    ; Update local window tracking
    add [r14 + CHAN_STATE_LOCAL_WINDOW], r15d

    ; Send encrypted packet
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .wa_fail

    xor eax, eax
    jmp .wa_done

.wa_fail:
    mov rax, -1

.wa_done:
    add rsp, CHAN_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
