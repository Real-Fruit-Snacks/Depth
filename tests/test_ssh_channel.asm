; Test harness for SSH channel multiplexing
; Reads from stdin:
;   sock_fd (4 bytes LE) + mode (1 byte: 'o'=client open, 'a'=server accept)
;   Client mode ('o'): user_len(4) + username + pass_len(4) + password
;   Server mode ('a'): host_key(64 bytes) + expected_pass_len(4) + expected_pass
;
; After kex+auth, runs channel operations:
;   'o' (client): channel_open -> send "hello" -> recv response -> output response
;   'a' (server): channel_accept -> recv data -> echo it back -> send eof+close
;
; Outputs: received data bytes to stdout (or 1 byte 0x01 on failure)
; Exit code: 0=success, 1=failure

%include "ssh.inc"
%include "syscall.inc"

; SSH state offsets (must match ssh_transport.asm)
%define SSH_STATE_K1_C2S     0
%define SSH_STATE_K2_C2S     32
%define SSH_STATE_SEQ_C2S    64
%define SSH_STATE_K1_S2C     68
%define SSH_STATE_K2_S2C     100
%define SSH_STATE_SEQ_S2C    132
%define SSH_STATE_SESSION_ID 136
%define SSH_STATE_ROLE       168
%define SSH_STATE_SIZE       176

extern ssh_kex_client
extern ssh_kex_server
extern ssh_auth_client_password
extern ssh_auth_server_password
extern ssh_channel_open_session
extern ssh_channel_accept
extern ssh_channel_send_data
extern ssh_channel_recv
extern ssh_channel_send_eof_close

section .bss
    input_buf:      resb 512
    ssh_state:      resb SSH_STATE_SIZE
    chan_state:      resb CHAN_STATE_SIZE
    host_keypair:   resb 64
    username_buf:   resb 256
    password_buf:   resb 256
    data_buf:       resb 1024

section .text
global _start

_start:
    ; Read initial header: sock_fd(4) + mode(1) = 5 bytes
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    lea rsi, [rel input_buf]
    mov edx, 5
    syscall
    cmp rax, 5
    jne .exit_fail

    mov r12d, [rel input_buf]      ; sock_fd
    movzx r13d, byte [rel input_buf + 4] ; mode

    cmp r13d, 'o'
    je .client_mode
    cmp r13d, 'a'
    je .server_mode
    jmp .exit_fail

; ============================================================================
; CLIENT MODE - open channel, send data, recv echo
; ============================================================================
.client_mode:
    ; Read user_len(4) + username + pass_len(4) + password
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov ebx, [rel input_buf]       ; user_len (LE)

    ; Read username
    xor eax, eax
    xor edi, edi
    lea rsi, [rel username_buf]
    mov edx, ebx
    test edx, edx
    jz .client_read_passlen
    syscall
    cmp eax, ebx
    jne .exit_fail

.client_read_passlen:
    ; Read pass_len
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r14d, [rel input_buf]      ; pass_len (LE)

    ; Read password
    xor eax, eax
    xor edi, edi
    lea rsi, [rel password_buf]
    mov edx, r14d
    test edx, edx
    jz .client_kex
    syscall
    cmp eax, r14d
    jne .exit_fail

.client_kex:
    ; Zero ssh_state
    push rbx
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb
    pop rbx

    ; Zero chan_state
    lea rdi, [rel chan_state]
    xor eax, eax
    mov ecx, CHAN_STATE_SIZE
    rep stosb

    ; Run key exchange as client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .exit_fail

    ; Run auth as client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel username_buf]
    mov ecx, ebx               ; user_len
    lea r8, [rel password_buf]
    mov r9d, r14d              ; pass_len
    call ssh_auth_client_password
    test rax, rax
    jnz .exit_fail

    ; Open channel
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    call ssh_channel_open_session
    test rax, rax
    jnz .exit_fail

    ; Send "hello" as channel data
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    lea rcx, [rel .hello_str]
    mov r8d, 5                 ; len("hello")
    call ssh_channel_send_data
    test rax, rax
    jnz .exit_fail

    ; Recv response (echoed data)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    lea rcx, [rel data_buf]
    mov r8d, 1024
    call ssh_channel_recv
    cmp rax, 0
    jle .exit_fail

    ; Output the received data to stdout
    mov edx, eax               ; data_len
    mov eax, SYS_WRITE
    mov edi, 1                 ; stdout
    lea rsi, [rel data_buf]
    syscall

    ; Success exit
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

; ============================================================================
; SERVER MODE - accept channel, recv data, echo back, close
; ============================================================================
.server_mode:
    ; Read host_key(64 bytes) + expected_pass_len(4) + expected_pass
    xor eax, eax
    xor edi, edi
    lea rsi, [rel host_keypair]
    mov edx, 64
    syscall
    cmp rax, 64
    jne .exit_fail

    ; Read expected_pass_len (4 bytes)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r14d, [rel input_buf]      ; pass_len (LE)

    ; Read expected password
    xor eax, eax
    xor edi, edi
    lea rsi, [rel password_buf]
    mov edx, r14d
    test edx, edx
    jz .server_kex
    syscall
    cmp eax, r14d
    jne .exit_fail

.server_kex:
    ; Zero ssh_state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; Zero chan_state
    lea rdi, [rel chan_state]
    xor eax, eax
    mov ecx, CHAN_STATE_SIZE
    rep stosb

    ; Run key exchange as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .exit_fail

    ; Run auth as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel password_buf]
    mov ecx, r14d
    call ssh_auth_server_password
    test rax, rax
    jnz .exit_fail

    ; Accept channel
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    call ssh_channel_accept
    test rax, rax
    jnz .exit_fail

    ; Recv data from client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    lea rcx, [rel data_buf]
    mov r8d, 1024
    call ssh_channel_recv
    cmp rax, 0
    jle .exit_fail

    mov ebx, eax               ; save data_len

    ; Echo data back to client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    lea rcx, [rel data_buf]
    mov r8d, ebx
    call ssh_channel_send_data
    test rax, rax
    jnz .exit_fail

    ; Send EOF + close
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_state]
    call ssh_channel_send_eof_close
    test rax, rax
    jnz .exit_fail

    ; Output the received data to stdout (so test can verify)
    mov edx, ebx
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel data_buf]
    syscall

    ; Success exit
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

; ============================================================================
.exit_fail:
    ; Output failure byte
    mov byte [rel input_buf], 1
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall

    mov eax, SYS_EXIT
    mov edi, 1
    syscall

section .rodata
.hello_str: db "hello"
