; Test harness for SSH password authentication
; Reads from stdin:
;   sock_fd (4 bytes LE) + mode (1 byte: 'c'=client, 's'=server)
;   Client mode ('c'): user_len(4) + username + pass_len(4) + password
;   Server mode ('s'): host_key(64 bytes) + expected_pass_len(4) + expected_pass
;
; Runs kex first, then auth.
; Outputs: 1 byte (0=success, 1=failure) to stdout
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

section .bss
    input_buf:      resb 512
    ssh_state:      resb SSH_STATE_SIZE
    host_keypair:   resb 64
    username_buf:   resb 256
    password_buf:   resb 256

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

    cmp r13d, 'c'
    je .client_mode
    cmp r13d, 's'
    je .server_mode
    jmp .exit_fail

; ============================================================================
; CLIENT MODE
; ============================================================================
.client_mode:
    ; Read user_len(4) + username + pass_len(4) + password
    ; First read user_len
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
    syscall
    cmp eax, ebx
    jne .exit_fail

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
    jz .client_kex                  ; skip read if pass_len is 0
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

    ; Run key exchange as client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .exit_fail

    ; Run auth as client
    ; ssh_auth_client_password(edi=sock_fd, rsi=state_ptr, rdx=username, ecx=user_len,
    ;                          r8=password, r9d=pass_len)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel username_buf]
    mov ecx, ebx               ; user_len
    lea r8, [rel password_buf]
    mov r9d, r14d              ; pass_len
    call ssh_auth_client_password
    test rax, rax
    jnz .auth_fail

    jmp .auth_success

; ============================================================================
; SERVER MODE
; ============================================================================
.server_mode:
    ; Read host_key(64 bytes) + expected_pass_len(4) + expected_pass
    ; Read host keypair (64 bytes)
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

    ; Run key exchange as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .exit_fail

    ; Run auth as server
    ; ssh_auth_server_password(edi=sock_fd, rsi=state_ptr, rdx=expected_pass, ecx=pass_len)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel password_buf]
    mov ecx, r14d
    call ssh_auth_server_password
    test rax, rax
    jnz .auth_fail

    jmp .auth_success

; ============================================================================
; Output and exit
; ============================================================================
.auth_success:
    ; Output byte 0 to stdout
    mov byte [rel input_buf], 0
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall

    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.auth_fail:
    ; Output byte 1 to stdout
    mov byte [rel input_buf], 1
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall

    mov eax, SYS_EXIT
    mov edi, 1
    syscall

.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
