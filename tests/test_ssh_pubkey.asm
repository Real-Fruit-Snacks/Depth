; Test harness for SSH public key authentication
; Reads from stdin:
;   sock_fd (4 bytes LE) + mode (1 byte: 'k'=pubkey-only, 'a'=any)
;   Mode 'k': host_key(64) + num_authorized_keys(4 LE) + authorized_keys(32*N)
;   Mode 'a': host_key(64) + num_authorized_keys(4 LE) + authorized_keys(32*N)
;             + pass_len(4 LE) + password
;
; Runs kex_server first, then auth.
; Outputs: 1 byte (0=success, 1=failure) to stdout
; Exit code: 0=success, 1=failure

%include "ssh.inc"
%include "syscall.inc"

%define SSH_STATE_K1_C2S     0
%define SSH_STATE_K2_C2S     32
%define SSH_STATE_SEQ_C2S    64
%define SSH_STATE_K1_S2C     68
%define SSH_STATE_K2_S2C     100
%define SSH_STATE_SEQ_S2C    132
%define SSH_STATE_SESSION_ID 136
%define SSH_STATE_ROLE       168
%define SSH_STATE_SIZE       176

extern ssh_kex_server
extern ssh_auth_server_pubkey
extern ssh_auth_server_any

section .bss
    input_buf:        resb 512
    ssh_state:        resb SSH_STATE_SIZE
    host_keypair:     resb 64
    authorized_keys:  resb 128          ; 4 * 32 bytes max
    password_buf:     resb 256

section .data
    num_auth_keys:    dd 0
    pass_len:         dd 0

section .text
global _start

_start:
    ; Read initial header: sock_fd(4) + mode(1) = 5 bytes
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 5
    syscall
    cmp rax, 5
    jne .exit_fail

    mov r12d, [rel input_buf]
    movzx r13d, byte [rel input_buf + 4]

    cmp r13d, 'k'
    je .pubkey_mode
    cmp r13d, 'a'
    je .any_mode
    jmp .exit_fail

; ============================================================================
; PUBKEY-ONLY MODE ('k')
; ============================================================================
.pubkey_mode:
    ; Read host_key(64)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel host_keypair]
    mov edx, 64
    syscall
    cmp rax, 64
    jne .exit_fail

    ; Read num_authorized_keys(4)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov eax, [rel input_buf]
    mov [rel num_auth_keys], eax
    mov r14d, eax              ; num_keys

    ; Read authorized_keys (32 * num_keys bytes)
    mov edx, r14d
    shl edx, 5                 ; * 32
    test edx, edx
    jz .pubkey_kex
    xor eax, eax
    xor edi, edi
    lea rsi, [rel authorized_keys]
    syscall
    mov edx, r14d
    shl edx, 5
    cmp eax, edx
    jne .exit_fail

.pubkey_kex:
    ; Zero ssh_state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; Run kex as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .exit_fail

    ; Run pubkey auth
    ; ssh_auth_server_pubkey(edi=sock_fd, rsi=state_ptr, rdx=keys_ptr, ecx=num_keys)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel authorized_keys]
    mov ecx, r14d
    call ssh_auth_server_pubkey
    test rax, rax
    jnz .auth_fail

    jmp .auth_success

; ============================================================================
; ANY AUTH MODE ('a')
; ============================================================================
.any_mode:
    ; Read host_key(64)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel host_keypair]
    mov edx, 64
    syscall
    cmp rax, 64
    jne .exit_fail

    ; Read num_authorized_keys(4)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov eax, [rel input_buf]
    mov [rel num_auth_keys], eax
    mov r14d, eax

    ; Read authorized_keys
    mov edx, r14d
    shl edx, 5
    test edx, edx
    jz .any_read_pass
    xor eax, eax
    xor edi, edi
    lea rsi, [rel authorized_keys]
    syscall
    mov edx, r14d
    shl edx, 5
    cmp eax, edx
    jne .exit_fail

.any_read_pass:
    ; Read pass_len(4)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov eax, [rel input_buf]
    mov [rel pass_len], eax
    mov r15d, eax

    ; Read password
    test r15d, r15d
    jz .any_kex
    xor eax, eax
    xor edi, edi
    lea rsi, [rel password_buf]
    mov edx, r15d
    syscall
    cmp eax, r15d
    jne .exit_fail

.any_kex:
    ; Zero ssh_state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; Run kex as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .exit_fail

    ; Run any auth
    ; ssh_auth_server_any(edi=sock_fd, rsi=state_ptr, rdx=password_ptr,
    ;                     ecx=password_len, r8=authorized_keys_ptr, r9d=num_keys)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel password_buf]
    mov ecx, r15d
    lea r8, [rel authorized_keys]
    mov r9d, r14d
    call ssh_auth_server_any
    test rax, rax
    jnz .auth_fail

    jmp .auth_success

; ============================================================================
; Output and exit
; ============================================================================
.auth_success:
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
