; Test harness for SSH key exchange
; Reads socket fd (4 bytes LE) from stdin
; Runs ssh_kex_client on that fd
; Outputs: session_id(32) + k1_c2s(32) + k2_c2s(32) + k1_s2c(32) + k2_s2c(32) = 160 bytes
; Exit 0 on success, 1 on failure

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

section .bss
    input_buf:  resb 16
    ssh_state:  resb SSH_STATE_SIZE

section .text
global _start

_start:
    ; Read socket fd (4 bytes LE) from stdin
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov edi, [rel input_buf]   ; socket fd

    ; Zero out ssh_state
    push rdi
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb
    pop rdi

    ; Run key exchange
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .exit_fail

    ; Output session_id (32 bytes)
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ssh_state + SSH_STATE_SESSION_ID]
    mov edx, 32
    syscall

    ; Output k1_c2s (32 bytes)
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ssh_state + SSH_STATE_K1_C2S]
    mov edx, 32
    syscall

    ; Output k2_c2s (32 bytes)
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ssh_state + SSH_STATE_K2_C2S]
    mov edx, 32
    syscall

    ; Output k1_s2c (32 bytes)
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ssh_state + SSH_STATE_K1_S2C]
    mov edx, 32
    syscall

    ; Output k2_s2c (32 bytes)
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ssh_state + SSH_STATE_K2_S2C]
    mov edx, 32
    syscall

    jmp .exit_ok

.exit_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
