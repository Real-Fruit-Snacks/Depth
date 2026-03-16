%include "ssh.inc"

extern sha256

section .bss
    msg_buf: resb 1048576           ; 1MB max message
    hash_buf: resb 32

section .text
global _start

_start:
    ; Read 4-byte little-endian length from stdin
    sub rsp, 16                     ; alignment + space
    xor eax, eax                    ; SYS_READ
    xor edi, edi                    ; fd 0 (stdin)
    mov rsi, rsp
    mov edx, 4
    syscall

    mov r12d, [rsp]                 ; save message length in callee-saved reg
    add rsp, 16

    ; Read message bytes from stdin
    test r12d, r12d
    jz .do_hash

    ; May need multiple reads for large messages
    xor r13d, r13d                  ; bytes read so far
.read_loop:
    xor eax, eax                    ; SYS_READ
    xor edi, edi                    ; fd 0
    lea rsi, [rel msg_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall

    test rax, rax
    jle .do_hash                    ; EOF or error
    add r13d, eax
    cmp r13d, r12d
    jl .read_loop

.do_hash:
    ; sha256(msg, len, output)
    lea rdi, [rel msg_buf]
    mov esi, r12d
    lea rdx, [rel hash_buf]
    call sha256

    ; Write 32-byte hash to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel hash_buf]
    mov edx, SHA256_DIGEST_SIZE
    syscall

    ; exit(0)
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
