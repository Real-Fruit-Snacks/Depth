%include "ssh.inc"

extern x25519

section .bss
    scalar_buf: resb 32
    point_buf:  resb 32
    out_buf:    resb 32

section .text
global _start

_start:
    ; Read 32 bytes scalar from stdin
    xor r12d, r12d          ; bytes read
.read_scalar:
    xor eax, eax            ; SYS_READ
    xor edi, edi            ; fd 0
    lea rsi, [rel scalar_buf]
    add rsi, r12
    mov edx, 32
    sub edx, r12d
    syscall
    test rax, rax
    jle .read_point
    add r12d, eax
    cmp r12d, 32
    jl .read_scalar

.read_point:
    ; Read 32 bytes point from stdin
    xor r12d, r12d
.read_point_loop:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel point_buf]
    add rsi, r12
    mov edx, 32
    sub edx, r12d
    syscall
    test rax, rax
    jle .do_x25519
    add r12d, eax
    cmp r12d, 32
    jl .read_point_loop

.do_x25519:
    ; x25519(out, scalar, point)
    lea rdi, [rel out_buf]
    lea rsi, [rel scalar_buf]
    lea rdx, [rel point_buf]
    call x25519

    ; Write 32 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, X25519_KEY_SIZE
    syscall

    ; exit(0)
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
