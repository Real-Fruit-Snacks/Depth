%include "ssh.inc"
extern sc_reduce

section .bss
    buf: resb 64
    
section .text
global _start
_start:
    ; Read 64 bytes from stdin
    xor eax, eax
    xor edi, edi
    lea rsi, [rel buf]
    mov edx, 64
    syscall
    
    ; Call sc_reduce
    lea rdi, [rel buf]
    call sc_reduce
    
    ; Write first 32 bytes to stdout
    mov eax, 1
    mov edi, 1
    lea rsi, [rel buf]
    mov edx, 32
    syscall
    
    mov eax, 60
    xor edi, edi
    syscall
