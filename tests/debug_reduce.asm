%include "ssh.inc"

extern sc_reduce

section .bss
    scalar_buf: resb 64
    hex_buf:    resb 4

section .data
    ; This is SHA-512(prefix || empty_msg) from RFC 8032 vector 1
    ; Python: b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d
    test_nonce_hash:
        db 0xb6, 0xb1, 0x9c, 0xd8, 0xe0, 0x42, 0x6f, 0x59
        db 0x83, 0xfa, 0x11, 0x2d, 0x89, 0xa1, 0x43, 0xaa
        db 0x97, 0xda, 0xb8, 0xbc, 0x5d, 0xeb, 0x8d, 0x5b
        db 0x62, 0x53, 0xc9, 0x28, 0xb6, 0x52, 0x72, 0xf4
        db 0x04, 0x40, 0x98, 0xc2, 0xa9, 0x90, 0x03, 0x9c
        db 0xde, 0x5b, 0x6a, 0x48, 0x18, 0xdf, 0x0b, 0xfb
        db 0x6e, 0x40, 0xdc, 0x5d, 0xee, 0x54, 0x24, 0x80
        db 0x32, 0x96, 0x23, 0x23, 0xe7, 0x01, 0x35, 0x2d

    ; Expected r mod L (from Python):
    ; f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404
    label_input: db "input (64 bytes): ", 0
    label_output: db "sc_reduce output: ", 0
    label_expected: db "expected:         f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404", 10, 0
    nl: db 10
    hex_chars: db "0123456789abcdef"

section .text
global _start

print_string:
    push rdi
    mov rsi, rdi
    xor ecx, ecx
.len:
    cmp byte [rsi+rcx], 0
    je .done
    inc ecx
    jmp .len
.done:
    mov eax, SYS_WRITE
    mov edi, 2
    mov edx, ecx
    syscall
    pop rdi
    ret

print_hex:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    xor r14d, r14d
.loop:
    cmp r14, r13
    jge .done
    movzx eax, byte [r12 + r14]
    mov ecx, eax
    shr ecx, 4
    lea rdx, [rel hex_chars]
    movzx ecx, byte [rdx + rcx]
    and eax, 0x0f
    movzx eax, byte [rdx + rax]
    mov byte [rel hex_buf], cl
    mov byte [rel hex_buf+1], al
    mov eax, SYS_WRITE
    mov edi, 2
    lea rsi, [rel hex_buf]
    mov edx, 2
    syscall
    inc r14
    jmp .loop
.done:
    mov eax, SYS_WRITE
    mov edi, 2
    lea rsi, [rel nl]
    mov edx, 1
    syscall
    pop r14
    pop r13
    pop r12
    ret

_start:
    ; Copy test data to scalar_buf
    lea rsi, [rel test_nonce_hash]
    lea rdi, [rel scalar_buf]
    mov ecx, 64
    rep movsb

    ; Print input
    lea rdi, [rel label_input]
    call print_string
    lea rdi, [rel scalar_buf]
    mov rsi, 64
    call print_hex

    ; Call sc_reduce
    lea rdi, [rel scalar_buf]
    call sc_reduce

    ; Print output
    lea rdi, [rel label_output]
    call print_string
    lea rdi, [rel scalar_buf]
    mov rsi, 32
    call print_hex

    ; Print expected
    lea rdi, [rel label_expected]
    call print_string

    mov eax, SYS_EXIT
    xor edi, edi
    syscall
