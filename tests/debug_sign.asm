%include "ssh.inc"

extern sha512
extern ed25519_pubkey, ed25519_sign

; sc_reduce is internal to ed25519.asm, we can't call it directly.
; Instead, let's just call ed25519_sign and dump the full 64-byte sig output,
; and also dump intermediate values by calling sha512 directly.

section .bss
    secret:     resb 32
    pubkey_out: resb 32
    keypair:    resb 64
    sha_out:    resb 64
    buffer:     resb 256
    sig_out:    resb 64
    r_scalar:   resb 64
    hex_buf:    resb 256

section .data
    ; RFC 8032 test vector 1 secret key
    test_secret:
        db 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60
        db 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4
        db 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19
        db 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60

    nl: db 10
    label_sha512: db "SHA-512(secret): ", 0
    label_h_lo: db "h[0:32] (clamped a): ", 0
    label_h_hi: db "h[32:64] (prefix): ", 0
    label_nonce_hash: db "SHA-512(prefix||msg): ", 0
    label_pubkey: db "pubkey: ", 0
    label_sig: db "sig: ", 0
    label_sig_r: db "sig R[0:32]: ", 0
    label_sig_s: db "sig S[32:64]: ", 0

    hex_chars: db "0123456789abcdef"

section .text
global _start

; print_string(rdi=string, null-terminated)
print_string:
    push rdi
    mov rsi, rdi
    xor ecx, ecx
.len:
    cmp byte [rsi+rcx], 0
    je .done_len
    inc ecx
    jmp .len
.done_len:
    mov eax, SYS_WRITE
    mov edi, 2          ; stderr
    mov edx, ecx
    syscall
    pop rdi
    ret

; print_hex(rdi=buf, rsi=len) - print hex to stderr
print_hex:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    xor r14d, r14d
.hex_loop:
    cmp r14, r13
    jge .hex_done
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
    jmp .hex_loop
.hex_done:
    ; print newline
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
    ; Step 1: SHA-512(secret)
    lea rdi, [rel test_secret]
    mov rsi, 32
    lea rdx, [rel sha_out]
    call sha512

    lea rdi, [rel label_sha512]
    call print_string
    lea rdi, [rel sha_out]
    mov rsi, 64
    call print_hex

    ; Print h[0:32]
    lea rdi, [rel label_h_lo]
    call print_string
    lea rdi, [rel sha_out]
    mov rsi, 32
    call print_hex

    ; Print h[32:64]
    lea rdi, [rel label_h_hi]
    call print_string
    lea rdi, [rel sha_out + 32]
    mov rsi, 32
    call print_hex

    ; Step 2: compute nonce hash = SHA-512(h[32:64] || empty_message)
    ; copy h[32:64] to buffer
    lea rsi, [rel sha_out + 32]
    lea rdi, [rel buffer]
    mov ecx, 32
    rep movsb

    lea rdi, [rel buffer]
    mov rsi, 32
    lea rdx, [rel r_scalar]
    call sha512

    lea rdi, [rel label_nonce_hash]
    call print_string
    lea rdi, [rel r_scalar]
    mov rsi, 64
    call print_hex

    ; Step 3: compute pubkey
    lea rdi, [rel pubkey_out]
    lea rsi, [rel test_secret]
    call ed25519_pubkey

    lea rdi, [rel label_pubkey]
    call print_string
    lea rdi, [rel pubkey_out]
    mov rsi, 32
    call print_hex

    ; Step 4: sign empty message
    ; build keypair = secret || pubkey
    lea rdi, [rel keypair]
    lea rsi, [rel test_secret]
    mov ecx, 32
    rep movsb
    lea rdi, [rel keypair + 32]
    lea rsi, [rel pubkey_out]
    mov ecx, 32
    rep movsb

    lea rdi, [rel sig_out]
    lea rsi, [rel keypair + 64]   ; msg = right after keypair (empty = any ptr)
    xor edx, edx                  ; msg_len = 0
    lea rcx, [rel keypair]
    call ed25519_sign

    lea rdi, [rel label_sig]
    call print_string
    lea rdi, [rel sig_out]
    mov rsi, 64
    call print_hex

    lea rdi, [rel label_sig_r]
    call print_string
    lea rdi, [rel sig_out]
    mov rsi, 32
    call print_hex

    lea rdi, [rel label_sig_s]
    call print_string
    lea rdi, [rel sig_out + 32]
    mov rsi, 32
    call print_hex

    ; exit
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
