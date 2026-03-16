%include "ssh.inc"

extern ed25519_pubkey, ed25519_sign, ed25519_verify

section .bss
    cmd_buf:    resb 1
    secret_buf: resb 32
    keypair_buf: resb 64
    pubkey_buf: resb 32
    sig_buf:    resb 64
    msg_len_buf: resb 4
    msg_buf:    resb 4096
    out_buf:    resb 64

section .text
global _start

; read_exact(rdi=buf, rsi=count) — read exactly count bytes from stdin
read_exact:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    xor ebx, ebx           ; bytes read so far
.re_loop:
    cmp rbx, r13
    jge .re_done
    xor eax, eax           ; SYS_READ
    xor edi, edi            ; fd 0
    lea rsi, [r12 + rbx]
    mov rdx, r13
    sub rdx, rbx
    syscall
    test rax, rax
    jle .re_done
    add rbx, rax
    jmp .re_loop
.re_done:
    pop r13
    pop r12
    ret

_start:
    ; Read 1-byte command
    lea rdi, [rel cmd_buf]
    mov rsi, 1
    call read_exact

    movzx eax, byte [rel cmd_buf]
    cmp al, 'p'
    je .do_pubkey
    cmp al, 's'
    je .do_sign
    cmp al, 'v'
    je .do_verify
    ; Unknown command — exit(2)
    mov eax, SYS_EXIT
    mov edi, 2
    syscall

.do_pubkey:
    ; Read 32-byte secret
    lea rdi, [rel secret_buf]
    mov rsi, 32
    call read_exact

    ; ed25519_pubkey(out, secret)
    lea rdi, [rel out_buf]
    lea rsi, [rel secret_buf]
    call ed25519_pubkey

    ; Write 32 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, 32
    syscall

    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.do_sign:
    ; Read 64-byte keypair (secret || pubkey)
    lea rdi, [rel keypair_buf]
    mov rsi, 64
    call read_exact

    ; Read 4-byte LE msg_len
    lea rdi, [rel msg_len_buf]
    mov rsi, 4
    call read_exact

    ; Read msg
    mov ecx, [rel msg_len_buf]
    test ecx, ecx
    jz .sign_call
    lea rdi, [rel msg_buf]
    movzx rsi, ecx
    call read_exact

.sign_call:
    ; ed25519_sign(sig_out, msg, msg_len, keypair)
    lea rdi, [rel out_buf]
    lea rsi, [rel msg_buf]
    mov edx, [rel msg_len_buf]
    lea rcx, [rel keypair_buf]
    call ed25519_sign

    ; Write 64 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, 64
    syscall

    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.do_verify:
    ; Read 32-byte pubkey
    lea rdi, [rel pubkey_buf]
    mov rsi, 32
    call read_exact

    ; Read 64-byte sig
    lea rdi, [rel sig_buf]
    mov rsi, 64
    call read_exact

    ; Read 4-byte LE msg_len
    lea rdi, [rel msg_len_buf]
    mov rsi, 4
    call read_exact

    ; Read msg
    mov ecx, [rel msg_len_buf]
    test ecx, ecx
    jz .verify_call
    lea rdi, [rel msg_buf]
    movzx rsi, ecx
    call read_exact

.verify_call:
    ; ed25519_verify(sig, msg, msg_len, pubkey)
    lea rdi, [rel sig_buf]
    lea rsi, [rel msg_buf]
    mov edx, [rel msg_len_buf]
    lea rcx, [rel pubkey_buf]
    call ed25519_verify

    ; exit(0) if valid (eax==0), exit(1) if invalid (eax==-1)
    test eax, eax
    jz .verify_ok
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
.verify_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
