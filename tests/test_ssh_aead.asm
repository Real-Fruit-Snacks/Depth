%include "ssh.inc"

extern ssh_aead_encrypt
extern ssh_aead_decrypt
extern ssh_aead_decrypt_length

section .bss
    input_buf:  resb 131072
    output_buf: resb 131072
    k1_buf:     resb 32
    k2_buf:     resb 32
    data_buf:   resb 131072

section .text
global _start

_start:
    ; Read 1 byte command from stdin
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall
    test rax, rax
    jle .exit_fail

    movzx eax, byte [rel input_buf]

    cmp al, 'e'
    je .cmd_encrypt
    cmp al, 'd'
    je .cmd_decrypt
    cmp al, 'l'
    je .cmd_decrypt_length
    jmp .exit_fail

; --- Encrypt command ---
; Read: k1(32) + k2(32) + seq(4 LE) + payload_len(4 LE) + payload
.cmd_encrypt:
    ; Read k1 (32 bytes)
    xor r13d, r13d
.read_k1_enc:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel k1_buf]
    add rsi, r13
    mov edx, 32
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 32
    jl .read_k1_enc

    ; Read k2 (32 bytes)
    xor r13d, r13d
.read_k2_enc:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel k2_buf]
    add rsi, r13
    mov edx, 32
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 32
    jl .read_k2_enc

    ; Read seq(4) + payload_len(4) = 8 bytes
    xor r13d, r13d
.read_hdr_enc:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    add rsi, r13
    mov edx, 8
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 8
    jl .read_hdr_enc

    mov r14d, [rel input_buf]       ; seq_num (LE)
    mov r15d, [rel input_buf + 4]   ; payload_len (LE)

    ; Read payload
    test r15d, r15d
    jz .do_encrypt
    xor r13d, r13d
.read_payload_enc:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel data_buf]
    add rsi, r13
    mov edx, r15d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_encrypt
    add r13d, eax
    cmp r13d, r15d
    jl .read_payload_enc

.do_encrypt:
    ; ssh_aead_encrypt(output, payload, payload_len, k1, k2, seq_num)
    lea rdi, [rel output_buf]
    lea rsi, [rel data_buf]
    mov edx, r15d
    lea rcx, [rel k1_buf]
    lea r8, [rel k2_buf]
    mov r9d, r14d
    call ssh_aead_encrypt
    ; rax = total output bytes

    ; Write output to stdout
    mov rdx, rax            ; length
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

; --- Decrypt command ---
; Read: k1(32) + k2(32) + seq(4 LE) + input_len(4 LE) + input
.cmd_decrypt:
    ; Read k1
    xor r13d, r13d
.read_k1_dec:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel k1_buf]
    add rsi, r13
    mov edx, 32
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 32
    jl .read_k1_dec

    ; Read k2
    xor r13d, r13d
.read_k2_dec:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel k2_buf]
    add rsi, r13
    mov edx, 32
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 32
    jl .read_k2_dec

    ; Read seq(4) + input_len(4)
    xor r13d, r13d
.read_hdr_dec:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    add rsi, r13
    mov edx, 8
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 8
    jl .read_hdr_dec

    mov r14d, [rel input_buf]       ; seq_num
    mov r15d, [rel input_buf + 4]   ; input_len

    ; Read input data
    test r15d, r15d
    jz .do_decrypt
    xor r13d, r13d
.read_input_dec:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel data_buf]
    add rsi, r13
    mov edx, r15d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_decrypt
    add r13d, eax
    cmp r13d, r15d
    jl .read_input_dec

.do_decrypt:
    ; ssh_aead_decrypt(output, input, total_input_len, k1, k2, seq_num)
    lea rdi, [rel output_buf]
    lea rsi, [rel data_buf]
    mov edx, r15d
    lea rcx, [rel k1_buf]
    lea r8, [rel k2_buf]
    mov r9d, r14d
    call ssh_aead_decrypt
    ; rax = payload_len on success, -1 on failure

    cmp rax, -1
    je .exit_fail

    ; Write decrypted payload to stdout
    mov rdx, rax
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

; --- Decrypt length command ---
; Read: k2(32) + seq(4 LE) + enc_len(4)
.cmd_decrypt_length:
    ; Read k2
    xor r13d, r13d
.read_k2_len:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel k2_buf]
    add rsi, r13
    mov edx, 32
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 32
    jl .read_k2_len

    ; Read seq(4) + enc_len(4) = 8 bytes
    xor r13d, r13d
.read_hdr_len:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    add rsi, r13
    mov edx, 8
    sub edx, r13d
    syscall
    test rax, rax
    jle .exit_fail
    add r13d, eax
    cmp r13d, 8
    jl .read_hdr_len

    mov r14d, [rel input_buf]       ; seq_num
    ; enc_len bytes are at input_buf+4

    ; ssh_aead_decrypt_length(output4, enc_length4, k2, seq_num)
    lea rdi, [rel output_buf]
    lea rsi, [rel input_buf + 4]
    lea rdx, [rel k2_buf]
    mov ecx, r14d
    call ssh_aead_decrypt_length

    ; Write 4 bytes (LE uint32) to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    mov edx, 4
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
