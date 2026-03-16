; Test harness for HMAC-SHA256
; Reads from stdin: key_len(4 LE) + key + msg_len(4 LE) + message
; Writes 32 bytes HMAC-SHA256 output to stdout
; Exit 0

%include "ssh.inc"

extern hmac_sha256

section .bss
    key_buf:  resb 1024                 ; max key size
    msg_buf:  resb 1048576              ; 1MB max message
    out_buf:  resb 32                   ; HMAC output

section .text
global _start

_start:
    ; Read 4-byte little-endian key length
    sub rsp, 16
    xor eax, eax                        ; SYS_READ
    xor edi, edi                        ; stdin
    mov rsi, rsp
    mov edx, 4
    syscall

    mov r12d, [rsp]                     ; r12d = key_len
    add rsp, 16

    ; Read key bytes
    test r12d, r12d
    jz .read_msg_len

    xor r13d, r13d                      ; bytes read so far
.read_key_loop:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel key_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .read_msg_len
    add r13d, eax
    cmp r13d, r12d
    jl .read_key_loop

.read_msg_len:
    ; Read 4-byte little-endian message length
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall

    mov r14d, [rsp]                     ; r14d = msg_len
    add rsp, 16

    ; Read message bytes
    test r14d, r14d
    jz .do_hmac

    xor r13d, r13d
.read_msg_loop:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel msg_buf]
    add rsi, r13
    mov edx, r14d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_hmac
    add r13d, eax
    cmp r13d, r14d
    jl .read_msg_loop

.do_hmac:
    ; hmac_sha256(key, key_len, msg, msg_len, output)
    lea rdi, [rel key_buf]
    mov esi, r12d
    lea rdx, [rel msg_buf]
    mov ecx, r14d
    lea r8, [rel out_buf]
    call hmac_sha256

    ; Write 32-byte HMAC to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, SHA256_DIGEST_SIZE
    syscall

    ; exit(0)
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
