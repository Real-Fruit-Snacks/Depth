; Test harness for HKDF
; Reads mode byte from stdin, then mode-specific data:
;   'e' (extract): salt_len(4 LE) + salt + ikm_len(4 LE) + ikm → outputs PRK (32 bytes)
;   'x' (expand):  prk(32) + info_len(4 LE) + info + output_len(4 LE) → outputs expanded key
;   'l' (expand_label): secret(32) + label_len(4 LE) + label + ctx_len(4 LE) + ctx + out_len(4 LE) → outputs key
;   'd' (derive_secret): secret(32) + label_len(4 LE) + label + msgs_len(4 LE) + msgs → outputs 32 bytes

%include "ssh.inc"

extern hkdf_extract
extern hkdf_expand
extern hkdf_expand_label
extern derive_secret

section .bss
    buf1:     resb 1048576              ; general input buffer 1
    buf2:     resb 1048576              ; general input buffer 2
    out_buf:  resb 8192                 ; output buffer (max 255*32 = 8160)

section .text
global _start

; Helper: read exactly edx bytes into rsi from stdin
; Clobbers rax, rdi, rcx. Uses r13 as temp counter.
_read_exact:
    push r13
    xor r13d, r13d
.loop:
    cmp r13d, edx
    jge .done
    xor eax, eax                        ; SYS_READ
    xor edi, edi                        ; stdin
    push rsi
    push rdx
    lea rsi, [rsi + r13]
    mov edx, edx
    sub edx, r13d
    syscall
    pop rdx
    pop rsi
    test rax, rax
    jle .done
    add r13d, eax
    jmp .loop
.done:
    pop r13
    ret

_start:
    ; Read 1-byte mode
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 1
    syscall
    movzx r15d, byte [rsp]             ; r15d = mode character
    add rsp, 16

    cmp r15d, 'e'
    je .mode_extract
    cmp r15d, 'x'
    je .mode_expand
    cmp r15d, 'l'
    je .mode_expand_label
    cmp r15d, 'd'
    je .mode_derive_secret

    ; Unknown mode - exit 1
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

; ---- MODE 'e': extract ----
.mode_extract:
    ; Read salt_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r12d, [rsp]                     ; r12d = salt_len
    add rsp, 16

    ; Read salt bytes into buf1
    lea rsi, [rel buf1]
    mov edx, r12d
    test edx, edx
    jz .extract_read_ikm_len
    call _read_exact

.extract_read_ikm_len:
    ; Read ikm_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r14d, [rsp]                     ; r14d = ikm_len
    add rsp, 16

    ; Read IKM bytes into buf2
    lea rsi, [rel buf2]
    mov edx, r14d
    test edx, edx
    jz .extract_do
    call _read_exact

.extract_do:
    ; Check if salt_len == 0 → pass NULL salt
    test r12d, r12d
    jz .extract_null_salt

    lea rdi, [rel buf1]                 ; salt
    mov esi, r12d                       ; salt_len
    jmp .extract_call

.extract_null_salt:
    xor edi, edi                        ; NULL salt
    xor esi, esi                        ; salt_len = 0

.extract_call:
    lea rdx, [rel buf2]                 ; ikm
    mov ecx, r14d                       ; ikm_len
    lea r8, [rel out_buf]               ; output
    call hkdf_extract

    ; Write 32 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, 32
    syscall
    jmp .exit_ok

; ---- MODE 'x': expand ----
.mode_expand:
    ; Read PRK (32 bytes) into buf1
    lea rsi, [rel buf1]
    mov edx, 32
    call _read_exact

    ; Read info_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r12d, [rsp]                     ; r12d = info_len
    add rsp, 16

    ; Read info bytes into buf2
    lea rsi, [rel buf2]
    mov edx, r12d
    test edx, edx
    jz .expand_read_outlen
    call _read_exact

.expand_read_outlen:
    ; Read output_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r14d, [rsp]                     ; r14d = output_len
    add rsp, 16

    ; hkdf_expand(prk, info, info_len, output_len, output)
    lea rdi, [rel buf1]                 ; prk
    lea rsi, [rel buf2]                 ; info
    mov edx, r12d                       ; info_len
    mov ecx, r14d                       ; output_len
    lea r8, [rel out_buf]               ; output
    call hkdf_expand

    ; Write output_len bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, r14d
    syscall
    jmp .exit_ok

; ---- MODE 'l': expand_label ----
.mode_expand_label:
    ; Read secret (32 bytes) into buf1
    lea rsi, [rel buf1]
    mov edx, 32
    call _read_exact

    ; Read label_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r12d, [rsp]                     ; r12d = label_len
    add rsp, 16

    ; Read label into buf2
    lea rsi, [rel buf2]
    mov edx, r12d
    test edx, edx
    jz .label_read_ctx_len
    call _read_exact

.label_read_ctx_len:
    ; Read context_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r13d, [rsp]                     ; r13d = context_len
    add rsp, 16

    ; Read context into buf2 + 65536 (offset to avoid overlap with label)
    lea rsi, [rel buf2]
    add rsi, 65536
    mov edx, r13d
    test edx, edx
    jz .label_read_outlen
    call _read_exact

.label_read_outlen:
    ; Read output_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r14d, [rsp]                     ; r14d = output_len
    add rsp, 16

    ; hkdf_expand_label(secret, label, label_len, context, context_len, output_len, output_ptr)
    ; Push output_ptr as 7th arg before call
    lea rax, [rel out_buf]
    push rax

    lea rdi, [rel buf1]                 ; secret
    lea rsi, [rel buf2]                 ; label
    mov edx, r12d                       ; label_len
    lea rcx, [rel buf2]
    add rcx, 65536                      ; context
    mov r8d, r13d                       ; context_len
    mov r9d, r14d                       ; output_len
    call hkdf_expand_label
    add rsp, 8                          ; clean up pushed arg

    ; Write output_len bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, r14d
    syscall
    jmp .exit_ok

; ---- MODE 'd': derive_secret ----
.mode_derive_secret:
    ; Read secret (32 bytes) into buf1
    lea rsi, [rel buf1]
    mov edx, 32
    call _read_exact

    ; Read label_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r12d, [rsp]                     ; r12d = label_len
    add rsp, 16

    ; Read label into buf2
    lea rsi, [rel buf2]
    mov edx, r12d
    test edx, edx
    jz .derive_read_msgs_len
    call _read_exact

.derive_read_msgs_len:
    ; Read msgs_len (4 bytes LE)
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 4
    syscall
    mov r14d, [rsp]                     ; r14d = msgs_len
    add rsp, 16

    ; Read messages into buf2 + 65536
    lea rsi, [rel buf2]
    add rsi, 65536
    mov edx, r14d
    test edx, edx
    jz .derive_do
    call _read_exact

.derive_do:
    ; derive_secret(secret, label, label_len, messages, messages_len, output)
    lea rdi, [rel buf1]                 ; secret
    lea rsi, [rel buf2]                 ; label
    mov edx, r12d                       ; label_len
    lea rcx, [rel buf2]
    add rcx, 65536                      ; messages
    mov r8d, r14d                       ; messages_len
    lea r9, [rel out_buf]               ; output
    call derive_secret

    ; Write 32 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel out_buf]
    mov edx, 32
    syscall
    jmp .exit_ok

.exit_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
