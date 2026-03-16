; HKDF (HMAC-based Key Derivation Function) per RFC 5869
; Built on HMAC-SHA256 for TLS 1.3 key derivation (RFC 8446)
;
; Functions:
;   hkdf_extract(rdi=salt, esi=salt_len, rdx=ikm, ecx=ikm_len, r8=output_32)
;   hkdf_expand(rdi=prk_32, rsi=info, edx=info_len, ecx=output_len, r8=output)
;   hkdf_expand_label(rdi=secret_32, rsi=label, edx=label_len, rcx=context,
;                     r8d=context_len, r9d=output_len, [rsp+8]=output_ptr)
;   derive_secret(rdi=secret_32, rsi=label, edx=label_len,
;                 rcx=messages, r8d=messages_len, r9=output_32)

%include "ssh.inc"

extern hmac_sha256
extern sha256

section .data
align 16
zero_salt: times 32 db 0
tls13_prefix: db "tls13 "               ; 6 bytes, no null terminator

section .text
global hkdf_extract
global hkdf_expand
global hkdf_expand_label
global derive_secret

; =============================================================================
; hkdf_extract(rdi=salt, esi=salt_len, rdx=ikm, ecx=ikm_len, r8=output_32)
; PRK = HMAC-SHA256(salt, IKM)
; If salt is NULL (rdi=0), uses 32 zero bytes as salt
; =============================================================================
hkdf_extract:
    push rbp
    mov rbp, rsp
    push rbx

    ; Check if salt is NULL
    test rdi, rdi
    jnz .extract_has_salt

    ; Use zero salt (32 bytes)
    lea rdi, [rel zero_salt]
    mov esi, 32

.extract_has_salt:
    ; hmac_sha256(key=salt, key_len=salt_len, msg=ikm, msg_len=ikm_len, output)
    ; Arguments already in correct registers:
    ;   rdi = salt (key)
    ;   esi = salt_len (key_len)
    ;   rdx = ikm (msg)
    ;   ecx = ikm_len (msg_len)
    ;   r8  = output
    call hmac_sha256

    pop rbx
    pop rbp
    ret

; =============================================================================
; hkdf_expand(rdi=prk_32, rsi=info, edx=info_len, ecx=output_len, r8=output)
; Expands PRK into output_len bytes of key material.
; T(0) = empty
; T(1) = HMAC(PRK, info || 0x01)
; T(N) = HMAC(PRK, T(N-1) || info || N)
; Output = T(1) || T(2) || ... truncated to output_len
; Max output_len = 255 * 32 = 8160 bytes
; =============================================================================
; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-48      saved prk pointer
;   rbp-56      saved info pointer
;   rbp-60      saved info_len
;   rbp-64      saved output_len
;   rbp-72      saved output pointer
;   rbp-76      current counter byte
;   rbp-80      bytes_written
;   rbp-112     prev_T (32 bytes) [rbp-112 .. rbp-81]
;   rbp-416     concat buffer (304 bytes: 32 + 256 + 1 + padding)
;   rbp-448     hmac_output temp (32 bytes)

hkdf_expand:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 448

    ; Save arguments
    mov [rbp-48], rdi                   ; prk pointer
    mov [rbp-56], rsi                   ; info pointer
    mov [rbp-60], edx                   ; info_len
    mov [rbp-64], ecx                   ; output_len
    mov [rbp-72], r8                    ; output pointer
    mov dword [rbp-76], 0              ; counter = 0
    mov dword [rbp-80], 0              ; bytes_written = 0

    ; If output_len == 0, just return
    test ecx, ecx
    jz .expand_done

    ; r12 = prk, r13 = info, r14d = info_len, r15 = output
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov r15, r8

.expand_loop:
    ; Increment counter
    mov eax, [rbp-76]
    inc eax
    mov [rbp-76], eax

    ; Build concat message in buffer at rbp-416
    ; If counter == 1: msg = info || counter_byte
    ; If counter > 1:  msg = prev_T(32) || info || counter_byte
    lea rdi, [rbp-416]                  ; concat buffer start
    xor ebx, ebx                        ; ebx = concat length

    cmp dword [rbp-76], 1
    je .expand_no_prev_t

    ; Copy prev_T (32 bytes)
    lea rsi, [rbp-112]
    mov ecx, 32
    rep movsb
    add ebx, 32

.expand_no_prev_t:
    ; Copy info
    mov ecx, r14d
    test ecx, ecx
    jz .expand_append_counter
    mov rsi, r13
    rep movsb
    add ebx, r14d

.expand_append_counter:
    ; Append counter byte
    mov eax, [rbp-76]
    mov [rdi], al
    inc ebx

    ; Now call HMAC-SHA256(PRK, concat, concat_len, hmac_output)
    mov rdi, r12                        ; key = PRK
    mov esi, 32                         ; key_len = 32
    lea rdx, [rbp-416]                  ; msg = concat buffer
    mov ecx, ebx                        ; msg_len = concat length
    lea r8, [rbp-448]                   ; output = hmac temp
    call hmac_sha256

    ; Restore callee-saved regs (hmac_sha256 preserves them, but reload from stack to be safe)
    mov r12, [rbp-48]
    mov r13, [rbp-56]
    mov r14d, [rbp-60]
    mov r15, [rbp-72]

    ; Copy hmac_output to prev_T
    lea rsi, [rbp-448]
    lea rdi, [rbp-112]
    mov ecx, 32
    rep movsb

    ; Determine how many bytes to copy to output
    mov eax, [rbp-64]                   ; output_len
    sub eax, [rbp-80]                   ; remaining = output_len - bytes_written
    cmp eax, 32
    jle .expand_partial
    mov eax, 32                         ; copy full 32 bytes

.expand_partial:
    ; Copy eax bytes from hmac_output to output + bytes_written
    mov rdi, r15                        ; output base
    mov edx, [rbp-80]                   ; bytes_written
    add rdi, rdx                        ; output + bytes_written
    lea rsi, [rbp-448]                  ; hmac_output
    mov ecx, eax
    rep movsb

    ; Update bytes_written
    add [rbp-80], eax

    ; Check if we've written enough
    mov eax, [rbp-80]
    cmp eax, [rbp-64]
    jl .expand_loop

.expand_done:
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; hkdf_expand_label(rdi=secret_32, rsi=label, edx=label_len, rcx=context,
;                   r8d=context_len, r9d=output_len, [rsp+8]=output_ptr)
; TLS 1.3 specific HKDF-Expand-Label (RFC 8446 Section 7.1):
;   HkdfLabel = uint16(output_len) +
;               opaque8(6 + label_len, "tls13 " + label) +
;               opaque8(context_len, context)
;   Output = HKDF-Expand(secret, HkdfLabel, output_len)
; =============================================================================
; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-48      saved secret pointer
;   rbp-56      saved label pointer
;   rbp-60      saved label_len
;   rbp-68      saved context pointer
;   rbp-72      saved context_len
;   rbp-76      saved output_len
;   rbp-84      saved output_ptr
;   rbp-384     hkdf_label buffer (300 bytes, plenty for typical use)

hkdf_expand_label:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 384

    ; Save arguments
    mov [rbp-48], rdi                   ; secret
    mov [rbp-56], rsi                   ; label
    mov [rbp-60], edx                   ; label_len
    mov [rbp-68], rcx                   ; context
    mov [rbp-72], r8d                   ; context_len
    mov [rbp-76], r9d                   ; output_len

    ; output_ptr is at [rbp+16] (after return addr at rbp+8)
    mov rax, [rbp+16]
    mov [rbp-84], rax                   ; output_ptr

    ; Build HkdfLabel in buffer at rbp-384
    lea rdi, [rbp-384]

    ; Byte 0-1: uint16 output_len (big-endian)
    movzx eax, word [rbp-76]
    mov byte [rdi], ah                  ; high byte
    mov byte [rdi+1], al                ; low byte
    add rdi, 2

    ; Byte 2: uint8 label_prefix_len = 6 + label_len
    mov eax, [rbp-60]
    add eax, 6
    mov [rdi], al
    inc rdi

    ; Bytes 3-8: "tls13 " (6 bytes)
    lea rsi, [rel tls13_prefix]
    mov ecx, 6
    rep movsb

    ; Bytes 9...: label (label_len bytes)
    mov rsi, [rbp-56]
    mov ecx, [rbp-60]
    test ecx, ecx
    jz .label_copied
    rep movsb
.label_copied:

    ; Next byte: uint8 context_len
    mov eax, [rbp-72]
    mov [rdi], al
    inc rdi

    ; Context bytes
    mov rsi, [rbp-68]
    mov ecx, [rbp-72]
    test ecx, ecx
    jz .context_copied
    rep movsb
.context_copied:

    ; Calculate total hkdf_label length
    lea rax, [rbp-384]
    sub rdi, rax                        ; rdi = total label length
    mov ebx, edi                        ; ebx = hkdf_label_len

    ; Call hkdf_expand(secret, hkdf_label, hkdf_label_len, output_len, output)
    mov rdi, [rbp-48]                   ; prk = secret
    lea rsi, [rbp-384]                  ; info = hkdf_label
    mov edx, ebx                        ; info_len = hkdf_label_len
    mov ecx, [rbp-76]                   ; output_len
    mov r8, [rbp-84]                    ; output
    call hkdf_expand

    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; derive_secret(rdi=secret_32, rsi=label, edx=label_len,
;               rcx=messages, r8d=messages_len, r9=output_32)
; Derive-Secret(Secret, Label, Messages) =
;   HKDF-Expand-Label(Secret, Label, Hash(Messages), 32)
; Where Hash = SHA-256
; =============================================================================
; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-48      saved secret pointer
;   rbp-56      saved label pointer
;   rbp-60      saved label_len
;   rbp-68      saved output pointer (r9)
;   rbp-100     transcript_hash (32 bytes)

derive_secret:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 112

    ; Save arguments
    mov [rbp-48], rdi                   ; secret
    mov [rbp-56], rsi                   ; label
    mov [rbp-60], edx                   ; label_len
    mov [rbp-68], r9                    ; output

    ; Step 1: transcript_hash = SHA-256(messages, messages_len)
    mov rdi, rcx                        ; msg = messages
    movzx rsi, r8d                      ; msg_len = messages_len
    lea rdx, [rbp-100]                  ; output = transcript_hash
    call sha256

    ; Restore saved values
    mov rdi, [rbp-48]                   ; secret
    mov rsi, [rbp-56]                   ; label
    mov edx, [rbp-60]                   ; label_len

    ; Step 2: hkdf_expand_label(secret, label, label_len, transcript_hash, 32, 32, output)
    ;   rdi = secret (already set)
    ;   rsi = label (already set)
    ;   edx = label_len (already set)
    ;   rcx = context = transcript_hash
    ;   r8d = context_len = 32
    ;   r9d = output_len = 32
    ;   [rsp] = output_ptr (push before call)
    lea rcx, [rbp-100]                  ; context = transcript_hash
    mov r8d, 32                         ; context_len
    mov r9d, 32                         ; output_len

    ; Push output_ptr as 7th argument
    mov rax, [rbp-68]
    push rax
    call hkdf_expand_label
    add rsp, 8                          ; clean up pushed arg

    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
