; aead.inc - ChaCha20-Poly1305 AEAD construction
; Platform-agnostic NASM include file (no syscalls, no API calls)
; Implements RFC 8439 Section 2.8 AEAD_CHACHA20_POLY1305 (no AAD)

%include "chacha20.inc"
%include "poly1305.inc"

section .text

; aead_encrypt: Encrypt plaintext and produce ciphertext + 16-byte tag
; Input:
;   rdi = pointer to 32-byte key
;   rsi = pointer to 12-byte nonce
;   rdx = pointer to plaintext
;   rcx = plaintext length
;   r8  = pointer to output buffer (must have room for plaintext_len + 16)
; Output: rax = total output length (ciphertext_len + 16)
aead_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi            ; key pointer
    mov r13, rsi            ; nonce pointer
    mov r14, rdx            ; plaintext pointer
    mov r15, rcx            ; plaintext length (also ciphertext length)
    push r8                 ; output buffer pointer

    ; --- Step 1: Generate one-time Poly1305 key (counter=0) ---
    ; Allocate 64 bytes on stack for chacha20_block output
    sub rsp, 64
    ; chacha20_block(key=r12, counter=0, nonce=r13, output=rsp)
    mov rdi, r12
    xor esi, esi            ; counter = 0
    mov rdx, r13
    lea rcx, [rsp]
    call chacha20_block
    ; First 32 bytes at [rsp] are the one-time key (otk)

    ; --- Step 2: Encrypt plaintext with counter=1 ---
    ; chacha20_encrypt(key=r12, counter=1, nonce=r13, input=r14, len=r15, output=out_buf)
    mov rdi, r12
    mov esi, 1              ; counter = 1
    mov rdx, r13
    mov rcx, r14            ; plaintext pointer
    mov r8, r15             ; plaintext length
    mov r9, [rsp + 64]      ; output buffer pointer (pushed r8, then sub 64)
    call chacha20_encrypt
    ; Ciphertext is now at output[0..r15-1]

    ; --- Step 3: Construct Poly1305 MAC input ---
    ; Format (no AAD):
    ;   pad16(ciphertext) || le64(0) || le64(ct_len)
    ; Total size = pad16(r15) + 16
    ;
    ; Compute padded ciphertext size: (r15 + 15) & ~15
    mov rax, r15
    add rax, 15
    and rax, ~15            ; padded_ct_len
    mov rbx, rax            ; rbx = padded_ct_len
    add rax, 16             ; + 16 for two le64 fields
    mov rbp, rax            ; rbp = total poly_input_len

    ; Allocate poly input buffer on stack (aligned to 8)
    ; We need rbp bytes on stack
    sub rsp, rbp

    ; Copy ciphertext into poly input buffer
    mov r14, [rsp + rbp + 64]  ; output buffer pointer
    ; Copy r15 bytes from output buffer to [rsp]
    xor ecx, ecx
.aead_enc_copy_ct:
    cmp rcx, r15
    jge .aead_enc_pad_ct
    movzx eax, byte [r14 + rcx]
    mov byte [rsp + rcx], al
    inc rcx
    jmp .aead_enc_copy_ct

.aead_enc_pad_ct:
    ; Zero-pad from r15 to rbx (padded_ct_len)
    cmp rcx, rbx
    jge .aead_enc_lengths
    mov byte [rsp + rcx], 0
    inc rcx
    jmp .aead_enc_pad_ct

.aead_enc_lengths:
    ; Write le64(aad_len) = 0
    mov qword [rsp + rbx], 0
    ; Write le64(ct_len)
    mov [rsp + rbx + 8], r15

    ; --- Step 4: Compute tag ---
    ; poly1305_mac(key=otk_at_[rsp+rbp], msg=[rsp], msg_len=rbp, output=output+ct_len)
    ; otk is at [rsp + rbp] (the 64-byte chacha block we allocated earlier)
    lea rdi, [rsp + rbp]           ; otk (first 32 bytes of chacha block)
    lea rsi, [rsp]                  ; poly input
    mov rdx, rbp                    ; poly input length
    ; tag destination = output_buf + ct_len
    mov rcx, r14                    ; output buffer base
    add rcx, r15                    ; + ciphertext length = tag position
    call poly1305_mac

    ; --- Step 5: Return total length ---
    mov rax, r15
    add rax, 16             ; ciphertext_len + 16 (tag)

    ; Clean up stack: rbp (poly input) + 64 (chacha block) + 8 (pushed r8)
    add rsp, rbp
    add rsp, 64 + 8

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; aead_decrypt: Verify tag and decrypt ciphertext
; Input:
;   rdi = pointer to 32-byte key
;   rsi = pointer to 12-byte nonce
;   rdx = pointer to ciphertext
;   rcx = ciphertext length (NOT including tag)
;   r8  = pointer to 16-byte received tag
;   r9  = pointer to output buffer (plaintext)
; Output: rax = plaintext length on success, -1 on MAC verification failure
aead_decrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi            ; key pointer
    mov r13, rsi            ; nonce pointer
    mov r14, rdx            ; ciphertext pointer
    mov r15, rcx            ; ciphertext length
    push r9                 ; output buffer pointer
    push r8                 ; received tag pointer

    ; --- Step 1: Generate one-time Poly1305 key (counter=0) ---
    sub rsp, 64
    mov rdi, r12
    xor esi, esi            ; counter = 0
    mov rdx, r13
    lea rcx, [rsp]
    call chacha20_block
    ; otk at [rsp], 32 bytes

    ; --- Step 2: Construct Poly1305 MAC input from ciphertext ---
    ; Same format as encrypt: pad16(ciphertext) || le64(0) || le64(ct_len)
    mov rax, r15
    add rax, 15
    and rax, ~15            ; padded_ct_len
    mov rbx, rax
    add rax, 16             ; + 16 for lengths
    mov rbp, rax            ; total poly_input_len

    sub rsp, rbp

    ; Copy ciphertext to poly input
    xor ecx, ecx
.aead_dec_copy_ct:
    cmp rcx, r15
    jge .aead_dec_pad_ct
    movzx eax, byte [r14 + rcx]
    mov byte [rsp + rcx], al
    inc rcx
    jmp .aead_dec_copy_ct

.aead_dec_pad_ct:
    cmp rcx, rbx
    jge .aead_dec_lengths
    mov byte [rsp + rcx], 0
    inc rcx
    jmp .aead_dec_pad_ct

.aead_dec_lengths:
    mov qword [rsp + rbx], 0
    mov [rsp + rbx + 8], r15

    ; --- Step 3: Compute expected tag ---
    ; Allocate 16 bytes for computed tag
    sub rsp, 16
    ; poly1305_mac(key=otk, msg=poly_input, msg_len=rbp, output=[rsp])
    lea rdi, [rsp + 16 + rbp]      ; otk (in the chacha block area)
    lea rsi, [rsp + 16]            ; poly input
    mov rdx, rbp                    ; poly input length
    lea rcx, [rsp]                  ; computed tag output
    call poly1305_mac

    ; --- Step 4: Constant-time tag comparison ---
    ; received tag pointer is at [rsp + 16 + rbp + 64 + 0] (pushed r8)
    ; Stack layout from top: 16(comp_tag) + rbp(poly_input) + 64(chacha_block) + 8(r8_tag) + 8(r9_out)
    mov rsi, [rsp + 16 + rbp + 64]  ; received tag pointer
    xor eax, eax                    ; accumulator for differences
    %assign i 0
    %rep 16
        movzx ecx, byte [rsp + i]          ; computed tag byte
        movzx edx, byte [rsi + i]          ; received tag byte
        xor ecx, edx
        or eax, ecx
        %assign i i+1
    %endrep

    ; If eax != 0, tags don't match -> return -1
    test eax, eax
    jnz .aead_dec_fail

    ; --- Step 5: Tags match, decrypt ---
    ; chacha20_encrypt(key=r12, counter=1, nonce=r13, input=r14, len=r15, output=out_buf)
    mov rdi, r12
    mov esi, 1
    mov rdx, r13
    mov rcx, r14                            ; ciphertext pointer
    mov r8, r15                             ; ciphertext length
    mov r9, [rsp + 16 + rbp + 64 + 8]      ; output buffer pointer
    call chacha20_encrypt

    ; Return ciphertext length (= plaintext length)
    mov rax, r15
    jmp .aead_dec_done

.aead_dec_fail:
    mov rax, -1

.aead_dec_done:
    ; Clean up stack: 16(tag) + rbp(poly) + 64(chacha) + 16(two pushes)
    add rsp, 16
    add rsp, rbp
    add rsp, 64 + 16

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
