; ssh_aead.asm — chacha20-poly1305@openssh.com for SSH
; Two-key AEAD: K1 for payload, K2 for length encryption
; Nonce: 4 zero bytes + 8-byte big-endian sequence number

%include "ssh.inc"
%include "chacha20.inc"
%include "poly1305.inc"

section .text

; ---------------------------------------------------------------------------
; ssh_aead_encrypt(rdi=output, rsi=payload, edx=payload_len,
;                  rcx=k1_32, r8=k2_32, r9d=seq_num)
; Output: [enc_length(4)][enc_payload(payload_len)][mac(16)]
; Returns: rax = 4 + payload_len + 16
; ---------------------------------------------------------------------------
global ssh_aead_encrypt
ssh_aead_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi            ; output buffer
    mov r13, rsi            ; payload pointer
    mov r14d, edx           ; payload length
    mov r15, rcx            ; K1 pointer
    push r8                 ; K2 pointer  [rsp+8]
    push r9                 ; seq_num     [rsp+0] (low 32 bits)

    ; Build 12-byte nonce on stack: [00 00 00 00] [seq as 8-byte BE]
    ; seq_num is uint32, so BE 8-byte = [00 00 00 00 seq_be[3] seq_be[2] seq_be[1] seq_be[0]]
    sub rsp, 16             ; nonce buffer (only 12 bytes used, 16 for alignment)
    mov dword [rsp], 0      ; bytes 0-3: zero
    mov dword [rsp + 4], 0  ; bytes 4-7: zero (upper 32 bits of seq)
    mov eax, [rsp + 16]     ; seq_num from stack
    bswap eax               ; big-endian
    mov [rsp + 8], eax      ; bytes 8-11: bswap(seq)

    ; --- Step 1: Encrypt 4-byte length with K2, counter=0 ---
    ; Generate keystream block: chacha20_block(K2, counter=0, nonce, output)
    sub rsp, 64             ; keystream buffer
    mov rdi, [rsp + 64 + 16 + 8]   ; K2 pointer (past 64 + 16_nonce + 8_seq = +88)
    xor esi, esi                     ; counter = 0
    lea rdx, [rsp + 64]             ; nonce pointer
    lea rcx, [rsp]                   ; output: keystream
    call chacha20_block

    ; XOR first 4 keystream bytes with big-endian payload length
    mov eax, r14d           ; payload_len
    bswap eax               ; big-endian length
    xor eax, [rsp]          ; XOR with keystream[0..3]
    mov [r12], eax          ; write encrypted length to output[0..3]

    ; --- Step 2: Generate Poly1305 key with K1, counter=0 ---
    ; Reuse the 64-byte buffer for another chacha20_block
    mov rdi, r15            ; K1
    xor esi, esi            ; counter = 0
    lea rdx, [rsp + 64]    ; nonce
    lea rcx, [rsp]          ; output: keystream (first 32 bytes = poly key)
    call chacha20_block
    ; Poly1305 key is at [rsp], 32 bytes. Save it.

    ; Copy poly key to a safe place (we need the 64-byte buffer for encryption)
    sub rsp, 32
    ; Copy 32 bytes from [rsp+32] to [rsp]
    mov rax, [rsp + 32]
    mov [rsp], rax
    mov rax, [rsp + 40]
    mov [rsp + 8], rax
    mov rax, [rsp + 48]
    mov [rsp + 16], rax
    mov rax, [rsp + 56]
    mov [rsp + 24], rax

    ; --- Step 3: Encrypt payload with K1, counter=1 ---
    ; chacha20_encrypt(key, counter, nonce, input, len, output)
    mov rdi, r15            ; K1
    mov esi, 1              ; counter = 1
    lea rdx, [rsp + 32 + 64]       ; nonce (past 32_polykey + 64_ks)
    mov rcx, r13            ; payload input
    mov r8d, r14d
    movzx r8, r8d           ; length (zero-extend to 64-bit)
    lea r9, [r12 + 4]      ; output = output_buf + 4 (after encrypted length)
    call chacha20_encrypt

    ; --- Step 4: Compute MAC over encrypted_length(4) + encrypted_payload ---
    ; poly1305_mac(key, msg, msg_len, output_tag)
    ; Message = output[0 .. 4+payload_len-1]
    ; Tag goes at output[4+payload_len]
    lea rdi, [rsp]          ; poly key (32 bytes)
    mov rsi, r12            ; message = output buffer start (enc_length + enc_payload)
    mov edx, r14d
    add edx, 4              ; message length = 4 + payload_len
    movzx rdx, edx
    lea rcx, [r12 + 4]
    add rcx, r14            ; tag position = output + 4 + payload_len
    mov rcx, rcx
    call poly1305_mac

    ; Return total output length
    mov eax, r14d
    add eax, 20             ; 4 + payload_len + 16
    movzx rax, eax

    ; Clean up stack: 32(polykey) + 64(ks) + 16(nonce) + 16(seq+K2)
    add rsp, 32 + 64 + 16 + 16

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; ---------------------------------------------------------------------------
; ssh_aead_decrypt(rdi=output, rsi=input, edx=total_input_len,
;                  rcx=k1_32, r8=k2_32, r9d=seq_num)
; Input: [enc_length(4)][enc_payload][mac(16)]
; Output: decrypted payload
; Returns: rax = payload_len on success, -1 on MAC failure
; ---------------------------------------------------------------------------
global ssh_aead_decrypt
ssh_aead_decrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; output buffer
    mov r13, rsi            ; input pointer
    mov r14d, edx           ; total_input_len
    mov r15, rcx            ; K1
    push r8                 ; K2       [rsp+8]
    push r9                 ; seq_num  [rsp+0]

    ; payload_len = total_input_len - 4 - 16
    mov ebx, r14d
    sub ebx, 20             ; ebx = payload_len
    js .decrypt_fail_stack0 ; if negative, invalid

    ; Build nonce
    sub rsp, 16
    mov dword [rsp], 0
    mov dword [rsp + 4], 0
    mov eax, [rsp + 16]     ; seq_num
    bswap eax
    mov [rsp + 8], eax

    ; --- Step 1: Generate Poly1305 key with K1, counter=0 ---
    sub rsp, 64             ; keystream
    mov rdi, r15
    xor esi, esi
    lea rdx, [rsp + 64]    ; nonce
    lea rcx, [rsp]
    call chacha20_block
    ; poly key at [rsp], 32 bytes

    ; Save poly key
    sub rsp, 32
    mov rax, [rsp + 32]
    mov [rsp], rax
    mov rax, [rsp + 40]
    mov [rsp + 8], rax
    mov rax, [rsp + 48]
    mov [rsp + 16], rax
    mov rax, [rsp + 56]
    mov [rsp + 24], rax

    ; --- Step 2: Verify MAC ---
    ; MAC covers: enc_length(4) + enc_payload(ebx bytes)
    ; mac_msg_len = 4 + payload_len = total_input_len - 16
    ; Compute expected tag
    sub rsp, 16             ; space for computed tag
    lea rdi, [rsp + 16]    ; poly key
    mov rsi, r13            ; input start (enc_length + enc_payload)
    mov edx, r14d
    sub edx, 16             ; message length = total - 16
    movzx rdx, edx
    lea rcx, [rsp]          ; computed tag output
    call poly1305_mac

    ; Compare computed tag with received tag (at input + total_len - 16)
    lea rsi, [r13 + r14 - 16]  ; received tag
    xor eax, eax
%assign i 0
%rep 16
    movzx ecx, byte [rsp + i]
    movzx edx, byte [rsi + i]
    xor ecx, edx
    or eax, ecx
%assign i i+1
%endrep

    ; Clean up computed tag
    add rsp, 16

    test eax, eax
    jnz .decrypt_fail

    ; --- Step 3: Decrypt payload with K1, counter=1 ---
    mov rdi, r15            ; K1
    mov esi, 1              ; counter = 1
    lea rdx, [rsp + 32 + 64]  ; nonce
    lea rcx, [r13 + 4]     ; input = enc_payload (after 4-byte length)
    movzx r8, ebx           ; payload length
    mov r9, r12             ; output buffer
    call chacha20_encrypt

    ; Return payload length
    movzx rax, ebx
    jmp .decrypt_done

.decrypt_fail:
    mov rax, -1
    jmp .decrypt_done

.decrypt_fail_stack0:
    ; Failed before nonce/ks allocation
    add rsp, 16             ; pop seq+K2
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.decrypt_done:
    ; Clean up: 32(polykey) + 64(ks) + 16(nonce) + 16(seq+K2)
    add rsp, 32 + 64 + 16 + 16

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; ---------------------------------------------------------------------------
; ssh_aead_decrypt_length(rdi=output4, rsi=enc_length4, rdx=k2_32, ecx=seq_num)
; Decrypt just the 4-byte packet length
; Returns: eax = decrypted length (host byte order, i.e., LE on x86)
; ---------------------------------------------------------------------------
global ssh_aead_decrypt_length
ssh_aead_decrypt_length:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; output pointer
    mov r13, rsi            ; encrypted length pointer
    mov r14, rdx            ; K2
    mov r15d, ecx           ; seq_num

    ; Build nonce
    sub rsp, 16
    mov dword [rsp], 0
    mov dword [rsp + 4], 0
    mov eax, r15d
    bswap eax
    mov [rsp + 8], eax

    ; Generate keystream: chacha20_block(K2, counter=0, nonce, output)
    sub rsp, 64
    mov rdi, r14            ; K2
    xor esi, esi            ; counter = 0
    lea rdx, [rsp + 64]    ; nonce
    lea rcx, [rsp]          ; keystream output
    call chacha20_block

    ; XOR first 4 bytes of keystream with encrypted length -> big-endian plaintext length
    mov eax, [r13]          ; encrypted length (4 bytes)
    xor eax, [rsp]          ; XOR with keystream[0..3]
    ; eax now has big-endian length
    bswap eax               ; convert to host (little-endian)
    mov [r12], eax          ; store to output

    ; Clean up: 64(ks) + 16(nonce)
    add rsp, 64 + 16

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
