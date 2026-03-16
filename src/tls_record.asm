; tls_record.asm — TLS 1.3 record layer
; Plaintext and encrypted record read/write using ChaCha20-Poly1305 AEAD
; AEAD construction per RFC 8439 Section 2.8 (IETF variant, NOT SSH variant)

%include "ssh.inc"
%include "tls.inc"
%include "chacha20.inc"
%include "poly1305.inc"

extern net_read_exact
extern net_write_all

section .text

; =============================================================================
; tls_record_write_plain(edi=sock_fd, esi=content_type, rdx=data, ecx=data_len)
;   -> rax=0 or -1
; Sends: [content_type(1)][0x03 0x03(2)][length_BE16(2)][data]
; =============================================================================
global tls_record_write_plain
tls_record_write_plain:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov ebx, edi            ; sock_fd
    mov r12d, esi           ; content_type
    mov r13, rdx            ; data pointer
    mov r14d, ecx           ; data_len

    ; Build 5-byte header on stack
    sub rsp, 16             ; 16 for alignment (only need 5)
    mov byte [rsp], r12b    ; content_type
    mov byte [rsp+1], 0x03  ; version high
    mov byte [rsp+2], 0x03  ; version low
    ; length big-endian
    mov eax, r14d
    mov byte [rsp+3], ah    ; length high byte
    mov byte [rsp+4], al    ; length low byte

    ; Send header
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 5
    call net_write_all
    test rax, rax
    jnz .wp_fail

    ; Send data
    test r14d, r14d
    jz .wp_done
    mov edi, ebx
    mov rsi, r13
    mov edx, r14d
    call net_write_all
    test rax, rax
    jnz .wp_fail

.wp_done:
    xor eax, eax
    jmp .wp_ret

.wp_fail:
    mov rax, -1

.wp_ret:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; tls_record_read_plain(edi=sock_fd, rsi=output, edx=max_len)
;   -> rax=data_len or -1, content_type in r8b
; Reads: [content_type(1)][version(2)][length(2)][data]
; =============================================================================
global tls_record_read_plain
tls_record_read_plain:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov ebx, edi            ; sock_fd
    mov r12, rsi            ; output buffer
    mov r13d, edx           ; max_len

    ; Read 5-byte header
    sub rsp, 16
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 5
    call net_read_exact
    test rax, rax
    jnz .rp_fail

    ; Parse header
    movzx r14d, byte [rsp]         ; content_type
    ; Skip version bytes [rsp+1], [rsp+2]
    movzx r15d, byte [rsp+3]      ; length high
    shl r15d, 8
    movzx eax, byte [rsp+4]       ; length low
    or r15d, eax                    ; r15d = payload length

    ; Validate length
    cmp r15d, r13d
    ja .rp_fail                     ; too big for output buffer
    test r15d, r15d
    jz .rp_done_empty

    ; Read payload
    mov edi, ebx
    mov rsi, r12
    mov edx, r15d
    call net_read_exact
    test rax, rax
    jnz .rp_fail

.rp_done_empty:
    ; Return data_len in rax, content_type in r8b
    movzx rax, r15d
    movzx r8d, r14b
    jmp .rp_ret

.rp_fail:
    mov rax, -1

.rp_ret:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; tls_record_write_enc(edi=sock_fd, rsi=tls_state, edx=inner_ct, rcx=data, r8d=data_len)
;   -> rax=0 or -1
;
; Encrypts: plaintext_with_ct = data + inner_content_type_byte
; AEAD per RFC 8439:
;   nonce = write_iv XOR padded_seq (12 bytes)
;   poly_key = chacha20_block(write_key, counter=0, nonce)[:32]
;   ciphertext = chacha20_encrypt(write_key, counter=1, nonce, plaintext_with_ct)
;   AAD = [0x17][0x03 0x03][BE16(ct_len + 16)]  (5 bytes)
;   mac_data = AAD + pad16(AAD) + ciphertext + pad16(ciphertext) + LE64(5) + LE64(ct_len)
;   tag = poly1305_mac(poly_key, mac_data)
; Sends: [0x17][0x03 0x03][BE16(ct_len + 16)][ciphertext][tag]
; Increments write_seq
; =============================================================================
; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-48      sock_fd (4 bytes)
;   rbp-56      tls_state pointer
;   rbp-60      inner_ct (4 bytes)
;   rbp-68      data pointer
;   rbp-72      data_len (4 bytes)
;   rbp-76      ct_len = data_len + 1 (plaintext with content type)
;   rbp-88      nonce (12 bytes) [rbp-88 .. rbp-77]
;   rbp-96      AAD (8 bytes, only 5 used) [rbp-96 .. rbp-89]
;   rbp-128     poly_key (32 bytes) [rbp-128 .. rbp-97]
;   rbp-192     chacha20_block output (64 bytes) [rbp-192 .. rbp-129]
;   Below rbp-192: dynamic ciphertext buffer + mac_data buffer
global tls_record_write_enc
tls_record_write_enc:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 200

    ; Save arguments
    mov [rbp-48], edi           ; sock_fd
    mov [rbp-56], rsi           ; tls_state
    mov [rbp-60], edx           ; inner_ct
    mov [rbp-68], rcx           ; data
    mov [rbp-72], r8d           ; data_len

    ; ct_len = data_len + 1 (for inner content type byte)
    mov eax, r8d
    inc eax
    mov [rbp-76], eax           ; ct_len

    ; --- Build nonce: write_iv XOR padded_seq ---
    ; padded_seq = 4 zero bytes + 8-byte big-endian sequence number
    ; write_iv is at tls_state + TLS_STATE_WRITE_IV (12 bytes)
    ; write_seq is at tls_state + TLS_STATE_WRITE_SEQ (8 bytes, little-endian)
    mov r12, [rbp-56]           ; tls_state

    ; Load write_seq as 64-bit LE, convert to BE for XOR
    mov rax, [r12 + TLS_STATE_WRITE_SEQ]
    bswap rax                   ; big-endian seq

    ; Build padded_seq on stack temp: [00 00 00 00] [BE seq 8 bytes]
    ; Then XOR with write_iv
    ; nonce byte 0..3 = iv[0..3] XOR 0 = iv[0..3]
    mov ecx, [r12 + TLS_STATE_WRITE_IV]
    mov [rbp-88], ecx

    ; nonce byte 4..11 = iv[4..11] XOR BE_seq[0..7]
    mov rcx, [r12 + TLS_STATE_WRITE_IV + 4]
    xor rcx, rax
    mov [rbp-84], rcx

    ; --- Build AAD: [0x17][0x03 0x03][BE16(ct_len + 16)] ---
    mov byte [rbp-96], 0x17     ; application_data
    mov byte [rbp-95], 0x03
    mov byte [rbp-94], 0x03
    mov eax, [rbp-76]           ; ct_len
    add eax, 16                 ; + tag size
    mov byte [rbp-93], ah       ; length high
    mov byte [rbp-92], al       ; length low

    ; --- Generate poly_key: chacha20_block(write_key, 0, nonce)[:32] ---
    lea rdi, [r12 + TLS_STATE_WRITE_KEY]
    xor esi, esi                ; counter = 0
    lea rdx, [rbp-88]           ; nonce
    lea rcx, [rbp-192]          ; 64-byte output
    call chacha20_block

    ; Copy first 32 bytes to poly_key
    lea rsi, [rbp-192]
    lea rdi, [rbp-128]
    mov ecx, 32
    rep movsb

    ; --- Build plaintext_with_ct: data + inner_ct byte ---
    ; Allocate ct_len bytes on stack for plaintext, ct_len for ciphertext
    mov eax, [rbp-76]           ; ct_len
    ; Round up each to 16-byte alignment, need 2 * aligned_ct_len + mac_data space
    add eax, 15
    and eax, -16                ; aligned ct_len
    mov r13d, eax               ; r13d = aligned_ct_len

    ; mac_data = 16(AAD padded) + aligned_ct + 16(lengths) = 16 + aligned_ct + 16
    mov ecx, r13d
    add ecx, 32                 ; mac_data size (padded)
    add ecx, r13d               ; + plaintext buffer
    add ecx, r13d               ; + ciphertext buffer
    add ecx, 16                 ; + tag
    add ecx, 64                 ; + record header space + safety
    sub rsp, rcx
    and rsp, -16                ; align

    ; r14 = plaintext buffer base
    mov r14, rsp

    ; r15 = ciphertext buffer base = r14 + aligned_ct_len
    lea r15, [r14 + r13]

    ; Copy data to plaintext buffer
    mov rdi, r14
    mov rsi, [rbp-68]           ; data
    mov ecx, [rbp-72]           ; data_len
    test ecx, ecx
    jz .we_append_ct
    rep movsb

.we_append_ct:
    ; Append inner content type byte
    mov eax, [rbp-60]
    mov [rdi], al

    ; --- Encrypt: chacha20_encrypt(write_key, 1, nonce, plaintext, ct_len, ciphertext) ---
    mov r12, [rbp-56]           ; reload tls_state
    lea rdi, [r12 + TLS_STATE_WRITE_KEY]
    mov esi, 1                  ; counter = 1
    lea rdx, [rbp-88]           ; nonce
    mov rcx, r14                ; input = plaintext_with_ct
    mov r8d, [rbp-76]           ; length = ct_len
    movzx r8, r8d
    mov r9, r15                 ; output = ciphertext
    call chacha20_encrypt

    ; --- Build mac_data and compute tag ---
    ; mac_data = AAD(5) + pad16(AAD)(11 zeros) + ciphertext(ct_len) + pad16(ct) + LE64(5) + LE64(ct_len)
    ; Place mac_data after ciphertext buffer
    lea rbx, [r15 + r13]       ; rbx = mac_data start

    ; AAD (5 bytes)
    mov rdi, rbx
    lea rsi, [rbp-96]
    mov ecx, 5
    rep movsb

    ; Pad AAD to 16 bytes (11 zeros)
    xor eax, eax
    mov ecx, 11
    rep stosb

    ; Ciphertext (ct_len bytes)
    mov rsi, r15
    mov ecx, [rbp-76]
    rep movsb

    ; Pad ciphertext to multiple of 16
    mov eax, [rbp-76]
    and eax, 15                 ; remainder
    jz .we_no_ct_pad
    mov ecx, 16
    sub ecx, eax               ; padding needed
    xor eax, eax
    rep stosb
.we_no_ct_pad:

    ; LE64(AAD length = 5)
    mov qword [rdi], 5
    add rdi, 8

    ; LE64(ciphertext length = ct_len)
    mov eax, [rbp-76]
    movzx rax, eax
    mov [rdi], rax
    add rdi, 8

    ; mac_data_len = rdi - rbx
    mov rcx, rdi
    sub rcx, rbx               ; rcx = mac_data_len

    ; Compute tag: poly1305_mac(poly_key, mac_data, mac_data_len, tag_output)
    ; Tag goes right after ciphertext in r15 + ct_len
    mov eax, [rbp-76]
    movzx rax, eax
    lea r8, [r15 + rax]        ; tag position

    push r8                     ; save tag position
    push rcx                    ; save mac_data_len

    lea rdi, [rbp-128]          ; poly_key
    mov rsi, rbx                ; mac_data
    pop rdx                     ; mac_data_len
    pop rcx                     ; tag output
    push rcx                    ; re-save for later
    call poly1305_mac
    pop r8                      ; r8 = tag position

    ; --- Send record: header(5) + ciphertext(ct_len) + tag(16) ---
    ; First send the 5-byte AAD as the record header
    mov edi, [rbp-48]           ; sock_fd
    lea rsi, [rbp-96]           ; AAD = record header
    mov edx, 5
    call net_write_all
    test rax, rax
    jnz .we_fail

    ; Send ciphertext + tag
    mov eax, [rbp-76]           ; ct_len
    add eax, 16                 ; + tag
    mov edi, [rbp-48]
    mov rsi, r15                ; ciphertext (tag is contiguous after it)
    mov edx, eax
    call net_write_all
    test rax, rax
    jnz .we_fail

    ; --- Increment write_seq ---
    mov r12, [rbp-56]
    mov rax, [r12 + TLS_STATE_WRITE_SEQ]
    inc rax
    mov [r12 + TLS_STATE_WRITE_SEQ], rax

    xor eax, eax
    jmp .we_ret

.we_fail:
    mov rax, -1

.we_ret:
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; tls_record_read_enc(edi=sock_fd, rsi=tls_state, rdx=output, ecx=max_len)
;   -> rax=plaintext_len or -1, inner content_type in r8b
; Reads TLS record, decrypts with read_key, verifies MAC, strips inner CT
; Increments read_seq
; =============================================================================
; Stack frame layout (relative to rbp):
;   rbp-48      sock_fd
;   rbp-56      tls_state
;   rbp-64      output pointer
;   rbp-68      max_len
;   rbp-72      record payload len (ct_len + 16)
;   rbp-76      ct_len (record payload - 16)
;   rbp-88      nonce (12 bytes)
;   rbp-96      AAD (8 bytes, 5 used)
;   rbp-128     poly_key (32 bytes)
;   rbp-192     chacha20_block output (64 bytes)
;   Below: encrypted data buffer + mac_data buffer
global tls_record_read_enc
tls_record_read_enc:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 200

    mov [rbp-48], edi
    mov [rbp-56], rsi
    mov [rbp-64], rdx
    mov [rbp-68], ecx

    ; --- Read 5-byte record header ---
    sub rsp, 16
    mov edi, [rbp-48]
    lea rsi, [rsp]
    mov edx, 5
    call net_read_exact
    test rax, rax
    jnz .re_fail_hdr

    ; Parse header
    movzx eax, byte [rsp]       ; content_type (should be 0x17 for encrypted)
    ; Check for ChangeCipherSpec (type 20) — silently skip
    cmp al, TLS_CT_CHANGE_CIPHER
    je .re_skip_ccs

    ; Parse length
    movzx r14d, byte [rsp+3]
    shl r14d, 8
    movzx eax, byte [rsp+4]
    or r14d, eax               ; r14d = record payload length (ciphertext + tag)
    add rsp, 16

    ; Validate: must be >= 17 (at least 1 byte plaintext + 16 tag)
    cmp r14d, 17
    jb .re_fail

    mov [rbp-72], r14d         ; record payload len

    ; ct_len = payload_len - 16
    mov eax, r14d
    sub eax, 16
    mov [rbp-76], eax          ; ct_len (ciphertext = plaintext_with_ct encrypted)

    ; Check output buffer can hold ct_len - 1 (minus inner content type)
    mov ecx, eax
    dec ecx
    cmp ecx, [rbp-68]
    ja .re_fail                ; output too small

    ; --- Read record payload (ciphertext + tag) ---
    mov eax, r14d
    add eax, 15
    and eax, -16
    add eax, 64                ; safety margin
    sub rsp, rax
    and rsp, -16
    mov r12, rsp               ; r12 = encrypted data buffer

    mov edi, [rbp-48]
    mov rsi, r12
    mov edx, r14d
    call net_read_exact
    test rax, rax
    jnz .re_fail

    ; --- Build nonce: read_iv XOR padded_seq ---
    mov r13, [rbp-56]          ; tls_state

    mov rax, [r13 + TLS_STATE_READ_SEQ]
    bswap rax

    mov ecx, [r13 + TLS_STATE_READ_IV]
    mov [rbp-88], ecx

    mov rcx, [r13 + TLS_STATE_READ_IV + 4]
    xor rcx, rax
    mov [rbp-84], rcx

    ; --- Build AAD from the record header ---
    mov byte [rbp-96], 0x17
    mov byte [rbp-95], 0x03
    mov byte [rbp-94], 0x03
    mov eax, r14d               ; record payload len
    mov byte [rbp-93], ah
    mov byte [rbp-92], al

    ; --- Generate poly_key ---
    lea rdi, [r13 + TLS_STATE_READ_KEY]
    xor esi, esi
    lea rdx, [rbp-88]
    lea rcx, [rbp-192]
    call chacha20_block

    lea rsi, [rbp-192]
    lea rdi, [rbp-128]
    mov ecx, 32
    rep movsb

    ; --- Build mac_data and verify tag ---
    ; mac_data = AAD(5) + pad16(11) + ct(ct_len) + pad16(ct) + LE64(5) + LE64(ct_len)
    mov eax, [rbp-76]           ; ct_len
    add eax, 15
    and eax, -16                ; aligned ct_len
    mov r15d, eax

    ; Allocate mac_data buffer: 16 + aligned_ct + 16 + 16 (computed tag)
    mov ecx, r15d
    add ecx, 64
    sub rsp, rcx
    and rsp, -16
    mov rbx, rsp               ; rbx = mac_data

    ; AAD
    mov rdi, rbx
    lea rsi, [rbp-96]
    mov ecx, 5
    rep movsb

    ; Pad AAD
    xor eax, eax
    mov ecx, 11
    rep stosb

    ; Ciphertext (ct_len bytes from encrypted buffer, NOT the tag)
    mov rsi, r12
    mov ecx, [rbp-76]
    rep movsb

    ; Pad ciphertext
    mov eax, [rbp-76]
    and eax, 15
    jz .re_no_ct_pad
    mov ecx, 16
    sub ecx, eax
    xor eax, eax
    rep stosb
.re_no_ct_pad:

    ; LE64(5)
    mov qword [rdi], 5
    add rdi, 8

    ; LE64(ct_len)
    mov eax, [rbp-76]
    movzx rax, eax
    mov [rdi], rax
    add rdi, 8

    ; mac_data_len
    mov rcx, rdi
    sub rcx, rbx

    ; Compute expected tag
    sub rsp, 16                 ; space for computed tag
    mov r14, rsp                ; r14 = computed tag

    lea rdi, [rbp-128]          ; poly_key
    mov rsi, rbx                ; mac_data
    mov rdx, rcx                ; mac_data_len
    mov rcx, r14                ; output tag
    call poly1305_mac

    ; Compare computed tag with received tag (at r12 + ct_len)
    mov eax, [rbp-76]
    movzx rax, eax
    lea rsi, [r12 + rax]       ; received tag
    xor eax, eax
%assign i 0
%rep 16
    movzx ecx, byte [r14 + i]
    movzx edx, byte [rsi + i]
    xor ecx, edx
    or eax, ecx
%assign i i+1
%endrep

    test eax, eax
    jnz .re_fail                ; MAC verification failed

    ; --- Decrypt: chacha20_encrypt(read_key, 1, nonce, ciphertext, ct_len, output) ---
    ; Decrypt in-place into the output buffer provided by caller
    ; But we need to decrypt to a temp first to extract inner CT
    ; Actually, decrypt into caller's output buffer, then extract inner CT from the end
    mov r13, [rbp-56]
    mov r14, [rbp-64]           ; output buffer

    ; We decrypt ct_len bytes; the last byte is inner_content_type
    lea rdi, [r13 + TLS_STATE_READ_KEY]
    mov esi, 1
    lea rdx, [rbp-88]           ; nonce
    mov rcx, r12                ; input = ciphertext
    mov r8d, [rbp-76]           ; ct_len
    movzx r8, r8d
    mov r9, r14                 ; output = caller's buffer
    call chacha20_encrypt

    ; Extract inner content type from last byte of decrypted data
    mov eax, [rbp-76]
    dec eax                     ; plaintext_len = ct_len - 1
    movzx r8d, byte [r14 + rax] ; inner content type

    ; --- Increment read_seq ---
    mov r13, [rbp-56]
    mov rcx, [r13 + TLS_STATE_READ_SEQ]
    inc rcx
    mov [r13 + TLS_STATE_READ_SEQ], rcx

    ; Return plaintext_len in rax, inner_ct in r8b
    movzx rax, eax
    jmp .re_ret

.re_skip_ccs:
    ; ChangeCipherSpec: read 1 byte payload and discard, then recurse
    add rsp, 16
    ; Read the CCS payload length
    ; We already have the header, parse length
    ; Actually we need to re-read... let's re-parse from the header we already have
    ; The header is at [rsp-16] but we already added 16. Go back.
    sub rsp, 16
    movzx r14d, byte [rsp+3]
    shl r14d, 8
    movzx eax, byte [rsp+4]
    or r14d, eax               ; payload length (should be 1)
    add rsp, 16

    ; Read and discard the CCS payload
    test r14d, r14d
    jz .re_ccs_recurse
    sub rsp, 16
    mov edi, [rbp-48]
    lea rsi, [rsp]
    mov edx, r14d
    call net_read_exact
    add rsp, 16

.re_ccs_recurse:
    ; Retry reading the next record
    mov edi, [rbp-48]
    mov rsi, [rbp-56]
    mov rdx, [rbp-64]
    mov ecx, [rbp-68]
    ; Reset stack and re-enter
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    jmp tls_record_read_enc

.re_fail_hdr:
    add rsp, 16
.re_fail:
    mov rax, -1

.re_ret:
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
