; SHA-512 implementation per FIPS 180-4
; Calling convention: sha512(rdi=msg_ptr, rsi=msg_len, rdx=output_64bytes)

%include "ssh.inc"

section .rodata
align 16

; Round constants K[0..79] - cube roots of first 80 primes (64-bit)
K:
    dq 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70
    dq 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
    dq 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30
    dq 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    dq 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    dq 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
    dq 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

; Initial hash values H0 - square roots of first 8 primes (64-bit)
H0:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
    dq 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f
    dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

section .text
global sha512

; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-104     H[0..7]   hash state (64 bytes)
;   rbp-744     W[0..79]  message schedule (640 bytes)
;   rbp-752     saved output pointer
;   rbp-760     saved msg pointer
;   rbp-768     saved msg length
;   rbp-776     padded length
;   rbp-840     working vars a-h during rounds (64 bytes)
;   Below that:  pad buffer (variable size, allocated dynamically)

sha512:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 848                    ; fixed frame space (aligned)

    ; Save arguments
    mov [rbp-760], rdi              ; msg pointer
    mov [rbp-768], rsi              ; msg length
    mov [rbp-752], rdx              ; output pointer

    ; Calculate padded length
    ; padded_len = ((msg_len + 17) + 127) & ~127
    ; +1 for 0x80, +16 for 128-bit bit count
    mov rax, rsi
    add rax, 17                     ; +1 for 0x80, +16 for bit count
    add rax, 127
    and rax, -128                   ; round up to multiple of 128
    mov [rbp-776], rax
    mov r12, rax                    ; r12 = padded length

    ; Allocate pad buffer on stack (16-byte aligned)
    mov rax, r12
    add rax, 15
    and rax, -16
    sub rsp, rax
    and rsp, -16                    ; ensure alignment
    mov r13, rsp                    ; r13 = pad buffer

    ; Zero the entire pad buffer first
    mov rdi, r13
    xor eax, eax
    mov rcx, r12
    rep stosb

    ; Copy message to pad buffer
    mov rdi, r13
    mov rsi, [rbp-760]
    mov rcx, [rbp-768]
    rep movsb

    ; Append 0x80 byte after message
    mov byte [rdi], 0x80

    ; Write 128-bit big-endian bit count at end of padded buffer
    ; Upper 64 bits = 0 (already zeroed)
    ; Lower 64 bits = msg_len * 8
    mov rax, [rbp-768]
    shl rax, 3                      ; bit count
    bswap rax
    mov [r13 + r12 - 8], rax
    ; Upper 64 bits at [r13 + r12 - 16] already 0

    ; Initialize hash state from H0
    lea rsi, [rel H0]
    lea rdi, [rbp-104]
    %assign i 0
    %rep 8
        mov rax, [rsi + i*8]
        mov [rdi + i*8], rax
        %assign i i+1
    %endrep

    ; Process each 128-byte block
    xor r14d, r14d                  ; r14 = block offset

.block_loop:
    cmp r14, r12
    jge .done_blocks

    ; --- Load W[0..15] from block in big-endian ---
    lea rsi, [r13 + r14]
    lea rdi, [rbp-744]
    mov ecx, 16
.load_w:
    mov rax, [rsi]
    bswap rax
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .load_w

    ; --- Expand W[16..79] ---
    lea r15, [rbp-744]              ; r15 = W base
    mov ecx, 16
.expand_w:
    ; sigma1(W[i-2]) = ror(x,19) ^ ror(x,61) ^ (x >> 6)
    mov rax, [r15 + rcx*8 - 16]
    mov rdx, rax
    mov rbx, rax
    ror rdx, 19
    ror rbx, 61
    xor rdx, rbx
    shr rax, 6
    xor rdx, rax                   ; rdx = sigma1(W[i-2])

    ; sigma0(W[i-15]) = ror(x,1) ^ ror(x,8) ^ (x >> 7)
    mov rax, [r15 + rcx*8 - 120]
    mov rbx, rax
    mov rsi, rax
    ror rbx, 1
    ror rsi, 8
    xor rbx, rsi
    shr rax, 7
    xor rbx, rax                   ; rbx = sigma0(W[i-15])

    ; W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    add rdx, [r15 + rcx*8 - 56]    ; + W[i-7]
    add rdx, rbx                    ; + sigma0(W[i-15])
    add rdx, [r15 + rcx*8 - 128]   ; + W[i-16]
    mov [r15 + rcx*8], rdx

    inc ecx
    cmp ecx, 80
    jl .expand_w

    ; --- Initialize working variables from hash state ---
    ; Copy H[0..7] to working vars area at rbp-840
    lea rsi, [rbp-104]
    lea rdi, [rbp-840]
    %assign i 0
    %rep 8
        mov rax, [rsi + i*8]
        mov [rdi + i*8], rax
        %assign i i+1
    %endrep

    ; --- 80 compression rounds ---
    ; Working vars at rbp-840: a(+0) b(+8) c(+16) d(+24) e(+32) f(+40) g(+48) h(+56)
    xor ecx, ecx                    ; round counter
.round_loop:
    ; --- Compute T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i] ---

    ; Start T1 = h
    mov rax, [rbp-840+56]          ; h

    ; Sigma1(e) = ror(e,14) ^ ror(e,18) ^ ror(e,41)
    mov r8, [rbp-840+32]           ; e
    mov rdx, r8
    ror rdx, 14
    mov rbx, r8
    ror rbx, 18
    xor rdx, rbx
    mov rbx, r8
    ror rbx, 41
    xor rdx, rbx
    add rax, rdx                   ; T1 += Sigma1(e)

    ; Ch(e,f,g) = (e & f) ^ (~e & g)
    mov rdx, r8
    and rdx, [rbp-840+40]          ; e & f
    mov rbx, r8
    not rbx
    and rbx, [rbp-840+48]          ; ~e & g
    xor rdx, rbx
    add rax, rdx                   ; T1 += Ch(e,f,g)

    ; T1 += K[i]
    lea rdx, [rel K]
    add rax, [rdx + rcx*8]

    ; T1 += W[i]
    add rax, [r15 + rcx*8]

    ; rax = T1
    mov r8, rax                    ; save T1 in r8

    ; --- Compute T2 = Sigma0(a) + Maj(a,b,c) ---

    ; Sigma0(a) = ror(a,28) ^ ror(a,34) ^ ror(a,39)
    mov rax, [rbp-840+0]           ; a
    mov rdx, rax
    ror rdx, 28
    mov rbx, rax
    ror rbx, 34
    xor rdx, rbx
    mov rbx, rax
    ror rbx, 39
    xor rdx, rbx                  ; rdx = Sigma0(a)

    ; Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    mov rbx, rax                   ; a
    mov rsi, [rbp-840+8]           ; b
    mov rdi, [rbp-840+16]          ; c
    mov rax, rbx
    and rax, rsi                   ; a & b
    mov r9, rbx
    and r9, rdi                    ; a & c
    xor rax, r9
    mov r9, rsi
    and r9, rdi                    ; b & c
    xor rax, r9                   ; rax = Maj(a,b,c)

    add rdx, rax                   ; T2 = Sigma0(a) + Maj(a,b,c)
    ; rdx = T2, r8 = T1

    ; --- Shift working variables ---
    ; h = g
    mov rax, [rbp-840+48]
    mov [rbp-840+56], rax
    ; g = f
    mov rax, [rbp-840+40]
    mov [rbp-840+48], rax
    ; f = e
    mov rax, [rbp-840+32]
    mov [rbp-840+40], rax
    ; e = d + T1
    mov rax, [rbp-840+24]
    add rax, r8
    mov [rbp-840+32], rax
    ; d = c
    mov rax, [rbp-840+16]
    mov [rbp-840+24], rax
    ; c = b
    mov rax, [rbp-840+8]
    mov [rbp-840+16], rax
    ; b = a
    mov rax, [rbp-840+0]
    mov [rbp-840+8], rax
    ; a = T1 + T2
    mov rax, r8
    add rax, rdx
    mov [rbp-840+0], rax

    inc ecx
    cmp ecx, 80
    jl .round_loop

    ; --- Add working vars back to hash state ---
    %assign i 0
    %rep 8
        mov rax, [rbp-840 + i*8]
        add [rbp-104 + i*8], rax
        %assign i i+1
    %endrep

    ; Next block
    add r14, 128
    jmp .block_loop

.done_blocks:
    ; Write final hash to output in big-endian
    mov rdi, [rbp-752]              ; output pointer
    lea rsi, [rbp-104]              ; hash state
    mov ecx, 8
.write_hash:
    mov rax, [rsi]
    bswap rax
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .write_hash

    ; Restore stack and return
    lea rsp, [rbp-40]               ; restore to after push r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
