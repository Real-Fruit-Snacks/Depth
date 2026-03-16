; SHA-256 implementation per FIPS 180-4
; Calling convention: sha256(rdi=msg_ptr, rsi=msg_len, rdx=output_32bytes)

%include "ssh.inc"

section .rodata
align 16

; Round constants K[0..63] - cube roots of first 64 primes
K:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

; Initial hash values H0 - square roots of first 8 primes
H0:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

section .text
global sha256

; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx   \
;   rbp-16      saved r12    |  5 callee-saved registers (pushed after mov rbp,rsp)
;   rbp-24      saved r13    |
;   rbp-32      saved r14    |
;   rbp-40      saved r15   /
;   rbp-72      H[0..7]   hash state (32 bytes)
;   rbp-328     W[0..63]  message schedule (256 bytes)
;   rbp-336     saved output pointer
;   rbp-344     saved msg pointer
;   rbp-352     saved msg length
;   rbp-360     padded length
;   rbp-392     working vars a-h during rounds (32 bytes)
;   Below that:  pad buffer (variable size, allocated dynamically)

sha256:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 400                    ; fixed frame space (aligned)

    ; Save arguments
    mov [rbp-344], rdi              ; msg pointer
    mov [rbp-352], rsi              ; msg length
    mov [rbp-336], rdx              ; output pointer

    ; Calculate padded length
    mov rax, rsi
    add rax, 9                      ; +1 for 0x80, +8 for bit count
    add rax, 63
    and rax, -64                    ; round up to multiple of 64
    mov [rbp-360], rax
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
    mov rsi, [rbp-344]
    mov rcx, [rbp-352]
    rep movsb

    ; Append 0x80 byte after message
    mov byte [rdi], 0x80

    ; Write 64-bit big-endian bit count at end of padded buffer
    mov rax, [rbp-352]
    shl rax, 3                      ; bit count
    bswap rax
    mov [r13 + r12 - 8], rax

    ; Initialize hash state from H0
    lea rsi, [rel H0]
    lea rdi, [rbp-72]
    %assign i 0
    %rep 8
        mov eax, [rsi + i*4]
        mov [rdi + i*4], eax
        %assign i i+1
    %endrep

    ; Process each 64-byte block
    xor r14d, r14d                  ; r14 = block offset

.block_loop:
    cmp r14, r12
    jge .done_blocks

    ; --- Load W[0..15] from block in big-endian ---
    lea rsi, [r13 + r14]
    lea rdi, [rbp-328]
    mov ecx, 16
.load_w:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .load_w

    ; --- Expand W[16..63] ---
    lea r15, [rbp-328]              ; r15 = W base
    mov ecx, 16
.expand_w:
    ; sigma1(W[i-2]) = ror(x,17) ^ ror(x,19) ^ (x >> 10)
    mov eax, [r15 + rcx*4 - 8]
    mov edx, eax
    mov ebx, eax
    ror edx, 17
    ror ebx, 19
    xor edx, ebx
    shr eax, 10
    xor edx, eax                   ; edx = sigma1(W[i-2])

    ; sigma0(W[i-15]) = ror(x,7) ^ ror(x,18) ^ (x >> 3)
    mov eax, [r15 + rcx*4 - 60]
    mov ebx, eax
    mov esi, eax
    ror ebx, 7
    ror esi, 18
    xor ebx, esi
    shr eax, 3
    xor ebx, eax                   ; ebx = sigma0(W[i-15])

    ; W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    add edx, [r15 + rcx*4 - 28]    ; + W[i-7]
    add edx, ebx                    ; + sigma0(W[i-15])
    add edx, [r15 + rcx*4 - 64]    ; + W[i-16]
    mov [r15 + rcx*4], edx

    inc ecx
    cmp ecx, 64
    jl .expand_w

    ; --- Initialize working variables from hash state ---
    ; Copy H[0..7] to working vars area at rbp-392
    lea rsi, [rbp-72]
    lea rdi, [rbp-392]
    %assign i 0
    %rep 8
        mov eax, [rsi + i*4]
        mov [rdi + i*4], eax
        %assign i i+1
    %endrep

    ; --- 64 compression rounds ---
    ; Working vars at rbp-392: a(+0) b(+4) c(+8) d(+12) e(+16) f(+20) g(+24) h(+28)
    xor ecx, ecx                    ; round counter
.round_loop:
    ; Load working vars into registers for this round
    ; We use: eax=a, ebx=temp, edx=temp, esi=temp, edi=temp
    ; r8d=e for Sigma1/Ch

    ; --- Compute T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i] ---

    ; Start T1 = h
    mov eax, [rbp-392+28]          ; h

    ; Sigma1(e) = ror(e,6) ^ ror(e,11) ^ ror(e,25)
    mov r8d, [rbp-392+16]          ; e
    mov edx, r8d
    ror edx, 6
    mov ebx, r8d
    ror ebx, 11
    xor edx, ebx
    mov ebx, r8d
    ror ebx, 25
    xor edx, ebx
    add eax, edx                   ; T1 += Sigma1(e)

    ; Ch(e,f,g) = (e & f) ^ (~e & g)
    mov edx, r8d
    and edx, [rbp-392+20]          ; e & f
    mov ebx, r8d
    not ebx
    and ebx, [rbp-392+24]          ; ~e & g
    xor edx, ebx
    add eax, edx                   ; T1 += Ch(e,f,g)

    ; T1 += K[i]
    lea rdx, [rel K]
    add eax, [rdx + rcx*4]

    ; T1 += W[i]
    add eax, [r15 + rcx*4]

    ; eax = T1
    mov r8d, eax                   ; save T1 in r8d

    ; --- Compute T2 = Sigma0(a) + Maj(a,b,c) ---

    ; Sigma0(a) = ror(a,2) ^ ror(a,13) ^ ror(a,22)
    mov eax, [rbp-392+0]           ; a
    mov edx, eax
    ror edx, 2
    mov ebx, eax
    ror ebx, 13
    xor edx, ebx
    mov ebx, eax
    ror ebx, 22
    xor edx, ebx                  ; edx = Sigma0(a)

    ; Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    mov ebx, eax                   ; a
    mov esi, [rbp-392+4]           ; b
    mov edi, [rbp-392+8]           ; c
    mov eax, ebx
    and eax, esi                   ; a & b
    mov r9d, ebx
    and r9d, edi                   ; a & c
    xor eax, r9d
    mov r9d, esi
    and r9d, edi                   ; b & c
    xor eax, r9d                   ; eax = Maj(a,b,c)

    add edx, eax                   ; T2 = Sigma0(a) + Maj(a,b,c)
    ; edx = T2, r8d = T1

    ; --- Shift working variables ---
    ; h = g
    mov eax, [rbp-392+24]
    mov [rbp-392+28], eax
    ; g = f
    mov eax, [rbp-392+20]
    mov [rbp-392+24], eax
    ; f = e
    mov eax, [rbp-392+16]
    mov [rbp-392+20], eax
    ; e = d + T1
    mov eax, [rbp-392+12]
    add eax, r8d
    mov [rbp-392+16], eax
    ; d = c
    mov eax, [rbp-392+8]
    mov [rbp-392+12], eax
    ; c = b
    mov eax, [rbp-392+4]
    mov [rbp-392+8], eax
    ; b = a
    mov eax, [rbp-392+0]
    mov [rbp-392+4], eax
    ; a = T1 + T2
    mov eax, r8d
    add eax, edx
    mov [rbp-392+0], eax

    inc ecx
    cmp ecx, 64
    jl .round_loop

    ; --- Add working vars back to hash state ---
    %assign i 0
    %rep 8
        mov eax, [rbp-392 + i*4]
        add [rbp-72 + i*4], eax
        %assign i i+1
    %endrep

    ; Next block
    add r14, 64
    jmp .block_loop

.done_blocks:
    ; Write final hash to output in big-endian
    mov rdi, [rbp-336]              ; output pointer
    lea rsi, [rbp-72]               ; hash state
    mov ecx, 8
.write_hash:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .write_hash

    ; Restore stack and return
    lea rsp, [rbp-40]               ; restore to after push r15 (5 regs * 8 = 40 bytes above rbp)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
