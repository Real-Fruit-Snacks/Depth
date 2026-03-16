; poly1305.inc - Poly1305 MAC function
; Platform-agnostic NASM include file (no syscalls, no API calls)
; Implements RFC 8439 Poly1305 one-shot MAC
;
; Representation: accumulator h as 3 limbs (h0, h1, h2) where
;   h = h0 + h1*2^64 + h2*2^128,  h2 is small (a few bits)
; r as 2 limbs (r0, r1), clamped per spec
; p = 2^130 - 5

section .text

; poly1305_mac: Compute 16-byte Poly1305 authentication tag
; Input:
;   rdi = pointer to 32-byte key (r[0..15] || s[0..15])
;   rsi = message pointer
;   rdx = message length
;   rcx = pointer to 16-byte output tag buffer
; Clobbers: rax, rdx (others saved/restored)
poly1305_mac:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi        ; key pointer
    mov r13, rsi        ; message pointer
    mov r14, rdx        ; message length
    mov r15, rcx        ; output tag pointer

    ; --- Load and clamp r ---
    ; r is first 16 bytes of key, little-endian 128-bit -> r0 (low 64), r1 (high 64)
    mov rax, [r12]       ; r0 = key[0..7] LE
    mov rdx, [r12 + 8]   ; r1 = key[8..15] LE

    ; Clamp r per RFC 8439 Section 2.5:
    ;   r[3], r[7], r[11], r[15]: clear top 4 bits (AND 0x0f)
    ;   r[4], r[8], r[12]: clear bottom 2 bits (AND 0xfc)
    ; In terms of 64-bit limbs:
    ;   r0 bytes [0..7]: clamp byte 3 (AND 0x0f) and byte 4 (AND 0xfc)
    ;     byte 3 is bits 24-31: AND with 0x0f at bit 24 -> mask 0x0fffffff at bits 0-31
    ;     byte 4 is bits 32-39: AND with 0xfc at bit 32 -> mask 0xfffffffc at bits 32-39
    ;     byte 7 is bits 56-63: AND with 0x0f at bit 56
    ;   Combined r0 mask: 0x0ffffffc0ffffffful
    ;   r1 bytes [0..7] = key bytes [8..15]:
    ;     byte 3 (key byte 11): AND 0x0f -> bits 24-31
    ;     byte 4 (key byte 12): AND 0xfc -> bits 32-39
    ;     byte 7 (key byte 15): AND 0x0f -> bits 56-63
    ;   Combined r1 mask: 0x0ffffffc0fffffffUL
    ; But actually byte 0 of r1 is key[8], so:
    ;   key[8]  = r1 byte 0 -> AND 0xfc  (clear bottom 2 bits)
    ;   key[11] = r1 byte 3 -> AND 0x0f  (clear top 4 bits)
    ;   key[12] = r1 byte 4 -> AND 0xfc  (clear bottom 2 bits)
    ;   key[15] = r1 byte 7 -> AND 0x0f  (clear top 4 bits)
    ;   r1 mask: 0x0ffffffc0ffffffcUL

    mov rbx, 0x0ffffffc0fffffff
    and rax, rbx
    mov rbx, 0x0ffffffc0ffffffc
    and rdx, rbx

    ; Store clamped r on stack
    ; Stack layout: [rsp+0] = r0, [rsp+8] = r1, [rsp+16] = s0, [rsp+24] = s1
    sub rsp, 32
    mov [rsp], rax          ; r0
    mov [rsp + 8], rdx      ; r1

    ; Load s (second 16 bytes of key)
    mov rax, [r12 + 16]
    mov [rsp + 16], rax     ; s0
    mov rax, [r12 + 24]
    mov [rsp + 24], rax     ; s1

    ; Initialize accumulator h = 0
    ; We'll use: rbx = h0, rbp = h1, r8 = h2
    xor ebx, ebx           ; h0 = 0
    xor ebp, ebp           ; h1 = 0
    xor r8d, r8d            ; h2 = 0

    ; r13 = message pointer, r14 = remaining length

.poly1305_block_loop:
    cmp r14, 0
    je .poly1305_finalize

    ; Determine block size and hibit
    cmp r14, 16
    jb .poly1305_partial_block

    ; --- Full 16-byte block ---
    ; Load block as little-endian 128-bit: t0 (low 64), t1 (high 64)
    mov r9, [r13]           ; t0
    mov r10, [r13 + 8]      ; t1
    mov r11d, 1             ; hibit = 1 (bit 128)

    add r13, 16
    sub r14, 16
    jmp .poly1305_process_block

.poly1305_partial_block:
    ; Partial block: read r14 bytes, pad with zeros, hibit at position r14
    ; Use stack temp buffer
    sub rsp, 32
    ; Zero it
    mov qword [rsp], 0
    mov qword [rsp + 8], 0
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 0

    ; Copy r14 bytes from [r13] to [rsp]
    xor ecx, ecx
.poly1305_copy_partial:
    cmp rcx, r14
    jge .poly1305_copy_done
    movzx eax, byte [r13 + rcx]
    mov byte [rsp + rcx], al
    inc rcx
    jmp .poly1305_copy_partial

.poly1305_copy_done:
    ; Set the 0x01 byte at position r14
    mov byte [rsp + r14], 0x01

    ; Load padded block
    mov r9, [rsp]           ; t0
    mov r10, [rsp + 8]      ; t1

    ; hibit: if r14 < 16, the 0x01 byte could be in t0, t1, or at bit 128
    ; If r14 < 8: hibit is in t0 already, r11 = 0
    ; If r14 >= 8 and < 16: hibit is in t1 already, r11 = 0
    ; The 0x01 is already placed in the buffer at the right position, so hibit = 0
    ; (the 0x01 byte in the padded buffer handles it)
    xor r11d, r11d          ; hibit = 0

    add rsp, 32
    mov r14, 0              ; consumed all remaining bytes

.poly1305_process_block:
    ; h += block: h0 += t0, h1 += t1, h2 += hibit (with carry propagation)
    add rbx, r9
    adc rbp, r10
    adc r8, r11             ; r8 = h2 + hibit + carry

    ; Now compute h = h * r mod p, where p = 2^130 - 5
    ; h = h0 + h1*2^64 + h2*2^128
    ; r = r0 + r1*2^64
    ;
    ; h*r = h0*r0 + (h0*r1 + h1*r0)*2^64 + (h1*r1 + h2*r0)*2^128 + h2*r1*2^192
    ;
    ; We need to reduce mod 2^130-5.  Since 2^130 = 5 mod p:
    ;   x * 2^130 = x * 5 mod p
    ;   x * 2^192 = x * 5 * 2^62 mod p  (but this gets complicated)
    ;
    ; Better approach: full product in 5 "words", then reduce.
    ; d0 + d1*2^64 + d2*2^128 + d3*2^192 + d4*2^256
    ;
    ; d0 = lo(h0*r0)
    ; d1 = hi(h0*r0) + lo(h0*r1) + lo(h1*r0)
    ; d2 = hi(h0*r1) + hi(h1*r0) + lo(h1*r1) + h2*r0
    ; d3 = hi(h1*r1) + h2*r1
    ; d4 = 0 (h2 is small, at most a few bits)
    ;
    ; Then reduce: bits >= 130 get multiplied by 5 and added back.
    ;
    ; We'll store intermediate results on a temporary stack area.

    ; Save r14 (msg remaining) and r13 (msg pointer) - we need registers
    push r14
    push r13

    ; Load r0, r1 from our stack (now at rsp+16 due to 2 pushes)
    mov r14, [rsp + 16]      ; r0
    mov r13, [rsp + 24]      ; r1

    ; --- Compute h0 * r0 -> d0:d1_a ---
    mov rax, rbx             ; h0
    mul r14                  ; rdx:rax = h0 * r0
    mov r9, rax              ; d0 = lo
    mov r10, rdx             ; d1 partial = hi

    ; --- Compute h0 * r1 -> add to d1:d2_a ---
    mov rax, rbx             ; h0
    mul r13                  ; rdx:rax = h0 * r1
    mov r11, rdx             ; d2 partial = hi(h0*r1)
    add r10, rax             ; d1 += lo(h0*r1)
    adc r11, 0               ; d2 += carry

    ; --- Compute h1 * r0 -> add to d1:d2 ---
    mov rax, rbp             ; h1
    mul r14                  ; rdx:rax = h1 * r0
    add r10, rax             ; d1 += lo(h1*r0)
    adc r11, rdx             ; d2 += hi(h1*r0) + carry
    mov ecx, 0
    adc ecx, 0               ; carry into d3

    ; --- Compute h1 * r1 -> add to d2:d3 ---
    mov rax, rbp             ; h1
    mul r13                  ; rdx:rax = h1 * r1
    add r11, rax             ; d2 += lo(h1*r1)
    adc ecx, edx             ; d3 += hi(h1*r1) + carry (ecx is 64-bit safe, values small)
    ; Actually use rcx for safety
    ; Re-do: rcx was set to carry (0 or 1) above, then adc ecx, edx
    ; This could overflow 32-bit. Let's use full 64-bit rcx.
    ; Actually let me redo this more carefully.

    ; Let me restart the multiplication more carefully with proper carry tracking.
    ; Pop and redo.
    pop r13
    pop r14

    ; --- Redo multiplication properly ---
    push r14
    push r13
    push r12                 ; need one more register

    mov r14, [rsp + 24]      ; r0 (rsp shifted by 3 pushes = +24 from original rsp+0)
    mov r13, [rsp + 32]      ; r1

    ; d0, d1, d2, d3 will use: r9, r10, r11, r12
    ; d4 not needed (h2 is at most ~4 bits, r is 124 bits, so d4 is 0 in practice)

    ; h0*r0
    mov rax, rbx
    mul r14
    mov r9, rax              ; d0
    mov r10, rdx             ; d1

    ; h0*r1
    mov rax, rbx
    mul r13
    xor r11d, r11d
    add r10, rax
    adc r11, rdx             ; d2

    ; h1*r0
    mov rax, rbp
    mul r14
    xor r12d, r12d
    add r10, rax
    adc r11, rdx
    adc r12, 0               ; d3 carry

    ; h1*r1
    mov rax, rbp
    mul r13
    add r11, rax
    adc r12, rdx             ; d3

    ; h2*r0 (h2 is small, just a few bits, so this is a small multiplication)
    mov rax, r8              ; h2
    imul rax, r14            ; h2 * r0 (fits in 64 bits since h2 is tiny)
    add r11, rax
    adc r12, 0

    ; h2*r1
    mov rax, r8
    imul rax, r13            ; h2 * r1 (fits in 64 bits)
    add r12, rax
    ; d3 = r12, no further carry needed (result fits)

    ; Now we have the 256-bit product: d0(r9) + d1(r10)*2^64 + d2(r11)*2^128 + d3(r12)*2^192
    ;
    ; Reduce mod 2^130 - 5:
    ; Split at bit 130: low part = bits [0..129], high part = bits [130..]
    ; result = low + high * 5
    ;
    ; bits [0..63] = r9 = h0
    ; bits [64..127] = r10 = h1
    ; bits [128..129] = r11 & 3 = h2 (low 2 bits of r11)
    ; bits [130..191] = (r11 >> 2) | (r12 << 62)
    ; bits [192..255] = (r12 >> 2)
    ;
    ; high = bits[130..] as a number
    ; high = (r11 >> 2) + (r12 << 62)*1 + (r12 >> 2)*2^64  -- wait let me think again
    ;
    ; The 260-bit number: r9 + r10*2^64 + r11*2^128 + r12*2^192
    ; Low 130 bits:  r9 + r10*2^64 + (r11 & 0x3)*2^128
    ; High part (bits 130+): shifted right by 130 = (r11 >> 2) + (r12 * 2^62)
    ;   Wait: bit 130 of the full number is bit 2 of r11.
    ;   So high_part = (r11 >> 2) + r12 * 2^(192-130) = (r11 >> 2) + r12 * 2^62
    ;   As a 130-bit number: high0 = (r11 >> 2) | (r12 << 62), high1 = r12 >> 2
    ;
    ; result = low + high * 5
    ;        = r9 + r10*2^64 + (r11&3)*2^128 + 5*((r11>>2) | (r12<<62)) + 5*(r12>>2)*2^64

    ; Compute high0 = (r11 >> 2) | (r12 << 62)
    mov rax, r11
    shr rax, 2
    mov rcx, r12
    shl rcx, 62
    or rax, rcx             ; high0

    ; Compute high1 = r12 >> 2
    mov rcx, r12
    shr rcx, 2              ; high1

    ; h2 = r11 & 3
    and r11, 3

    ; Now: result = r9 + r10*2^64 + r11*2^128 + 5*(rax + rcx*2^64)
    ; Multiply high by 5 and add to low
    ; 5 * high0
    mov rdx, rax
    mov rax, 5
    mul rdx                 ; rdx:rax = 5 * high0
    add r9, rax             ; h0 += 5*high0 (low)
    adc r10, rdx            ; h1 += carry + 5*high0 (high)
    adc r11, 0              ; h2 += carry

    ; 5 * high1 -> add to h1
    mov rax, 5
    mul rcx                 ; rdx:rax = 5 * high1
    add r10, rax
    adc r11, rdx            ; h2 could grow but stays small

    ; Set h0, h1, h2
    mov rbx, r9
    mov rbp, r10
    mov r8, r11

    ; Restore saved registers
    pop r12
    pop r13
    pop r14

    jmp .poly1305_block_loop

.poly1305_finalize:
    ; h = h0(rbx) + h1(rbp)*2^64 + h2(r8)*2^128
    ; We need to compute (h + s) mod 2^128
    ; But first, we should do a final reduction to ensure h < p = 2^130 - 5
    ;
    ; Full reduction:
    ; After the loop, h < 2^130 (approximately). We need h mod p.
    ; If h >= p, then h -= p. Since p = 2^130 - 5, h >= p iff h >= 2^130 - 5.
    ;
    ; Method: compute g = h + 5. If g >= 2^130 (i.e., bit 130 set or h2 >= 4 after add),
    ; then h >= p, so use g (mod 2^130) as the reduced value.

    ; g = h + 5
    mov r9, rbx
    mov r10, rbp
    mov r11, r8
    add r9, 5
    adc r10, 0
    adc r11, 0

    ; Check if g >= 2^130, i.e., bit 130 set -> r11 >= 4
    ; (since h2 was at most ~4 bits, after +5 with carries, check bit 2 of r11)
    mov rax, r11
    shr rax, 2              ; 1 if g >= 2^130, else 0

    ; If rax = 1: use g (masked to 130 bits) = g mod 2^130
    ; If rax = 0: use h
    ; mask = rax == 1 ? 0xFFFFFFFFFFFFFFFF : 0
    neg rax                 ; 0 -> 0, 1 -> 0xFFFFFFFFFFFFFFFF
    mov rcx, rax            ; mask

    ; g mod 2^130: clear top bits of r11
    and r11, 3

    ; Select: h0 = (g0 & mask) | (h0 & ~mask), etc.
    ; h0 = h0 ^ ((h0 ^ g0) & mask)
    mov rax, rbx
    xor rax, r9
    and rax, rcx
    xor rbx, rax            ; h0 = reduced

    mov rax, rbp
    xor rax, r10
    and rax, rcx
    xor rbp, rax            ; h1 = reduced

    mov rax, r8
    xor rax, r11
    and rax, rcx
    xor r8, rax             ; h2 = reduced (0, 1, 2, or 3)

    ; Now h = h0(rbx) + h1(rbp)*2^64 + h2(r8)*2^128, and h < p
    ; Compute tag = (h + s) mod 2^128
    ; s = s0 + s1*2^64 (128-bit)
    ; We add s to the 130-bit h, take lower 128 bits

    add rbx, [rsp + 16]     ; h0 += s0
    adc rbp, [rsp + 24]     ; h1 += s1
    ; We discard any carry beyond 128 bits (mod 2^128)

    ; Write 16-byte tag in little-endian
    mov [r15], rbx
    mov [r15 + 8], rbp

    ; Clean up stack (32 bytes for r0,r1,s0,s1)
    add rsp, 32

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
