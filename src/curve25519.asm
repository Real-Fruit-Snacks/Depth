; X25519 Diffie-Hellman key exchange per RFC 7748
; Pure x86-64, 5-limb (51-bit radix) field arithmetic over GF(2^255-19)

%include "ssh.inc"

section .rodata
align 16
basepoint:
    db 9
    times 31 db 0

section .text

global x25519, x25519_base
global fe_add, fe_sub, fe_mul, fe_square
global fe_invert, fe_tobytes, fe_frombytes, fe_mul121666

%define LIMB_MASK 0x7ffffffffffff

; Helper macro: rax = %1, mul %2, add product to rcx:rdi
%macro MULADD 2
    mov rax, %1
    mul qword %2
    add rcx, rax
    adc rdi, rdx
%endmacro

; ============================================================================
; fe_add(rdi=out, rsi=a, rdx=b)
; ============================================================================
fe_add:
    mov rax, [rsi]
    add rax, [rdx]
    mov [rdi], rax
    mov rax, [rsi+8]
    add rax, [rdx+8]
    mov [rdi+8], rax
    mov rax, [rsi+16]
    add rax, [rdx+16]
    mov [rdi+16], rax
    mov rax, [rsi+24]
    add rax, [rdx+24]
    mov [rdi+24], rax
    mov rax, [rsi+32]
    add rax, [rdx+32]
    mov [rdi+32], rax
    ret

; ============================================================================
; fe_sub(rdi=out, rsi=a, rdx=b) — out = a - b + 2p (keeps positive)
; ============================================================================
fe_sub:
    mov r8, 0xFFFFFFFFFFFDA
    mov r9, 0xFFFFFFFFFFFFE
    mov rax, r8
    add rax, [rsi]
    sub rax, [rdx]
    mov [rdi], rax
    mov rax, r9
    add rax, [rsi+8]
    sub rax, [rdx+8]
    mov [rdi+8], rax
    mov rax, r9
    add rax, [rsi+16]
    sub rax, [rdx+16]
    mov [rdi+16], rax
    mov rax, r9
    add rax, [rsi+24]
    sub rax, [rdx+24]
    mov [rdi+24], rax
    mov rax, r9
    add rax, [rsi+32]
    sub rax, [rdx+32]
    mov [rdi+32], rax
    ret

; ============================================================================
; fe_mul(rdi=out, rsi=a, rdx=b)
; Schoolbook 5x5 with mod 2^255-19 reduction via 19* on overflow limbs.
; a[] saved to stack, b accessed via rbx.
; ============================================================================
fe_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 56

    mov [rsp+48], rdi       ; out
    mov rbx, rdx            ; b

    ; Load a[] to regs and stack
    mov r8,  [rsi]
    mov r9,  [rsi+8]
    mov r10, [rsi+16]
    mov r11, [rsi+24]
    mov r12, [rsi+32]
    mov [rsp],    r8
    mov [rsp+8],  r9
    mov [rsp+16], r10
    mov [rsp+24], r11
    mov [rsp+32], r12

    ; 19 * a[1..4]
    imul r13, r9,  19
    imul r14, r10, 19
    imul r15, r11, 19
    imul rbp, r12, 19

    mov rsi, LIMB_MASK

    ; --- limb 0: a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) ---
    mov rax, r8
    mul qword [rbx]
    mov rcx, rax
    mov rdi, rdx
    MULADD r13, [rbx+32]
    MULADD r14, [rbx+24]
    MULADD r15, [rbx+16]
    MULADD rbp, [rbx+8]
    mov r8, rcx
    and r8, rsi
    shrd rcx, rdi, 51

    ; --- limb 1: a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2) + carry ---
    mov rax, [rsp]
    mul qword [rbx+8]
    mov rdi, rdx
    add rax, rcx
    adc rdi, 0
    mov rcx, rax
    MULADD r9, [rbx]
    MULADD r14, [rbx+32]
    MULADD r15, [rbx+24]
    MULADD rbp, [rbx+16]
    mov r9, rcx
    and r9, rsi
    shrd rcx, rdi, 51

    ; --- limb 2: a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3) + carry ---
    mov rax, [rsp]
    mul qword [rbx+16]
    mov rdi, rdx
    add rax, rcx
    adc rdi, 0
    mov rcx, rax
    MULADD qword [rsp+8], [rbx+8]
    MULADD r10, [rbx]
    MULADD r15, [rbx+32]
    MULADD rbp, [rbx+24]
    mov r10, rcx
    and r10, rsi
    shrd rcx, rdi, 51

    ; --- limb 3: a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4 + carry ---
    mov rax, [rsp]
    mul qword [rbx+24]
    mov rdi, rdx
    add rax, rcx
    adc rdi, 0
    mov rcx, rax
    MULADD qword [rsp+8],  [rbx+16]
    MULADD qword [rsp+16], [rbx+8]
    MULADD r11, [rbx]
    MULADD rbp, [rbx+32]
    mov r11, rcx
    and r11, rsi
    shrd rcx, rdi, 51

    ; --- limb 4: a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + carry ---
    mov rax, [rsp]
    mul qword [rbx+32]
    mov rdi, rdx
    add rax, rcx
    adc rdi, 0
    mov rcx, rax
    MULADD qword [rsp+8],  [rbx+24]
    MULADD qword [rsp+16], [rbx+16]
    MULADD qword [rsp+24], [rbx+8]
    MULADD r12, [rbx]
    mov r12, rcx
    and r12, rsi
    shrd rcx, rdi, 51

    ; Reduce carry from limb4
    imul rcx, 19
    add r8, rcx
    mov rax, r8
    shr rax, 51
    and r8, rsi
    add r9, rax

    ; Store
    mov rdi, [rsp+48]
    mov [rdi],    r8
    mov [rdi+8],  r9
    mov [rdi+16], r10
    mov [rdi+24], r11
    mov [rdi+32], r12

    add rsp, 56
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; fe_square(rdi=out, rsi=a) — a^2 mod p (calls fe_mul with b=a)
; ============================================================================
fe_square:
    mov rdx, rsi
    jmp fe_mul

; ============================================================================
; fe_frombytes(rdi=fe_out, rsi=32byte_in)
; ============================================================================
fe_frombytes:
    mov rax, [rsi]
    mov rcx, [rsi+8]
    mov r8,  [rsi+16]
    mov r9,  [rsi+24]
    mov r10, 0x7FFFFFFFFFFFFFFF
    and r9, r10
    mov rdx, LIMB_MASK

    mov r10, rax
    and r10, rdx
    mov [rdi], r10

    shrd rax, rcx, 51
    shrd rcx, r8, 51
    shrd r8, r9, 51
    shr r9, 51
    mov r10, rax
    and r10, rdx
    mov [rdi+8], r10

    shrd rax, rcx, 51
    shrd rcx, r8, 51
    shrd r8, r9, 51
    shr r9, 51
    mov r10, rax
    and r10, rdx
    mov [rdi+16], r10

    shrd rax, rcx, 51
    shrd rcx, r8, 51
    shrd r8, r9, 51
    shr r9, 51
    mov r10, rax
    and r10, rdx
    mov [rdi+24], r10

    shrd rax, rcx, 51
    and rax, rdx
    mov [rdi+32], rax
    ret

; ============================================================================
; fe_tobytes(rdi=32byte_out, rsi=fe)
; ============================================================================
fe_tobytes:
    push rbx
    push r12
    push r13

    mov r13, rdi

    mov rax, [rsi]
    mov rcx, [rsi+8]
    mov r8,  [rsi+16]
    mov r9,  [rsi+24]
    mov r10, [rsi+32]
    mov rdx, LIMB_MASK

    ; Carry pass 1
    mov r11, rax
    shr r11, 51
    and rax, rdx
    add rcx, r11

    mov r11, rcx
    shr r11, 51
    and rcx, rdx
    add r8, r11

    mov r11, r8
    shr r11, 51
    and r8, rdx
    add r9, r11

    mov r11, r9
    shr r11, 51
    and r9, rdx
    add r10, r11

    mov r11, r10
    shr r11, 51
    and r10, rdx
    imul r11, 19
    add rax, r11

    ; Carry pass 2
    mov r11, rax
    shr r11, 51
    and rax, rdx
    add rcx, r11

    ; Conditional subtraction of p if val >= p
    mov r11, rax
    add r11, 19
    mov r12, r11
    shr r12, 51
    and r11, rdx

    add r12, rcx
    mov rbx, r12
    shr rbx, 51
    and r12, rdx

    add rbx, r8
    mov rdi, rbx
    shr rdi, 51
    and rbx, rdx

    add rdi, r9
    mov rsi, rdi
    shr rsi, 51
    and rdi, rdx

    add rsi, r10
    bt rsi, 51
    jnc .tobytes_no_reduce
    mov rax, r11
    mov rcx, r12
    mov r8, rbx
    mov r9, rdi
    mov r10, rsi
    and r10, rdx
.tobytes_no_reduce:

    ; Recombine
    mov r11, rcx
    shl r11, 51
    or rax, r11
    mov [r13], rax

    mov rax, rcx
    shr rax, 13
    mov r11, r8
    shl r11, 38
    or rax, r11
    mov [r13+8], rax

    mov rax, r8
    shr rax, 26
    mov r11, r9
    shl r11, 25
    or rax, r11
    mov [r13+16], rax

    mov rax, r9
    shr rax, 39
    mov r11, r10
    shl r11, 12
    or rax, r11
    mov [r13+24], rax

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; fe_invert(rdi=out, rsi=z) — z^(p-2) via addition chain for 2^255-21
; ============================================================================
fe_invert:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 400
    and rsp, -16

    mov [rbp-8], rdi
    mov [rbp-16], rsi

    ; Temps: z2=rsp, z9=rsp+40, z11=rsp+80, z_5_0=rsp+120,
    ;        z_10_0=rsp+160, z_20_0=rsp+200, z_50_0=rsp+240,
    ;        z_100_0=rsp+280, tmp=rsp+320

    ; z2 = z^2
    lea rdi, [rsp]
    mov rsi, [rbp-16]
    call fe_square

    ; t = z^4
    lea rdi, [rsp+320]
    lea rsi, [rsp]
    call fe_square
    ; t = z^8
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    call fe_square

    ; z9 = z * z^8
    lea rdi, [rsp+40]
    mov rsi, [rbp-16]
    lea rdx, [rsp+320]
    call fe_mul

    ; z11 = z2 * z9
    lea rdi, [rsp+80]
    lea rsi, [rsp]
    lea rdx, [rsp+40]
    call fe_mul

    ; t = z11^2 = z^22
    lea rdi, [rsp+320]
    lea rsi, [rsp+80]
    call fe_square

    ; z_5_0 = t * z9 = z^31 = z^(2^5-1)
    lea rdi, [rsp+120]
    lea rsi, [rsp+320]
    lea rdx, [rsp+40]
    call fe_mul

    ; z^(2^10-2^5): square z_5_0 5 times
    lea rdi, [rsp+160]
    lea rsi, [rsp+120]
    call fe_square
    %rep 4
        lea rdi, [rsp+160]
        lea rsi, [rsp+160]
        call fe_square
    %endrep
    ; z_10_0 = * z_5_0
    lea rdi, [rsp+160]
    lea rsi, [rsp+160]
    lea rdx, [rsp+120]
    call fe_mul

    ; square 10 times
    lea rdi, [rsp+200]
    lea rsi, [rsp+160]
    call fe_square
    %rep 9
        lea rdi, [rsp+200]
        lea rsi, [rsp+200]
        call fe_square
    %endrep
    ; z_20_0
    lea rdi, [rsp+200]
    lea rsi, [rsp+200]
    lea rdx, [rsp+160]
    call fe_mul

    ; square 20 times
    lea rdi, [rsp+320]
    lea rsi, [rsp+200]
    call fe_square
    %rep 19
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    ; z^(2^40-1)
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+200]
    call fe_mul

    ; square 10 times
    %rep 10
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    ; z_50_0
    lea rdi, [rsp+240]
    lea rsi, [rsp+320]
    lea rdx, [rsp+160]
    call fe_mul

    ; square 50 times
    lea rdi, [rsp+280]
    lea rsi, [rsp+240]
    call fe_square
    %rep 49
        lea rdi, [rsp+280]
        lea rsi, [rsp+280]
        call fe_square
    %endrep
    ; z_100_0
    lea rdi, [rsp+280]
    lea rsi, [rsp+280]
    lea rdx, [rsp+240]
    call fe_mul

    ; square 100 times
    lea rdi, [rsp+320]
    lea rsi, [rsp+280]
    call fe_square
    %rep 99
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    ; z^(2^200-1)
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+280]
    call fe_mul

    ; square 50 times
    %rep 50
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    ; z^(2^250-1)
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+240]
    call fe_mul

    ; square 5 times -> z^(2^255-32)
    %rep 5
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    ; * z11 -> z^(2^255-21) = z^(p-2)
    mov rdi, [rbp-8]
    lea rsi, [rsp+320]
    lea rdx, [rsp+80]
    call fe_mul

    mov rsp, rbp
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; fe_cswap(rdi=a, rsi=b, edx=swap) — constant-time
; ============================================================================
fe_cswap:
    neg rdx
    mov rcx, rdx
    %assign i 0
    %rep 5
        mov rax, [rdi + i*8]
        mov rdx, [rsi + i*8]
        mov r8, rax
        xor r8, rdx
        and r8, rcx
        xor rax, r8
        xor rdx, r8
        mov [rdi + i*8], rax
        mov [rsi + i*8], rdx
        %assign i i+1
    %endrep
    ret

; ============================================================================
; fe_copy(rdi=dst, rsi=src)
; ============================================================================
fe_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi+8]
    mov [rdi+8], rax
    mov rax, [rsi+16]
    mov [rdi+16], rax
    mov rax, [rsi+24]
    mov [rdi+24], rax
    mov rax, [rsi+32]
    mov [rdi+32], rax
    ret

; ============================================================================
; fe_set(rdi=fe, rsi=value)
; ============================================================================
fe_set:
    mov [rdi], rsi
    xor eax, eax
    mov [rdi+8], rax
    mov [rdi+16], rax
    mov [rdi+24], rax
    mov [rdi+32], rax
    ret

; ============================================================================
; fe_mul121666(rdi=out, rsi=a) — a * 121665 (a24 = (A-2)/4 = (486662-2)/4)
; ============================================================================
fe_mul121666:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi
    mov r14, LIMB_MASK
    mov r12, 121665

    sub rsp, 40

    mov rax, [rsi]
    mul r12
    mov rcx, rdx            ; hi
    mov rdx, rax
    and rdx, r14            ; limb0
    mov [rsp], rdx
    shrd rax, rcx, 51       ; carry
    mov rcx, rax

    mov rax, [rsi+8]
    mul r12
    add rax, rcx
    adc rdx, 0
    mov rcx, rdx
    mov rdx, rax
    and rdx, r14
    mov [rsp+8], rdx
    shrd rax, rcx, 51
    mov rcx, rax

    mov rax, [rsi+16]
    mul r12
    add rax, rcx
    adc rdx, 0
    mov rcx, rdx
    mov rdx, rax
    and rdx, r14
    mov [rsp+16], rdx
    shrd rax, rcx, 51
    mov rcx, rax

    mov rax, [rsi+24]
    mul r12
    add rax, rcx
    adc rdx, 0
    mov rcx, rdx
    mov rdx, rax
    and rdx, r14
    mov [rsp+24], rdx
    shrd rax, rcx, 51
    mov rcx, rax

    mov rax, [rsi+32]
    mul r12
    add rax, rcx
    adc rdx, 0
    mov rcx, rdx
    mov r8, rax
    and r8, r14              ; limb4
    shrd rax, rcx, 51
    imul rax, 19
    add rax, [rsp]           ; limb0 += carry*19
    mov rcx, rax
    shr rcx, 51
    and rax, r14

    mov [rbx], rax
    mov rax, [rsp+8]
    add rax, rcx
    mov [rbx+8], rax
    mov rax, [rsp+16]
    mov [rbx+16], rax
    mov rax, [rsp+24]
    mov [rbx+24], rax
    mov [rbx+32], r8

    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; x25519(rdi=out32, rsi=scalar32, rdx=point32)
; ============================================================================
x25519:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 640
    and rsp, -16

    ; Stack layout (all relative to rsp):
    ;   0:    scalar (32 bytes)
    ;   32:   u (40 bytes)
    ;   72:   x_2 (40)
    ;   112:  z_2 (40)
    ;   152:  x_3 (40)
    ;   192:  z_3 (40)
    ;   232:  A (40)
    ;   272:  AA (40)
    ;   312:  B (40)
    ;   352:  BB (40)
    ;   392:  E (40)
    ;   432:  C (40)
    ;   472:  D (40)
    ;   512:  DA (40)
    ;   552:  CB (40)
    ;   592:  tmp (40)
    ; [rbp-8]: out pointer

    mov [rbp-8], rdi
    mov r12, rsi
    mov r13, rdx

    ; Copy & clamp scalar
    mov rax, [r12]
    mov [rsp], rax
    mov rax, [r12+8]
    mov [rsp+8], rax
    mov rax, [r12+16]
    mov [rsp+16], rax
    mov rax, [r12+24]
    mov [rsp+24], rax
    and byte [rsp], 0xF8
    and byte [rsp+31], 0x7F
    or  byte [rsp+31], 0x40

    ; u = frombytes(point)
    lea rdi, [rsp+32]
    mov rsi, r13
    call fe_frombytes

    ; x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1
    lea rdi, [rsp+72]
    mov rsi, 1
    call fe_set
    lea rdi, [rsp+112]
    xor esi, esi
    call fe_set
    lea rdi, [rsp+152]
    lea rsi, [rsp+32]
    call fe_copy
    lea rdi, [rsp+192]
    mov rsi, 1
    call fe_set

    mov r14d, 254
    xor r15d, r15d

.ladder:
    mov ecx, r14d
    shr ecx, 3
    movzx eax, byte [rsp + rcx]
    mov ecx, r14d
    and ecx, 7
    shr eax, cl
    and eax, 1
    mov r13d, eax
    xor r13d, r15d
    mov r15d, eax

    ; cswap x_2, x_3
    lea rdi, [rsp+72]
    lea rsi, [rsp+152]
    movzx edx, r13b
    call fe_cswap
    ; cswap z_2, z_3
    lea rdi, [rsp+112]
    lea rsi, [rsp+192]
    movzx edx, r13b
    call fe_cswap

    ; A = x_2 + z_2
    lea rdi, [rsp+232]
    lea rsi, [rsp+72]
    lea rdx, [rsp+112]
    call fe_add
    ; AA = A^2
    lea rdi, [rsp+272]
    lea rsi, [rsp+232]
    call fe_square
    ; B = x_2 - z_2
    lea rdi, [rsp+312]
    lea rsi, [rsp+72]
    lea rdx, [rsp+112]
    call fe_sub
    ; BB = B^2
    lea rdi, [rsp+352]
    lea rsi, [rsp+312]
    call fe_square
    ; E = AA - BB
    lea rdi, [rsp+392]
    lea rsi, [rsp+272]
    lea rdx, [rsp+352]
    call fe_sub
    ; C = x_3 + z_3
    lea rdi, [rsp+432]
    lea rsi, [rsp+152]
    lea rdx, [rsp+192]
    call fe_add
    ; D = x_3 - z_3
    lea rdi, [rsp+472]
    lea rsi, [rsp+152]
    lea rdx, [rsp+192]
    call fe_sub
    ; DA = D * A
    lea rdi, [rsp+512]
    lea rsi, [rsp+472]
    lea rdx, [rsp+232]
    call fe_mul
    ; CB = C * B
    lea rdi, [rsp+552]
    lea rsi, [rsp+432]
    lea rdx, [rsp+312]
    call fe_mul
    ; x_3 = (DA+CB)^2
    lea rdi, [rsp+592]
    lea rsi, [rsp+512]
    lea rdx, [rsp+552]
    call fe_add
    lea rdi, [rsp+152]
    lea rsi, [rsp+592]
    call fe_square
    ; z_3 = u * (DA-CB)^2
    lea rdi, [rsp+592]
    lea rsi, [rsp+512]
    lea rdx, [rsp+552]
    call fe_sub
    lea rdi, [rsp+592]
    lea rsi, [rsp+592]
    call fe_square
    lea rdi, [rsp+192]
    lea rsi, [rsp+32]
    lea rdx, [rsp+592]
    call fe_mul
    ; x_2 = AA * BB
    lea rdi, [rsp+72]
    lea rsi, [rsp+272]
    lea rdx, [rsp+352]
    call fe_mul
    ; z_2 = E * (AA + a24*E)
    lea rdi, [rsp+592]
    lea rsi, [rsp+392]
    call fe_mul121666
    lea rdi, [rsp+592]
    lea rsi, [rsp+272]
    lea rdx, [rsp+592]
    call fe_add
    lea rdi, [rsp+112]
    lea rsi, [rsp+392]
    lea rdx, [rsp+592]
    call fe_mul

    dec r14d
    jns .ladder

    ; Final cswap
    lea rdi, [rsp+72]
    lea rsi, [rsp+152]
    movzx edx, r15b
    call fe_cswap
    lea rdi, [rsp+112]
    lea rsi, [rsp+192]
    movzx edx, r15b
    call fe_cswap

    ; result = x_2 * inv(z_2)
    lea rdi, [rsp+592]
    lea rsi, [rsp+112]
    call fe_invert
    lea rdi, [rsp+232]
    lea rsi, [rsp+72]
    lea rdx, [rsp+592]
    call fe_mul
    mov rdi, [rbp-8]
    lea rsi, [rsp+232]
    call fe_tobytes

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; x25519_base(rdi=out32, rsi=scalar32)
; ============================================================================
x25519_base:
    lea rdx, [rel basepoint]
    jmp x25519
