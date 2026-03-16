; Ed25519 digital signatures per RFC 8032 Section 5.1
; Pure x86-64, uses field arithmetic from curve25519.asm and SHA-512
;
; Calling convention:
;   ed25519_pubkey(rdi=pubkey32_out, rsi=secret32)
;   ed25519_sign(rdi=sig64_out, rsi=msg, rdx=msg_len, rcx=keypair64)
;   ed25519_verify(rdi=sig64, rsi=msg, rdx=msg_len, rcx=pubkey32) -> eax: 0=ok, -1=bad

%include "ssh.inc"

; External field arithmetic from curve25519.asm
extern fe_add, fe_sub, fe_mul, fe_square, fe_invert
extern fe_tobytes, fe_frombytes

; External SHA-512
extern sha512

section .rodata
align 16

; Ed25519 basepoint B in extended coordinates (X, Y, Z, T)
; Each coordinate is 5 limbs (40 bytes)
; B_y = 4/5 mod p = 46316835694926478169428394003475163141307993866256225615783033890098355573289
; Stored as compressed point bytes, we'll precompute extended form

; Basepoint compressed encoding (y-coordinate with sign bit)
basepoint_bytes:
    db 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    db 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    db 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    db 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66

; d = -121665/121666 mod p
; d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
; In 5-limb (51-bit radix) form:
ed_d:
    dq 0x34DCA135978A3     ; limb 0
    dq 0x1A8283B156EBD     ; limb 1
    dq 0x5E7A26001C029     ; limb 2
    dq 0x739C663A03CBB     ; limb 3
    dq 0x52036CEE2B6FF     ; limb 4

; 2*d constant for point addition
ed_2d:
    dq 0x69B9426B2F159     ; limb 0
    dq 0x35050762ADD7A     ; limb 1
    dq 0x3CF44C0038052     ; limb 2
    dq 0x6738CC7407977     ; limb 3
    dq 0x2406D9DC56DFF     ; limb 4

; sqrt(-1) mod p = 2^((p-1)/4) mod p
; = 19681161376707505956807079304988542015446066515923890162744021073123829784752
sqrtm1:
    dq 0x61B274A0EA0B0     ; limb 0
    dq 0x0D5A5FC8F189D     ; limb 1
    dq 0x7EF5E9CBD0C60     ; limb 2
    dq 0x78595A6804C9E     ; limb 3
    dq 0x2B8324804FC1D     ; limb 4

; Group order L = 2^252 + 27742317777372353535851937790883648493
; In little-endian qwords:
order_L:
    dq 0x5812631a5cf5d3ed
    dq 0x14def9dea2f79cd6
    dq 0x0000000000000000
    dq 0x1000000000000000

; fe_one: field element = 1
fe_one:
    dq 1, 0, 0, 0, 0

; fe_zero: field element = 0
fe_zero:
    dq 0, 0, 0, 0, 0

section .text

global ed25519_pubkey, ed25519_sign, ed25519_verify
extern sc_reduce, sc_muladd

; ============================================================================
; HELPER: read_exact(rdi=buf, rsi=count) - not needed here, but fe helpers
; ============================================================================

; ============================================================================
; fe_neg(rdi=out, rsi=a) — out = -a mod p = p - a (using 2p bias)
; Actually: out = 0 - a, with bias to keep positive
; ============================================================================
fe_neg:
    ; out = 0 - a + 2p
    push rbx
    mov rbx, rdi
    mov r8, 0xFFFFFFFFFFFDA    ; 2*p limb0
    mov r9, 0xFFFFFFFFFFFFE    ; 2*p limb1-4
    mov rax, r8
    sub rax, [rsi]
    mov [rbx], rax
    mov rax, r9
    sub rax, [rsi+8]
    mov [rbx+8], rax
    mov rax, r9
    sub rax, [rsi+16]
    mov [rbx+16], rax
    mov rax, r9
    sub rax, [rsi+24]
    mov [rbx+24], rax
    mov rax, r9
    sub rax, [rsi+32]
    mov [rbx+32], rax
    pop rbx
    ret

; ============================================================================
; fe_copy(rdi=dst, rsi=src) — copy 5-limb field element
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
; fe_iszero(rsi=fe) -> eax: 1 if zero, 0 if not
; Converts to bytes and checks all zero
; ============================================================================
fe_iszero:
    push rbx
    sub rsp, 48
    mov [rsp+40], rsi
    lea rdi, [rsp]
    ; rsi already set
    call fe_tobytes
    xor eax, eax
    xor ecx, ecx
    %assign i 0
    %rep 4
        or rax, [rsp + i*8]
        %assign i i+1
    %endrep
    test rax, rax
    setz al
    movzx eax, al
    add rsp, 48
    pop rbx
    ret

; ============================================================================
; ge_p3_0(rdi=point) — set point to identity (0, 1, 1, 0) in extended coords
; X=0, Y=1, Z=1, T=0
; ============================================================================
ge_p3_0:
    push rbx
    mov rbx, rdi
    ; X = 0
    xor esi, esi
    mov [rbx], rsi
    mov [rbx+8], rsi
    mov [rbx+16], rsi
    mov [rbx+24], rsi
    mov [rbx+32], rsi
    ; Y = 1
    mov qword [rbx+40], 1
    mov qword [rbx+48], 0
    mov qword [rbx+56], 0
    mov qword [rbx+64], 0
    mov qword [rbx+72], 0
    ; Z = 1
    mov qword [rbx+80], 1
    mov qword [rbx+88], 0
    mov qword [rbx+96], 0
    mov qword [rbx+104], 0
    mov qword [rbx+112], 0
    ; T = 0
    xor eax, eax
    mov [rbx+120], rax
    mov [rbx+128], rax
    mov [rbx+136], rax
    mov [rbx+144], rax
    mov [rbx+152], rax
    pop rbx
    ret

; ============================================================================
; ge_p3_copy(rdi=dst, rsi=src) — copy extended point (160 bytes)
; ============================================================================
ge_p3_copy:
    push rcx
    mov rcx, 20          ; 20 qwords = 160 bytes
.copy_loop:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .copy_loop
    pop rcx
    ret

; ============================================================================
; ge_add(rdi=result, rsi=p, rdx=q) — extended point addition
; Uses the unified addition formula for twisted Edwards curves with a=-1
;
; A = (Y1 - X1) * (Y2 - X2)
; B = (Y1 + X1) * (Y2 + X2)
; C = T1 * 2*d * T2
; D = Z1 * 2 * Z2
; E = B - A
; F = D - C
; G = D + C
; H = B + A
; X3 = E * F
; Y3 = G * H
; T3 = E * H
; Z3 = F * G
; ============================================================================
ge_add:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 480        ; 12 temps * 40 bytes
    and rsp, -16

    mov [rbp-8], rdi    ; result
    mov [rbp-16], rsi   ; p
    mov [rbp-24], rdx   ; q

    ; Temps: A=rsp, B=rsp+40, C=rsp+80, D=rsp+120,
    ;        E=rsp+160, F=rsp+200, G=rsp+240, H=rsp+280
    ;        t1=rsp+320, t2=rsp+360, t3=rsp+400

    ; t1 = Y1 - X1
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]
    lea rsi, [rsi+40]   ; Y1
    mov rdx, [rbp-16]   ; X1
    call fe_sub

    ; t2 = Y2 - X2
    lea rdi, [rsp+360]
    mov rsi, [rbp-24]
    lea rsi, [rsi+40]   ; Y2
    mov rdx, [rbp-24]   ; X2
    call fe_sub

    ; A = t1 * t2
    lea rdi, [rsp]
    lea rsi, [rsp+320]
    lea rdx, [rsp+360]
    call fe_mul

    ; t1 = Y1 + X1
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]
    lea rsi, [rsi+40]   ; Y1
    mov rdx, [rbp-16]   ; X1
    call fe_add

    ; t2 = Y2 + X2
    lea rdi, [rsp+360]
    mov rsi, [rbp-24]
    lea rsi, [rsi+40]   ; Y2
    mov rdx, [rbp-24]   ; X2
    call fe_add

    ; B = t1 * t2
    lea rdi, [rsp+40]
    lea rsi, [rsp+320]
    lea rdx, [rsp+360]
    call fe_mul

    ; t1 = T1 * T2
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]
    add rsi, 120        ; T1
    mov rdx, [rbp-24]
    add rdx, 120        ; T2
    call fe_mul

    ; C = t1 * 2d
    lea rdi, [rsp+80]
    lea rsi, [rsp+320]
    lea rdx, [rel ed_2d]
    call fe_mul

    ; t1 = Z1 * Z2
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]
    add rsi, 80         ; Z1
    mov rdx, [rbp-24]
    add rdx, 80         ; Z2
    call fe_mul

    ; D = 2 * t1 (= t1 + t1)
    lea rdi, [rsp+120]
    lea rsi, [rsp+320]
    lea rdx, [rsp+320]
    call fe_add

    ; E = B - A
    lea rdi, [rsp+160]
    lea rsi, [rsp+40]
    lea rdx, [rsp]
    call fe_sub

    ; F = D - C
    lea rdi, [rsp+200]
    lea rsi, [rsp+120]
    lea rdx, [rsp+80]
    call fe_sub

    ; G = D + C
    lea rdi, [rsp+240]
    lea rsi, [rsp+120]
    lea rdx, [rsp+80]
    call fe_add

    ; H = B + A
    lea rdi, [rsp+280]
    lea rsi, [rsp+40]
    lea rdx, [rsp]
    call fe_add

    ; X3 = E * F
    mov rdi, [rbp-8]
    lea rsi, [rsp+160]
    lea rdx, [rsp+200]
    call fe_mul

    ; Y3 = G * H
    mov rdi, [rbp-8]
    add rdi, 40
    lea rsi, [rsp+240]
    lea rdx, [rsp+280]
    call fe_mul

    ; T3 = E * H
    mov rdi, [rbp-8]
    add rdi, 120
    lea rsi, [rsp+160]
    lea rdx, [rsp+280]
    call fe_mul

    ; Z3 = F * G
    mov rdi, [rbp-8]
    add rdi, 80
    lea rsi, [rsp+200]
    lea rdx, [rsp+240]
    call fe_mul

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ge_double(rdi=result, rsi=p) — point doubling (dedicated formula, faster)
;
; A = X1^2
; B = Y1^2
; C = 2 * Z1^2
; D = -A    (a=-1 for Ed25519)
; E = (X1 + Y1)^2 - A - B
; F = D + B
; G = F - C
; H = D - B
; X3 = E * G
; Y3 = F * H
; T3 = E * H
; Z3 = F * G
; ============================================================================
ge_double:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 400
    and rsp, -16

    mov [rbp-8], rdi    ; result
    mov [rbp-16], rsi   ; p

    ; Temps: A=rsp, B=rsp+40, C=rsp+80, D=rsp+120,
    ;        E=rsp+160, F=rsp+200, G=rsp+240, H=rsp+280, t=rsp+320

    ; A = X1^2
    lea rdi, [rsp]
    mov rsi, [rbp-16]   ; X1
    call fe_square

    ; B = Y1^2
    lea rdi, [rsp+40]
    mov rsi, [rbp-16]
    add rsi, 40         ; Y1
    call fe_square

    ; t = Z1^2
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]
    add rsi, 80         ; Z1
    call fe_square

    ; C = 2*t
    lea rdi, [rsp+80]
    lea rsi, [rsp+320]
    lea rdx, [rsp+320]
    call fe_add

    ; D = -A (a = -1)
    lea rdi, [rsp+120]
    lea rsi, [rsp]
    call fe_neg

    ; t = X1 + Y1
    lea rdi, [rsp+320]
    mov rsi, [rbp-16]   ; X1
    mov rdx, [rbp-16]
    add rdx, 40         ; Y1
    call fe_add

    ; t = t^2
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    call fe_square

    ; E = t - A - B
    lea rdi, [rsp+160]
    lea rsi, [rsp+320]
    lea rdx, [rsp]
    call fe_sub
    lea rdi, [rsp+160]
    lea rsi, [rsp+160]
    lea rdx, [rsp+40]
    call fe_sub

    ; F = D + B
    lea rdi, [rsp+200]
    lea rsi, [rsp+120]
    lea rdx, [rsp+40]
    call fe_add

    ; G = F - C
    lea rdi, [rsp+240]
    lea rsi, [rsp+200]
    lea rdx, [rsp+80]
    call fe_sub

    ; H = D - B
    lea rdi, [rsp+280]
    lea rsi, [rsp+120]
    lea rdx, [rsp+40]
    call fe_sub

    ; X3 = E * G
    mov rdi, [rbp-8]
    lea rsi, [rsp+160]
    lea rdx, [rsp+240]
    call fe_mul

    ; Y3 = F * H
    mov rdi, [rbp-8]
    add rdi, 40
    lea rsi, [rsp+200]
    lea rdx, [rsp+280]
    call fe_mul

    ; T3 = E * H
    mov rdi, [rbp-8]
    add rdi, 120
    lea rsi, [rsp+160]
    lea rdx, [rsp+280]
    call fe_mul

    ; Z3 = F * G
    mov rdi, [rbp-8]
    add rdi, 80
    lea rsi, [rsp+200]
    lea rdx, [rsp+240]
    call fe_mul

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ge_scalarmult_base(rdi=result, rsi=scalar32)
; Compute scalar * B using double-and-add (MSB first)
; scalar is 32 bytes little-endian
; ============================================================================
ge_scalarmult_base:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 560
    and rsp, -16

    ; Stack: scalar=rsp, result_ptr=rbp-8, basepoint=rsp+32, tmp=rsp+192
    mov [rbp-8], rdi

    ; Copy scalar to stack
    mov rax, [rsi]
    mov [rsp], rax
    mov rax, [rsi+8]
    mov [rsp+8], rax
    mov rax, [rsi+16]
    mov [rsp+16], rax
    mov rax, [rsi+24]
    mov [rsp+24], rax

    ; Decompress basepoint into rsp+32
    lea rdi, [rsp+32]
    lea rsi, [rel basepoint_bytes]
    call ge_frombytes

    ; Initialize result to identity
    mov rdi, [rbp-8]
    call ge_p3_0

    ; Double-and-add from bit 254 down to 0
    ; (clamped scalars have bit 254 set; general scalars may use up to bit 255)
    mov r14d, 254

.scalarmult_loop:
    ; Double: result = 2*result
    lea rdi, [rsp+192]
    mov rsi, [rbp-8]
    call ge_double
    ; Copy tmp back to result
    mov rdi, [rbp-8]
    lea rsi, [rsp+192]
    call ge_p3_copy

    ; Get scalar bit r14
    mov ecx, r14d
    shr ecx, 3
    movzx eax, byte [rsp + rcx]
    mov ecx, r14d
    and ecx, 7
    shr eax, cl
    and eax, 1
    test eax, eax
    jz .scalarmult_skip

    ; Add basepoint: result = result + B
    lea rdi, [rsp+192]
    mov rsi, [rbp-8]
    lea rdx, [rsp+32]
    call ge_add
    ; Copy tmp back to result
    mov rdi, [rbp-8]
    lea rsi, [rsp+192]
    call ge_p3_copy

.scalarmult_skip:
    dec r14d
    jns .scalarmult_loop

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ge_scalarmult(rdi=result, rsi=scalar32, rdx=point)
; Compute scalar * point using double-and-add
; ============================================================================
ge_scalarmult:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 560
    and rsp, -16

    mov [rbp-8], rdi
    ; Copy point to rsp+32
    mov rdi, rdx
    mov [rbp-24], rdi   ; save point ptr temporarily

    ; Copy point (160 bytes) to stack at rsp+32
    lea rdi, [rsp+32]
    mov rsi, [rbp-24]
    call ge_p3_copy

    ; Copy scalar to rsp
    mov rsi, [rbp-16]   ; Oops, we didn't save scalar. Redo.
    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ; Fall through to a proper version below
    ret

; Actually, let me rewrite ge_scalarmult properly
ge_scalarmult_var:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 576
    and rsp, -16

    ; rdi=result, rsi=scalar32, rdx=point(extended)
    mov [rbp-8], rdi     ; result ptr
    mov [rbp-16], rsi    ; scalar ptr
    mov [rbp-24], rdx    ; point ptr

    ; Copy scalar (32 bytes) to rsp
    mov rsi, [rbp-16]
    mov rax, [rsi]
    mov [rsp], rax
    mov rax, [rsi+8]
    mov [rsp+8], rax
    mov rax, [rsi+16]
    mov [rsp+16], rax
    mov rax, [rsi+24]
    mov [rsp+24], rax

    ; Copy point (160 bytes) to rsp+32
    lea rdi, [rsp+32]
    mov rsi, [rbp-24]
    call ge_p3_copy

    ; Initialize result to identity
    mov rdi, [rbp-8]
    call ge_p3_0

    ; Double-and-add from bit 254 down to 0
    mov r14d, 254

.smv_loop:
    ; Double
    lea rdi, [rsp+192]
    mov rsi, [rbp-8]
    call ge_double
    mov rdi, [rbp-8]
    lea rsi, [rsp+192]
    call ge_p3_copy

    ; Get bit
    mov ecx, r14d
    shr ecx, 3
    movzx eax, byte [rsp + rcx]
    mov ecx, r14d
    and ecx, 7
    shr eax, cl
    and eax, 1
    test eax, eax
    jz .smv_skip

    ; Add point
    lea rdi, [rsp+192]
    mov rsi, [rbp-8]
    lea rdx, [rsp+32]
    call ge_add
    mov rdi, [rbp-8]
    lea rsi, [rsp+192]
    call ge_p3_copy

.smv_skip:
    dec r14d
    jns .smv_loop

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ge_tobytes(rdi=bytes32, rsi=point) — compress point to 32 bytes
; y_bytes with high bit of byte 31 = low bit of x
; x = X/Z, y = Y/Z
; ============================================================================
ge_tobytes:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 176
    and rsp, -16

    mov [rbp-8], rdi     ; output bytes
    mov [rbp-16], rsi    ; point

    ; Compute recip = 1/Z
    lea rdi, [rsp]       ; recip (40 bytes)
    mov rsi, [rbp-16]
    add rsi, 80          ; Z
    call fe_invert

    ; x = X * recip
    lea rdi, [rsp+40]
    mov rsi, [rbp-16]    ; X
    lea rdx, [rsp]       ; recip
    call fe_mul

    ; y = Y * recip
    lea rdi, [rsp+80]
    mov rsi, [rbp-16]
    add rsi, 40          ; Y
    lea rdx, [rsp]       ; recip
    call fe_mul

    ; Convert y to bytes
    mov rdi, [rbp-8]
    lea rsi, [rsp+80]
    call fe_tobytes

    ; Convert x to bytes (to get sign bit)
    lea rdi, [rsp+120]
    lea rsi, [rsp+40]
    call fe_tobytes

    ; Set high bit of byte 31 to low bit of x
    movzx eax, byte [rsp+120]   ; first byte of x_bytes = low byte
    and al, 1                    ; sign bit = x mod 2
    shl al, 7
    mov rdi, [rbp-8]
    or byte [rdi+31], al

    mov rsp, rbp
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ge_frombytes(rdi=point, rsi=bytes32) — decompress point from 32 bytes
; Parse y, recover x from curve equation:
;   x^2 = (y^2 - 1) / (d*y^2 + 1)
; Square root via u*v^3 * (u*v^7)^((p-5)/8), then check/fix sign
; ============================================================================
ge_frombytes:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp
    sub rsp, 480
    and rsp, -16

    mov [rbp-8], rdi     ; point output
    mov [rbp-16], rsi    ; bytes input

    ; Extract sign bit from byte 31
    mov rsi, [rbp-16]
    movzx eax, byte [rsi+31]
    shr eax, 7
    mov [rbp-24], rax    ; sign bit

    ; Copy bytes, clear sign bit
    lea rdi, [rsp+400]   ; 32-byte temp
    mov rsi, [rbp-16]
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi+8]
    mov [rdi+8], rax
    mov rax, [rsi+16]
    mov [rdi+16], rax
    mov rax, [rsi+24]
    mov rcx, 0x7FFFFFFFFFFFFFFF
    and rax, rcx                  ; clear sign bit
    mov [rdi+24], rax

    ; Y = fe_frombytes(cleaned bytes)
    mov rdi, [rbp-8]
    add rdi, 40          ; Y coordinate
    lea rsi, [rsp+400]
    call fe_frombytes

    ; Z = 1
    mov rdi, [rbp-8]
    add rdi, 80
    mov qword [rdi], 1
    mov qword [rdi+8], 0
    mov qword [rdi+16], 0
    mov qword [rdi+24], 0
    mov qword [rdi+32], 0

    ; Temps: u=rsp, v=rsp+40, v3=rsp+80, v7=rsp+120, x=rsp+160
    ;        t=rsp+200, t2=rsp+240

    ; u = y^2 - 1
    lea rdi, [rsp]
    mov rsi, [rbp-8]
    add rsi, 40          ; Y
    call fe_square
    ; u = u - 1
    lea rdi, [rsp+200]   ; temp with value 1
    mov qword [rdi], 1
    mov qword [rdi+8], 0
    mov qword [rdi+16], 0
    mov qword [rdi+24], 0
    mov qword [rdi+32], 0
    lea rdi, [rsp]
    lea rsi, [rsp]
    lea rdx, [rsp+200]
    call fe_sub

    ; v = d*y^2 + 1
    lea rdi, [rsp+40]
    mov rsi, [rbp-8]
    add rsi, 40          ; Y
    call fe_square       ; rsp+40 = y^2 temporarily
    lea rdi, [rsp+40]
    lea rsi, [rsp+40]
    lea rdx, [rel ed_d]
    call fe_mul          ; rsp+40 = d*y^2
    ; + 1
    lea rdi, [rsp+200]
    mov qword [rdi], 1
    mov qword [rdi+8], 0
    mov qword [rdi+16], 0
    mov qword [rdi+24], 0
    mov qword [rdi+32], 0
    lea rdi, [rsp+40]
    lea rsi, [rsp+40]
    lea rdx, [rsp+200]
    call fe_add

    ; Compute x = sqrt(u/v) using the formula:
    ; x = u * v^3 * (u * v^7)^((p-5)/8)

    ; v^2
    lea rdi, [rsp+200]
    lea rsi, [rsp+40]
    call fe_square

    ; v^3 = v^2 * v
    lea rdi, [rsp+80]
    lea rsi, [rsp+200]
    lea rdx, [rsp+40]
    call fe_mul

    ; v^4 = v^2 * v^2
    lea rdi, [rsp+200]
    lea rsi, [rsp+200]
    call fe_square

    ; v^7 = v^4 * v^3
    lea rdi, [rsp+120]
    lea rsi, [rsp+200]
    lea rdx, [rsp+80]
    call fe_mul

    ; uv7 = u * v^7
    lea rdi, [rsp+200]
    lea rsi, [rsp]       ; u
    lea rdx, [rsp+120]   ; v^7
    call fe_mul

    ; uv3 = u * v^3
    lea rdi, [rsp+240]
    lea rsi, [rsp]       ; u
    lea rdx, [rsp+80]   ; v^3
    call fe_mul

    ; Now compute (uv7)^((p-5)/8)
    ; (p-5)/8 = (2^255 - 24)/8 = 2^252 - 3
    ; This is p^((p-5)/8) which we compute via the addition chain for 2^252-3
    ; = the same as fe_invert chain but ending differently
    ; Actually, we use fe_pow25523 which computes z^(2^252-3)

    ; Compute uv7^(2^252-3)
    lea rdi, [rsp+280]    ; result of pow
    lea rsi, [rsp+200]    ; uv7
    call fe_pow25523

    ; x = uv3 * uv7^((p-5)/8)
    lea rdi, [rsp+160]    ; x candidate
    lea rsi, [rsp+240]    ; uv3
    lea rdx, [rsp+280]    ; pow result
    call fe_mul

    ; Check: v * x^2 == u ?
    lea rdi, [rsp+200]
    lea rsi, [rsp+160]
    call fe_square         ; x^2
    lea rdi, [rsp+200]
    lea rsi, [rsp+40]     ; v
    lea rdx, [rsp+200]    ; x^2
    call fe_mul            ; v*x^2

    ; Compare v*x^2 with u
    ; t = v*x^2 - u
    lea rdi, [rsp+280]
    lea rsi, [rsp+200]
    lea rdx, [rsp]        ; u
    call fe_sub

    lea rsi, [rsp+280]
    call fe_iszero
    test eax, eax
    jnz .frombytes_sign_check

    ; v*x^2 != u, try v*x^2 == -u
    ; If so, x = x * sqrt(-1)
    lea rdi, [rsp+160]
    lea rsi, [rsp+160]
    lea rdx, [rel sqrtm1]
    call fe_mul

.frombytes_sign_check:
    ; Convert x to bytes to check sign
    lea rdi, [rsp+320]    ; 32 bytes temp
    lea rsi, [rsp+160]
    call fe_tobytes

    ; Check if sign matches
    movzx eax, byte [rsp+320]  ; low byte of x
    and eax, 1
    cmp rax, [rbp-24]          ; desired sign
    je .frombytes_store_x

    ; Negate x
    lea rdi, [rsp+160]
    lea rsi, [rsp+160]
    call fe_neg

.frombytes_store_x:
    ; Store X
    mov rdi, [rbp-8]
    lea rsi, [rsp+160]
    call fe_copy

    ; T = X * Y
    mov rdi, [rbp-8]
    add rdi, 120         ; T
    mov rsi, [rbp-8]     ; X
    mov rdx, [rbp-8]
    add rdx, 40          ; Y
    call fe_mul

    mov rsp, rbp
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; fe_pow25523(rdi=out, rsi=z) — compute z^(2^252-3)
; Same addition chain as fe_invert but ends with z^(2^252-3) instead of z^(p-2)
; ============================================================================
fe_pow25523:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 400
    and rsp, -16

    mov [rbp-8], rdi
    mov [rbp-16], rsi

    ; z2 = z^2
    lea rdi, [rsp]
    mov rsi, [rbp-16]
    call fe_square

    ; t = z^8
    lea rdi, [rsp+320]
    lea rsi, [rsp]
    call fe_square
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

    ; t = z11^2
    lea rdi, [rsp+320]
    lea rsi, [rsp+80]
    call fe_square

    ; z_5_0 = t * z9
    lea rdi, [rsp+120]
    lea rsi, [rsp+320]
    lea rdx, [rsp+40]
    call fe_mul

    ; Square 5 times -> z^(2^10-2^5)
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

    ; Square 10 times
    lea rdi, [rsp+200]
    lea rsi, [rsp+160]
    call fe_square
    %rep 9
        lea rdi, [rsp+200]
        lea rsi, [rsp+200]
        call fe_square
    %endrep
    lea rdi, [rsp+200]
    lea rsi, [rsp+200]
    lea rdx, [rsp+160]
    call fe_mul

    ; Square 20 times
    lea rdi, [rsp+320]
    lea rsi, [rsp+200]
    call fe_square
    %rep 19
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+200]
    call fe_mul

    ; Square 10 times
    %rep 10
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    lea rdi, [rsp+240]
    lea rsi, [rsp+320]
    lea rdx, [rsp+160]
    call fe_mul

    ; Square 50 times
    lea rdi, [rsp+280]
    lea rsi, [rsp+240]
    call fe_square
    %rep 49
        lea rdi, [rsp+280]
        lea rsi, [rsp+280]
        call fe_square
    %endrep
    lea rdi, [rsp+280]
    lea rsi, [rsp+280]
    lea rdx, [rsp+240]
    call fe_mul

    ; Square 100 times
    lea rdi, [rsp+320]
    lea rsi, [rsp+280]
    call fe_square
    %rep 99
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+280]
    call fe_mul

    ; Square 50 times
    %rep 50
        lea rdi, [rsp+320]
        lea rsi, [rsp+320]
        call fe_square
    %endrep
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    lea rdx, [rsp+240]
    call fe_mul

    ; Square 2 times -> z^(2^252 - 4)
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    call fe_square
    lea rdi, [rsp+320]
    lea rsi, [rsp+320]
    call fe_square

    ; * z -> z^(2^252 - 3)
    mov rdi, [rbp-8]
    lea rsi, [rsp+320]
    mov rdx, [rbp-16]
    call fe_mul

    mov rsp, rbp
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; ed25519_pubkey(rdi=pubkey32_out, rsi=secret32)
; 1. h = SHA-512(secret)
; 2. a = clamp(h[0..31])
; 3. A = a * B
; 4. pubkey = compress(A)
; ============================================================================
ed25519_pubkey:
    push rbx
    push r12
    push r13
    push rbp
    mov rbp, rsp
    sub rsp, 304
    and rsp, -16

    mov [rbp-8], rdi     ; pubkey output
    mov [rbp-16], rsi    ; secret input

    ; h = SHA-512(secret) -> 64 bytes at rsp
    mov rdi, [rbp-16]    ; msg = secret
    mov rsi, 32          ; len = 32
    lea rdx, [rsp]       ; output
    call sha512

    ; Clamp h[0..31]
    and byte [rsp], 0xF8       ; clear low 3 bits
    and byte [rsp+31], 0x7F    ; clear bit 255
    or  byte [rsp+31], 0x40    ; set bit 254

    ; A = scalar * B
    lea rdi, [rsp+64]    ; point result (160 bytes)
    lea rsi, [rsp]       ; clamped scalar
    call ge_scalarmult_base

    ; Compress A to bytes
    mov rdi, [rbp-8]
    lea rsi, [rsp+64]
    call ge_tobytes

    mov rsp, rbp
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ed25519_sign(rdi=sig64_out, rsi=msg, rdx=msg_len, rcx=keypair64)
;
; keypair = secret32 || pubkey32
;
; 1. h = SHA-512(secret)
; 2. a = clamp(h[0..31])
; 3. r = SHA-512(h[32..63] || message) mod L
; 4. R = r * B
; 5. S = (r + SHA-512(R_bytes || pubkey || message) * a) mod L
; 6. sig = R_bytes || S
; ============================================================================
ed25519_sign:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    ; Need significant stack: hash outputs, points, scalars, message buffer
    ; Budget: ~4KB should be safe
    sub rsp, 4096
    and rsp, -16

    mov [rbp-8], rdi     ; sig output
    mov [rbp-16], rsi    ; msg
    mov [rbp-24], rdx    ; msg_len
    mov [rbp-32], rcx    ; keypair (secret || pubkey)

    ; Step 1: h = SHA-512(secret_key) -> rsp (64 bytes)
    mov rcx, [rbp-32]
    mov rdi, rcx         ; secret = first 32 bytes of keypair
    mov rsi, 32
    lea rdx, [rsp]       ; hash output
    call sha512

    ; Step 2: a = clamp(h[0..31]) -> store at rsp+64 (32 bytes)
    ; Copy h[0..31] to rsp+64
    mov rax, [rsp]
    mov [rsp+64], rax
    mov rax, [rsp+8]
    mov [rsp+64+8], rax
    mov rax, [rsp+16]
    mov [rsp+64+16], rax
    mov rax, [rsp+24]
    mov [rsp+64+24], rax
    ; Clamp
    and byte [rsp+64], 0xF8
    and byte [rsp+64+31], 0x7F
    or  byte [rsp+64+31], 0x40

    ; Step 3: r = SHA-512(h[32..63] || message) mod L
    ; Build buffer at rsp+96: h[32..63] (32 bytes) || message (msg_len bytes)
    ; Copy h[32..63]
    mov rax, [rsp+32]
    mov [rsp+96], rax
    mov rax, [rsp+40]
    mov [rsp+96+8], rax
    mov rax, [rsp+48]
    mov [rsp+96+16], rax
    mov rax, [rsp+56]
    mov [rsp+96+24], rax

    ; Copy message after prefix
    lea rdi, [rsp+128]
    mov rsi, [rbp-16]
    mov rcx, [rbp-24]
    test rcx, rcx
    jz .sign_hash_r
    rep movsb

.sign_hash_r:
    ; SHA-512(prefix || msg) -> rsp+2048 (64 bytes = "r_hash")
    lea rdi, [rsp+96]        ; buffer
    mov rsi, 32
    add rsi, [rbp-24]        ; total len = 32 + msg_len
    lea rdx, [rsp+2048]      ; output
    call sha512

    ; Reduce r_hash (64 bytes) mod L -> rsp+2048 (first 32 bytes)
    lea rdi, [rsp+2048]
    call sc_reduce
    ; r scalar is now at rsp+2048 (32 bytes)

    ; Step 4: R = r * B -> point at rsp+2112 (160 bytes)
    lea rdi, [rsp+2112]
    lea rsi, [rsp+2048]
    call ge_scalarmult_base

    ; Compress R to bytes -> rsp+2272 (32 bytes) = R_bytes
    lea rdi, [rsp+2272]
    lea rsi, [rsp+2112]
    call ge_tobytes

    ; Copy R_bytes to sig[0..31]
    mov rdi, [rbp-8]
    mov rax, [rsp+2272]
    mov [rdi], rax
    mov rax, [rsp+2272+8]
    mov [rdi+8], rax
    mov rax, [rsp+2272+16]
    mov [rdi+16], rax
    mov rax, [rsp+2272+24]
    mov [rdi+24], rax

    ; Step 5: k = SHA-512(R_bytes || pubkey || message) mod L
    ; Build buffer at rsp+2304: R_bytes(32) || pubkey(32) || message
    ; R_bytes
    mov rax, [rsp+2272]
    mov [rsp+2304], rax
    mov rax, [rsp+2272+8]
    mov [rsp+2304+8], rax
    mov rax, [rsp+2272+16]
    mov [rsp+2304+16], rax
    mov rax, [rsp+2272+24]
    mov [rsp+2304+24], rax
    ; pubkey (second 32 bytes of keypair)
    mov rcx, [rbp-32]
    add rcx, 32
    mov rax, [rcx]
    mov [rsp+2336], rax
    mov rax, [rcx+8]
    mov [rsp+2336+8], rax
    mov rax, [rcx+16]
    mov [rsp+2336+16], rax
    mov rax, [rcx+24]
    mov [rsp+2336+24], rax
    ; message
    lea rdi, [rsp+2368]
    mov rsi, [rbp-16]
    mov rcx, [rbp-24]
    test rcx, rcx
    jz .sign_hash_k
    rep movsb

.sign_hash_k:
    ; SHA-512(R || A || msg) -> rsp+2816 (64 bytes)
    lea rdi, [rsp+2304]
    mov rsi, 64
    add rsi, [rbp-24]        ; 32 + 32 + msg_len
    lea rdx, [rsp+2816]
    call sha512

    ; Reduce k mod L
    lea rdi, [rsp+2816]
    call sc_reduce
    ; k scalar at rsp+2816 (32 bytes)

    ; Step 6: S = (r + k * a) mod L = sc_muladd(out, k, a, r)
    ; out = sig+32, a = rsp+64, k = rsp+2816, r = rsp+2048
    mov rdi, [rbp-8]
    add rdi, 32               ; sig[32..63]
    lea rsi, [rsp+2816]       ; k (a_param)
    lea rdx, [rsp+64]         ; a (b_param)
    lea rcx, [rsp+2048]       ; r (c_param)
    call sc_muladd

    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ed25519_verify(rdi=sig64, rsi=msg, rdx=msg_len, rcx=pubkey32) -> eax: 0=ok, -1=bad
;
; 1. Decode R from sig[0..31], decode A from pubkey
; 2. k = SHA-512(R_bytes || pubkey || message) mod L
; 3. Check: S*B == R + k*A
; ============================================================================
ed25519_verify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp
    sub rsp, 4096
    and rsp, -16

    mov [rbp-8], rdi     ; sig
    mov [rbp-16], rsi    ; msg
    mov [rbp-24], rdx    ; msg_len
    mov [rbp-32], rcx    ; pubkey

    ; Decode A from pubkey -> rsp (160 bytes)
    lea rdi, [rsp]
    mov rsi, [rbp-32]
    call ge_frombytes

    ; Decode R from sig[0..31] -> rsp+160 (160 bytes)
    lea rdi, [rsp+160]
    mov rsi, [rbp-8]
    call ge_frombytes

    ; k = SHA-512(R_bytes || pubkey || message) mod L
    ; Build buffer at rsp+2048
    ; R_bytes = sig[0..31]
    mov rsi, [rbp-8]
    lea rdi, [rsp+2048]
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi+8]
    mov [rdi+8], rax
    mov rax, [rsi+16]
    mov [rdi+16], rax
    mov rax, [rsi+24]
    mov [rdi+24], rax
    ; pubkey
    mov rsi, [rbp-32]
    mov rax, [rsi]
    mov [rdi+32], rax
    mov rax, [rsi+8]
    mov [rdi+40], rax
    mov rax, [rsi+16]
    mov [rdi+48], rax
    mov rax, [rsi+24]
    mov [rdi+56], rax
    ; message
    lea rdi, [rsp+2048+64]
    mov rsi, [rbp-16]
    mov rcx, [rbp-24]
    test rcx, rcx
    jz .verify_hash_k
    rep movsb

.verify_hash_k:
    ; SHA-512(R || A || msg) -> rsp+2816
    lea rdi, [rsp+2048]
    mov rsi, 64
    add rsi, [rbp-24]
    lea rdx, [rsp+2816]
    call sha512

    ; Reduce k mod L
    lea rdi, [rsp+2816]
    call sc_reduce
    ; k at rsp+2816 (32 bytes)

    ; Compute S*B -> rsp+320 (160 bytes)
    ; S = sig[32..63]
    lea rdi, [rsp+320]
    mov rsi, [rbp-8]
    add rsi, 32          ; S
    call ge_scalarmult_base

    ; Compute k*A -> rsp+480 (160 bytes)
    lea rdi, [rsp+480]
    lea rsi, [rsp+2816]  ; k
    lea rdx, [rsp]       ; A
    call ge_scalarmult_var

    ; Compute R + k*A -> rsp+640 (160 bytes)
    lea rdi, [rsp+640]
    lea rsi, [rsp+160]   ; R
    lea rdx, [rsp+480]   ; k*A
    call ge_add

    ; Compress S*B -> rsp+800 (32 bytes)
    lea rdi, [rsp+800]
    lea rsi, [rsp+320]
    call ge_tobytes

    ; Compress R+kA -> rsp+832 (32 bytes)
    lea rdi, [rsp+832]
    lea rsi, [rsp+640]
    call ge_tobytes

    ; Compare the two compressed points
    mov rax, [rsp+800]
    xor rax, [rsp+832]
    mov rcx, [rsp+808]
    xor rcx, [rsp+840]
    or rax, rcx
    mov rcx, [rsp+816]
    xor rcx, [rsp+848]
    or rax, rcx
    mov rcx, [rsp+824]
    xor rcx, [rsp+856]
    or rax, rcx

    ; If all zero, points match -> return 0, else -1
    test rax, rax
    jz .verify_ok
    mov eax, -1
    jmp .verify_ret
.verify_ok:
    xor eax, eax
.verify_ret:
    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
