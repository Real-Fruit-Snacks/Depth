; chacha20.inc - ChaCha20 block function and stream cipher
; Platform-agnostic NASM include file (no syscalls, no API calls)
; Implements RFC 8439 ChaCha20

; Quarter-round macro: QR(a, b, c, d) on the state array at [rbp + offset]
; %1-%4 are offsets into the state (in bytes, i.e., word_index * 4)
%macro CHACHA20_QR 4
    ; a += b; d ^= a; d <<<= 16
    mov eax, [rbp + %1]
    add eax, [rbp + %2]
    mov [rbp + %1], eax
    mov edx, [rbp + %4]
    xor edx, eax
    rol edx, 16
    mov [rbp + %4], edx

    ; c += d; b ^= c; b <<<= 12
    mov eax, [rbp + %3]
    add eax, edx
    mov [rbp + %3], eax
    mov edx, [rbp + %2]
    xor edx, eax
    rol edx, 12
    mov [rbp + %2], edx

    ; a += b; d ^= a; d <<<= 8
    mov eax, [rbp + %1]
    add eax, edx
    mov [rbp + %1], eax
    mov edx, [rbp + %4]
    xor edx, eax
    rol edx, 8
    mov [rbp + %4], edx

    ; c += d; b ^= c; b <<<= 7
    mov eax, [rbp + %3]
    add eax, edx
    mov [rbp + %3], eax
    mov edx, [rbp + %2]
    xor edx, eax
    rol edx, 7
    mov [rbp + %2], edx
%endmacro

section .text

; chacha20_block: Generate 64 bytes of keystream
; Input:
;   rdi = pointer to 32-byte key
;   esi = block counter (uint32)
;   rdx = pointer to 12-byte nonce
;   rcx = pointer to 64-byte output buffer
; Clobbers: rax, rdx (others saved/restored)
chacha20_block:
    ; Save callee-saved registers
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi        ; key pointer
    mov r13d, esi       ; block counter
    mov r14, rdx        ; nonce pointer
    mov r15, rcx        ; output buffer pointer

    ; Allocate 128 bytes on stack: 64 for working state, 64 for original state
    ; Layout: [rsp] = working state (64 bytes), [rsp+64] = original state (64 bytes)
    sub rsp, 128

    ; Set up state matrix in original state area [rsp+64]
    ; Words 0-3: Constants "expand 32-byte k"
    mov dword [rsp + 64 +  0], 0x61707865
    mov dword [rsp + 64 +  4], 0x3320646e
    mov dword [rsp + 64 +  8], 0x79622d32
    mov dword [rsp + 64 + 12], 0x6b206574

    ; Words 4-11: Key (8 x 32-bit LE words, already LE in memory)
    mov eax, [r12 +  0]
    mov [rsp + 64 + 16], eax
    mov eax, [r12 +  4]
    mov [rsp + 64 + 20], eax
    mov eax, [r12 +  8]
    mov [rsp + 64 + 24], eax
    mov eax, [r12 + 12]
    mov [rsp + 64 + 28], eax
    mov eax, [r12 + 16]
    mov [rsp + 64 + 32], eax
    mov eax, [r12 + 20]
    mov [rsp + 64 + 36], eax
    mov eax, [r12 + 24]
    mov [rsp + 64 + 40], eax
    mov eax, [r12 + 28]
    mov [rsp + 64 + 44], eax

    ; Word 12: Block counter
    mov [rsp + 64 + 48], r13d

    ; Words 13-15: Nonce (3 x 32-bit LE words)
    mov eax, [r14 +  0]
    mov [rsp + 64 + 52], eax
    mov eax, [r14 +  4]
    mov [rsp + 64 + 56], eax
    mov eax, [r14 +  8]
    mov [rsp + 64 + 60], eax

    ; Copy original state to working state
    ; Copy 64 bytes (8 qwords)
    lea rsi, [rsp + 64]
    lea rdi, [rsp]
    mov ecx, 8
.chacha20_copy_state:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .chacha20_copy_state

    ; rbp = pointer to working state for QR macro
    lea rbp, [rsp]

    ; 20 rounds = 10 iterations of (column rounds + diagonal rounds)
    mov ebx, 10
.chacha20_rounds:
    ; Column rounds
    ; QR(0, 4,  8, 12)  -> offsets 0, 16, 32, 48
    CHACHA20_QR 0, 16, 32, 48
    ; QR(1, 5,  9, 13)  -> offsets 4, 20, 36, 52
    CHACHA20_QR 4, 20, 36, 52
    ; QR(2, 6, 10, 14)  -> offsets 8, 24, 40, 56
    CHACHA20_QR 8, 24, 40, 56
    ; QR(3, 7, 11, 15)  -> offsets 12, 28, 44, 60
    CHACHA20_QR 12, 28, 44, 60

    ; Diagonal rounds
    ; QR(0, 5, 10, 15)  -> offsets 0, 20, 40, 60
    CHACHA20_QR 0, 20, 40, 60
    ; QR(1, 6, 11, 12)  -> offsets 4, 24, 44, 48
    CHACHA20_QR 4, 24, 44, 48
    ; QR(2, 7,  8, 13)  -> offsets 8, 28, 32, 52
    CHACHA20_QR 8, 28, 32, 52
    ; QR(3, 4,  9, 14)  -> offsets 12, 16, 36, 56
    CHACHA20_QR 12, 16, 36, 56

    dec ebx
    jnz .chacha20_rounds

    ; Add original state to working state (word-by-word)
    mov ecx, 16
    lea rsi, [rsp + 64]     ; original state
    lea rdi, [rsp]           ; working state
.chacha20_add_state:
    mov eax, [rsi]
    add [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .chacha20_add_state

    ; Write 16 LE dwords (64 bytes) to output buffer
    lea rsi, [rsp]
    mov rdi, r15
    mov ecx, 8
.chacha20_write_output:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .chacha20_write_output

    ; Clean up stack
    add rsp, 128

    ; Restore callee-saved registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; chacha20_encrypt: XOR plaintext with ChaCha20 keystream
; Input:
;   rdi = key pointer (32 bytes)
;   esi = initial block counter (uint32)
;   rdx = nonce pointer (12 bytes)
;   rcx = input data pointer
;   r8  = data length (bytes)
;   r9  = output buffer pointer
chacha20_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rdi        ; key pointer
    mov r13d, esi       ; block counter
    mov r14, rdx        ; nonce pointer
    mov r15, rcx        ; input data pointer
    push r8             ; data length (on stack)
    push r9             ; output buffer pointer (on stack)

    ; Allocate 64 bytes for keystream block on stack
    sub rsp, 64

    ; r15 = input pointer (already set)
    ; rbx = bytes remaining
    mov rbx, [rsp + 64 + 8]   ; data length (r8 was pushed first after r9... fix offsets)
    ; Stack layout: [rsp] = 64-byte keystream, [rsp+64] = output ptr (r9), [rsp+72] = data len (r8)
    mov rbx, [rsp + 72]       ; data length
    mov rbp, [rsp + 64]       ; output buffer pointer

.chacha20_enc_loop:
    test rbx, rbx
    jz .chacha20_enc_done

    ; Generate keystream block
    ; chacha20_block(key=r12, counter=r13d, nonce=r14, output=rsp)
    mov rdi, r12
    mov esi, r13d
    mov rdx, r14
    lea rcx, [rsp]
    ; Save volatile registers before call
    push rbx
    push rbp
    push r15
    call chacha20_block
    pop r15
    pop rbp
    pop rbx

    ; Increment block counter
    inc r13d

    ; Determine how many bytes to XOR this iteration (min(rbx, 64))
    mov rcx, 64
    cmp rbx, 64
    cmovb rcx, rbx         ; rcx = min(remaining, 64)

    ; XOR input with keystream, write to output
    xor edx, edx           ; byte index
.chacha20_enc_xor:
    cmp rdx, rcx
    jge .chacha20_enc_next
    movzx eax, byte [r15 + rdx]    ; input byte
    xor al, byte [rsp + rdx]        ; XOR with keystream
    mov byte [rbp + rdx], al         ; write to output
    inc rdx
    jmp .chacha20_enc_xor

.chacha20_enc_next:
    add r15, rcx            ; advance input pointer
    add rbp, rcx            ; advance output pointer
    sub rbx, rcx            ; decrease remaining bytes
    jmp .chacha20_enc_loop

.chacha20_enc_done:
    ; Clean up stack (64-byte keystream + 2 pushes)
    add rsp, 64 + 16

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
