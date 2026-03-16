; HMAC-SHA256 per RFC 2104
; hmac_sha256(rdi=key, esi=key_len, rdx=msg, ecx=msg_len, r8=output_32)
;
; Uses existing sha256(rdi=msg_ptr, rsi=msg_len, rdx=output_32bytes)

%include "ssh.inc"

extern sha256

section .text
global hmac_sha256

; Stack frame layout (relative to rbp):
;   rbp-8       saved rbx
;   rbp-16      saved r12
;   rbp-24      saved r13
;   rbp-32      saved r14
;   rbp-40      saved r15
;   rbp-48      saved output pointer (r8)
;   rbp-52      saved msg_len (ecx)
;   rbp-60      saved msg pointer (rdx)
;   rbp-64      saved key_len (esi)
;   rbp-72      saved key pointer (rdi)
;   rbp-136     padded_key (64 bytes)  [rbp-136 .. rbp-73]
;   rbp-200     xor_key work area (64 bytes) [rbp-200 .. rbp-137]
;   rbp-232     inner_hash / final_hash temp (32 bytes) [rbp-232 .. rbp-201]
;   rbp-328     outer_concat buffer (96 = 64+32 bytes) [rbp-328 .. rbp-233]
;   Below:      inner_concat buffer (64 + msg_len), dynamically sized
;
; Total fixed: 328 bytes, round up to 336 for alignment

hmac_sha256:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 336                        ; fixed frame

    ; Save all arguments in callee-saved registers AND stack slots
    mov [rbp-72], rdi                   ; key pointer
    mov [rbp-64], rsi                   ; key_len (use full rsi, only low 32 bits matter)
    mov [rbp-60], rdx                   ; msg pointer
    mov [rbp-52], rcx                   ; msg_len (use full rcx, only low 32 bits matter)
    mov [rbp-48], r8                    ; output pointer

    ; Also save in callee-saved regs for quick access
    mov r12, rdi                        ; r12 = key
    mov r13d, esi                       ; r13d = key_len
    mov r14, rdx                        ; r14 = msg
    mov r15d, ecx                       ; r15d = msg_len

    ; Step 1: Zero padded_key (64 bytes at rbp-136)
    lea rdi, [rbp-136]
    xor eax, eax
    mov ecx, 64
    rep stosb

    ; Step 2: If key_len > 64, hash the key down to 32 bytes
    cmp r13d, 64
    jle .key_fits

    ; key too long: sha256(key, key_len) -> padded_key
    mov rdi, r12                        ; key pointer
    mov rsi, r13                        ; key_len (zero-extended)
    and rsi, 0xFFFFFFFF                 ; ensure clean 64-bit
    lea rdx, [rbp-136]                  ; output to padded_key
    call sha256

    ; Restore our saved values (sha256 may have clobbered registers)
    mov r12, [rbp-72]
    mov r13d, [rbp-64]
    mov r14, [rbp-60]
    mov r15d, [rbp-52]
    jmp .key_ready

.key_fits:
    ; Copy key to padded_key (rest already zeroed)
    lea rdi, [rbp-136]
    mov rsi, r12
    mov ecx, r13d
    test ecx, ecx
    jz .key_ready
    rep movsb

.key_ready:
    ; Step 3: Allocate inner_concat buffer on stack: 64 + msg_len bytes
    ; Need at least 64 bytes even if msg_len == 0
    mov eax, r15d
    add eax, 64
    add eax, 15
    and eax, -16                        ; 16-byte align size
    sub rsp, rax
    and rsp, -16                        ; ensure stack alignment
    mov rbx, rsp                        ; rbx = inner_concat buffer

    ; Step 4: Build inner_key in inner_concat: padded_key XOR 0x36
    lea rsi, [rbp-136]                  ; padded_key
    mov rdi, rbx                        ; inner_concat
    mov ecx, 64
.xor_ipad:
    mov al, [rsi]
    xor al, 0x36
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .xor_ipad

    ; Step 5: Copy message after inner_key in inner_concat
    ; rdi already points to inner_concat + 64
    mov rsi, r14                        ; msg pointer
    mov ecx, r15d                       ; msg_len
    test ecx, ecx
    jz .do_inner_hash
    rep movsb

.do_inner_hash:
    ; Step 6: inner_hash = SHA-256(inner_concat, 64 + msg_len)
    mov rdi, rbx                        ; inner_concat
    mov esi, r15d
    add esi, 64                         ; length = 64 + msg_len
    lea rdx, [rbp-232]                  ; output: inner_hash temp
    call sha256

    ; Restore callee-saved values after sha256 call
    mov r12, [rbp-72]
    mov r13d, [rbp-64]
    mov r14, [rbp-60]
    mov r15d, [rbp-52]

    ; Step 7: Build outer_concat at rbp-328: padded_key XOR 0x5c, then inner_hash
    lea rsi, [rbp-136]                  ; padded_key
    lea rdi, [rbp-328]                  ; outer_concat
    mov ecx, 64
.xor_opad:
    mov al, [rsi]
    xor al, 0x5c
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .xor_opad

    ; Copy inner_hash (32 bytes) after outer_key
    ; rdi already at outer_concat + 64
    lea rsi, [rbp-232]                  ; inner_hash
    mov ecx, 32
    rep movsb

    ; Step 8: result = SHA-256(outer_concat, 96)
    lea rdi, [rbp-328]                  ; outer_concat
    mov esi, 96                         ; 64 + 32
    lea rdx, [rbp-232]                  ; reuse temp for final hash
    call sha256

    ; Step 9: Copy final hash to output
    mov rdi, [rbp-48]                   ; output pointer
    lea rsi, [rbp-232]                  ; final hash
    mov ecx, 32
    rep movsb

    ; Restore stack and return
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
