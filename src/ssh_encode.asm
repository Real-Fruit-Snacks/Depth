; SSH wire encoding functions per RFC 4251
; Pure x86-64 NASM, no libc

section .text

; encode_uint32(rdi=output, esi=value) -> rax=4
;   Writes value as 4-byte big-endian
global encode_uint32
encode_uint32:
    mov eax, esi
    bswap eax
    mov [rdi], eax
    mov eax, 4
    ret

; decode_uint32(rdi=input) -> eax=value
;   Reads 4-byte big-endian uint32
global decode_uint32
decode_uint32:
    mov eax, [rdi]
    bswap eax
    ret

; encode_string(rdi=output, rsi=data, edx=data_len) -> rax=bytes_written
;   Writes: [uint32 len][data bytes] -> returns 4 + data_len
global encode_string
encode_string:
    push rdi
    push rsi
    push rdx

    ; Write big-endian length
    mov eax, edx
    bswap eax
    mov [rdi], eax

    ; Copy data
    add rdi, 4
    pop rcx             ; ecx = data_len (was edx)
    push rcx
    rep movsb

    pop rax             ; data_len
    add rax, 4          ; total = 4 + data_len
    pop rsi
    pop rdi
    ret

; decode_string(rdi=input) -> rax=data_offset(4), ecx=data_len
;   Returns offset=4 (data starts at input+4), length from the uint32 header
global decode_string
decode_string:
    mov ecx, [rdi]
    bswap ecx
    mov eax, 4
    ret

; encode_mpint(rdi=output, rsi=data_le, edx=data_len) -> rax=bytes_written
;   Converts little-endian byte array to SSH mpint encoding:
;   - Reverse to big-endian
;   - Strip leading zeros
;   - Prepend 0x00 if high bit set (positive number sign)
;   - Write uint32 length + bytes
global encode_mpint
encode_mpint:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; output buffer
    mov r13, rsi            ; input LE data
    mov r14d, edx           ; input length

    ; Reverse bytes into output+4 (temporary space for BE data)
    ; We reverse in-place into output+4, then adjust
    lea r15, [r12 + 4]      ; destination for BE bytes
    xor ecx, ecx            ; i = 0
.reverse_loop:
    cmp ecx, r14d
    jge .reverse_done
    mov eax, r14d
    sub eax, 1
    sub eax, ecx            ; index = len - 1 - i
    movzx ebx, byte [r13 + rax]
    mov [r15 + rcx], bl
    inc ecx
    jmp .reverse_loop
.reverse_done:

    ; Now r15 has r14d bytes of big-endian data
    ; Strip leading zeros
    xor ecx, ecx            ; skip index
.strip_zeros:
    cmp ecx, r14d
    jge .all_zero
    cmp byte [r15 + rcx], 0
    jne .found_nonzero
    inc ecx
    jmp .strip_zeros

.all_zero:
    ; Value is zero: mpint = [0x00 0x00 0x00 0x00] (length 0)
    xor eax, eax
    mov [r12], eax
    mov eax, 4
    jmp .mpint_done

.found_nonzero:
    ; ecx = index of first non-zero byte
    ; Remaining length = r14d - ecx
    mov ebx, r14d
    sub ebx, ecx            ; ebx = significant byte count
    lea rsi, [r15 + rcx]    ; rsi = pointer to first significant byte

    ; Check if high bit is set (need sign byte)
    movzx eax, byte [rsi]
    test eax, 0x80
    jz .no_sign_byte

    ; Need sign byte: shift data right by 1 to make room, then prepend 0x00
    ; First, move significant bytes from rsi to r12+5 (backwards to handle overlap)
    ; Use reverse copy: start from end
    mov ecx, ebx
    lea rdi, [r12 + 5 + rcx - 1]   ; dest end
    lea rax, [rsi + rcx - 1]       ; src end
.sign_copy:
    test ecx, ecx
    jz .sign_copy_done
    mov dl, [rax]
    mov [rdi], dl
    dec rdi
    dec rax
    dec ecx
    jmp .sign_copy
.sign_copy_done:
    mov byte [r12 + 4], 0          ; sign byte
    ; Write length = ebx + 1
    lea eax, [ebx + 1]
    bswap eax
    mov [r12], eax
    lea eax, [ebx + 5]             ; total = 4 + 1 + ebx
    jmp .mpint_done

.no_sign_byte:
    ; Move significant bytes to r12+4 (may overlap if ecx > 0)
    ; Copy forward is fine when dest <= src
    mov ecx, ebx
    lea rdi, [r12 + 4]
    rep movsb
    ; Write length = ebx
    mov eax, ebx
    bswap eax
    mov [r12], eax
    lea eax, [ebx + 4]             ; total = 4 + ebx
    ; fall through

.mpint_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; encode_mpint_be(rdi=output, rsi=data_be, edx=data_len) -> rax=bytes_written
; Same as encode_mpint but input is ALREADY big-endian (no byte reversal).
; Used for X25519 shared secrets which OpenSSH treats as BE per convention.
global encode_mpint_be
encode_mpint_be:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi            ; output buffer
    mov r13, rsi            ; input BE data
    mov r14d, edx           ; input length

    ; Strip leading zeros
    xor ecx, ecx
.be_strip_zeros:
    cmp ecx, r14d
    jge .be_all_zero
    cmp byte [r13 + rcx], 0
    jne .be_found_nonzero
    inc ecx
    jmp .be_strip_zeros

.be_all_zero:
    xor eax, eax
    mov [r12], eax
    mov eax, 4
    jmp .be_mpint_done

.be_found_nonzero:
    mov ebx, r14d
    sub ebx, ecx            ; ebx = significant byte count
    lea rsi, [r13 + rcx]    ; rsi = first significant byte

    ; Check if high bit set (need sign byte)
    movzx eax, byte [rsi]
    test eax, 0x80
    jz .be_no_sign

    ; Need sign byte
    mov byte [r12 + 4], 0
    lea rdi, [r12 + 5]
    mov ecx, ebx
    rep movsb
    lea eax, [ebx + 1]
    bswap eax
    mov [r12], eax
    lea eax, [ebx + 5]
    jmp .be_mpint_done

.be_no_sign:
    lea rdi, [r12 + 4]
    mov ecx, ebx
    rep movsb
    mov eax, ebx
    bswap eax
    mov [r12], eax
    lea eax, [ebx + 4]

.be_mpint_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; encode_name_list(rdi=output, rsi=string, edx=string_len) -> rax=bytes_written
;   Same as encode_string (name-list is just a string on the wire)
global encode_name_list
encode_name_list:
    jmp encode_string
