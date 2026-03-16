%include "ssh.inc"

extern encode_uint32
extern decode_uint32
extern encode_string
extern decode_string
extern encode_mpint
extern encode_name_list

section .bss
    input_buf:  resb 4096
    output_buf: resb 4096
    data_buf:   resb 4096

section .text
global _start

_start:
    ; Read 1 byte command from stdin
    xor eax, eax            ; SYS_READ
    xor edi, edi             ; fd 0
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall
    test rax, rax
    jle .exit_fail

    movzx eax, byte [rel input_buf]

    cmp al, 'u'
    je .cmd_uint32
    cmp al, 's'
    je .cmd_string
    cmp al, 'm'
    je .cmd_mpint
    jmp .exit_fail

.cmd_uint32:
    ; Read 4 bytes LE value
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    ; encode_uint32(output, value)
    lea rdi, [rel output_buf]
    mov esi, [rel input_buf]    ; LE value
    call encode_uint32

    ; Write 4 bytes to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    mov edx, 4
    syscall
    jmp .exit_ok

.cmd_string:
    ; Read 4 bytes LE length
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]   ; data length

    ; Read data bytes (may need loop for large data)
    test r12d, r12d
    jz .do_encode_string

    xor r13d, r13d              ; bytes read so far
.read_string_data:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel data_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_encode_string
    add r13d, eax
    cmp r13d, r12d
    jl .read_string_data

.do_encode_string:
    ; encode_string(output, data, len)
    lea rdi, [rel output_buf]
    lea rsi, [rel data_buf]
    mov edx, r12d
    call encode_string
    mov r14, rax                ; bytes written

    ; Write output to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    mov edx, r14d
    syscall
    jmp .exit_ok

.cmd_mpint:
    ; Read 4 bytes LE length
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]   ; data length

    ; Read LE data bytes
    test r12d, r12d
    jz .do_encode_mpint

    xor r13d, r13d
.read_mpint_data:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel data_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_encode_mpint
    add r13d, eax
    cmp r13d, r12d
    jl .read_mpint_data

.do_encode_mpint:
    ; encode_mpint(output, data_le, len)
    lea rdi, [rel output_buf]
    lea rsi, [rel data_buf]
    mov edx, r12d
    call encode_mpint
    mov r14, rax                ; bytes written

    ; Write output to stdout
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    mov edx, r14d
    syscall
    jmp .exit_ok

.exit_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
