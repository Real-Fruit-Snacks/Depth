; Debug harness for TLS 1.3 — exits with different codes to identify failure point
; Exit codes: 2=connect, 3=handshake, 4=write, 5=read, 0=success

%include "ssh.inc"
%include "tls.inc"
%include "syscall.inc"

extern tls13_handshake
extern tls_record_write_enc
extern tls_record_read_enc
extern net_connect

section .bss
    tls_state:  resb TLS_STATE_SIZE
    recv_buf:   resb 16384

section .data
    hello_msg:  db "HELLO_TLS"
    hello_len   equ 9

section .text
global _start

_start:
    sub rsp, 16
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 2
    syscall
    cmp rax, 2
    jne .fail_read

    movzx r12d, word [rsp]
    add rsp, 16

    ; Connect
    mov edi, 0x0100007F
    mov eax, r12d
    xchg al, ah
    movzx esi, ax
    call net_connect
    cmp rax, -1
    je .fail_connect
    mov r13d, eax

    ; Zero tls_state
    lea rdi, [rel tls_state]
    xor eax, eax
    mov ecx, TLS_STATE_SIZE
    rep stosb

    ; Handshake
    mov edi, r13d
    lea rsi, [rel tls_state]
    call tls13_handshake
    test rax, rax
    jnz .fail_handshake

    ; Write
    mov edi, r13d
    lea rsi, [rel tls_state]
    mov edx, TLS_CT_APPLICATION
    lea rcx, [rel hello_msg]
    mov r8d, hello_len
    call tls_record_write_enc
    test rax, rax
    jnz .fail_write

    ; Read — skip non-application-data records (NewSessionTicket etc.)
.read_loop:
    mov edi, r13d
    lea rsi, [rel tls_state]
    lea rdx, [rel recv_buf]
    mov ecx, 16384
    call tls_record_read_enc
    cmp rax, -1
    je .fail_read_enc

    cmp r8b, TLS_CT_APPLICATION
    jne .read_loop

    mov r14d, eax
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel recv_buf]
    mov edx, r14d
    syscall

    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.fail_read:
    mov edi, 10
    jmp .exit
.fail_connect:
    mov edi, 2
    jmp .exit
.fail_handshake:
    mov edi, 3
    jmp .exit
.fail_write:
    mov edi, 4
    jmp .exit
.fail_read_enc:
    mov edi, 5
.exit:
    mov eax, SYS_EXIT
    syscall
