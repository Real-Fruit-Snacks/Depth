; Test harness for TLS 1.3 handshake + record layer
; Reads port(2 LE) from stdin, connects to 127.0.0.1:port, performs TLS handshake,
; then sends "HELLO_TLS" via encrypted record, reads echo, writes echo to stdout.
; Exit 0 on success, 1 on failure.

%include "ssh.inc"
%include "tls.inc"
%include "syscall.inc"
%include "config.inc"

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
    ; Read 2-byte port (LE) from stdin
    sub rsp, 16
    xor eax, eax                ; SYS_READ
    xor edi, edi                ; stdin
    mov rsi, rsp
    mov edx, 2
    syscall
    cmp rax, 2
    jne .fail

    movzx r12d, word [rsp]     ; r12d = port (LE host order)
    add rsp, 16

    ; Connect to 127.0.0.1:port
    ; net_connect(ip_be32, port_be16)
    ; 127.0.0.1 in BE = 0x0100007F
    mov edi, 0x0100007F
    ; Convert port to BE16
    mov eax, r12d
    xchg al, ah
    movzx esi, ax
    call net_connect
    cmp rax, -1
    je .fail
    mov r13d, eax               ; r13d = sock_fd

    ; Zero tls_state
    lea rdi, [rel tls_state]
    xor eax, eax
    mov ecx, TLS_STATE_SIZE
    rep stosb

    ; Perform TLS handshake
    mov edi, r13d
    lea rsi, [rel tls_state]
    call tls13_handshake
    test rax, rax
    jnz .fail

    ; Send "HELLO_TLS" as encrypted application data
    mov edi, r13d
    lea rsi, [rel tls_state]
    mov edx, TLS_CT_APPLICATION
    lea rcx, [rel hello_msg]
    mov r8d, hello_len
    call tls_record_write_enc
    test rax, rax
    jnz .fail

    ; Read echo response — skip non-application-data records (e.g. NewSessionTicket)
.read_app_data:
    mov edi, r13d
    lea rsi, [rel tls_state]
    lea rdx, [rel recv_buf]
    mov ecx, 16384
    call tls_record_read_enc
    cmp rax, -1
    je .fail

    ; rax = plaintext_len, r8b = inner content type
    cmp r8b, TLS_CT_APPLICATION
    jne .read_app_data          ; skip handshake messages (NewSessionTicket etc.)

    mov r14d, eax               ; r14d = received data length

    ; Write received data to stdout
    mov eax, SYS_WRITE
    mov edi, 1                  ; stdout
    lea rsi, [rel recv_buf]
    mov edx, r14d
    syscall

    ; Close socket
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Exit 0
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
