; test_tls_ssh.asm — Test harness for SSH-inside-TLS
;
; Reads port(2 LE) from stdin, connects to 127.0.0.1:port, performs TLS 1.3
; handshake, then runs SSH kex + auth over the TLS tunnel.
; Exit 0 on success (SSH auth completed), 1 on failure.
;
; The Python test (test_tls_ssh.py) runs a TLS-terminating proxy that
; forwards decrypted traffic to a real asyncssh server.

%include "ssh.inc"
%include "tls.inc"
%include "syscall.inc"
%include "config.inc"

; TLS functions
extern tls13_handshake
extern tls_record_write_enc
extern tls_record_read_enc
extern tls_read_exact
extern tls_write_all
extern tls_io_state
extern tls_io_fd

; I/O dispatch
extern io_read_fn
extern io_write_fn

; Network
extern net_connect

; SSH functions
extern ssh_kex_client
extern ssh_auth_client_password

section .bss
    tls_state:  resb TLS_STATE_SIZE
    ssh_state:  resb 176          ; SSH_STATE_SIZE

section .data
    ; Credentials matching the Python test server
    test_user:  db "svc"
    test_user_len equ 3
    test_pass:  db "changeme"
    test_pass_len equ 10

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
    mov edi, 0x0100007F         ; 127.0.0.1 in BE
    mov eax, r12d
    xchg al, ah                 ; convert to BE16
    movzx esi, ax
    call net_connect
    cmp rax, -1
    je .fail
    mov r13d, eax               ; r13d = sock_fd

    ; Zero TLS state
    lea rdi, [rel tls_state]
    xor eax, eax
    mov ecx, TLS_STATE_SIZE
    rep stosb

    ; Perform TLS 1.3 handshake
    mov edi, r13d
    lea rsi, [rel tls_state]
    call tls13_handshake
    test rax, rax
    jnz .fail

    ; Configure TLS I/O layer
    lea rax, [rel tls_state]
    mov [rel tls_io_state], rax
    mov [rel tls_io_fd], r13d

    ; Swap I/O function pointers so SSH transport goes through TLS
    lea rax, [rel tls_read_exact]
    mov [rel io_read_fn], rax
    lea rax, [rel tls_write_all]
    mov [rel io_write_fn], rax

    ; Zero SSH state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, 176
    rep stosb

    ; SSH key exchange — goes through TLS transparently
    mov edi, r13d
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .fail

    ; SSH password authentication
    mov edi, r13d
    lea rsi, [rel ssh_state]
    lea rdx, [rel test_user]
    mov ecx, test_user_len
    lea r8, [rel test_pass]
    mov r9d, test_pass_len
    call ssh_auth_client_password
    test rax, rax
    jnz .fail

    ; Write "OK" to stdout to signal success
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ok_msg]
    mov edx, 2
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

section .rodata
    ok_msg: db "OK"
