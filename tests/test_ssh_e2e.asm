; Test harness for SSH end-to-end: client kex + auth + event loop
; Reads from stdin:
;   sock_fd (4 bytes LE) + host_key(64 bytes) + pass_len(4 LE) + password
;
; The harness acts as the assembly side of a full e2e test:
;   - Runs kex as CLIENT (connects to Python mock teamserver)
;   - Runs auth as CLIENT
;   - Enters event loop (ssh_client_event_loop) which:
;     - Accepts CHANNEL_OPEN from mock teamserver
;     - Handles pty-req, shell/exec requests
;     - Runs PTY relay
;
; For the "client connect to server" e2e test, the Python side acts as
; the teamserver (kex_server + auth_server + sends CHANNEL_OPEN + requests).
;
; Exit code: 0=success, 1=failure

%include "ssh.inc"
%include "syscall.inc"

; SSH state offsets (must match ssh_transport.asm)
%define SSH_STATE_K1_C2S     0
%define SSH_STATE_K2_C2S     32
%define SSH_STATE_SEQ_C2S    64
%define SSH_STATE_K1_S2C     68
%define SSH_STATE_K2_S2C     100
%define SSH_STATE_SEQ_S2C    132
%define SSH_STATE_SESSION_ID 136
%define SSH_STATE_ROLE       168
%define SSH_STATE_SIZE       176

; Client functions
extern ssh_kex_client
extern ssh_auth_client_password
extern ssh_client_event_loop

; Provide stub server_ip/server_port symbols (ssh_client.asm extern references)
; The e2e test harness does NOT call ssh_client_connect, so these are unused.
section .rodata
align 8
global server_ip
server_ip:      dd 0x0100007F
global server_port
server_port:    dw 0x1600

section .bss
    input_buf:      resb 512
    ssh_state:      resb SSH_STATE_SIZE
    password_buf:   resb 256
    username_buf:   resb 256

section .text
global _start

_start:
    ; Read sock_fd (4 bytes LE)
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]  ; sock_fd

    ; Read user_len (4 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r13d, [rel input_buf]  ; user_len

    ; Read username
    test r13d, r13d
    jz .read_passlen
    xor eax, eax
    xor edi, edi
    lea rsi, [rel username_buf]
    mov edx, r13d
    syscall
    cmp eax, r13d
    jne .exit_fail

.read_passlen:
    ; Read pass_len (4 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r14d, [rel input_buf]  ; pass_len

    ; Read password
    test r14d, r14d
    jz .do_kex
    xor eax, eax
    xor edi, edi
    lea rsi, [rel password_buf]
    mov edx, r14d
    syscall
    cmp eax, r14d
    jne .exit_fail

.do_kex:
    ; Zero ssh_state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; Run kex as client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .exit_fail

    ; Run auth as client
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel username_buf]
    mov ecx, r13d              ; user_len
    lea r8, [rel password_buf]
    mov r9d, r14d              ; pass_len
    call ssh_auth_client_password
    test rax, rax
    jnz .exit_fail

    ; Enter event loop
    mov edi, r12d
    lea rsi, [rel ssh_state]
    call ssh_client_event_loop

    ; Event loop returned (connection dropped) -- success
    jmp .exit_success

.exit_success:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.exit_fail:
    mov byte [rel input_buf], 1
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall

    mov eax, SYS_EXIT
    mov edi, 1
    syscall
