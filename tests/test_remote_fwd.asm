; Test harness for remote port forwarding (ssh -R)
; Same as bind mode harness: assembly acts as SSH server.
; Python connects, does kex+auth, sends GLOBAL_REQUEST "tcpip-forward",
; then connects to the forwarded port to test data relay.
;
; Reads from stdin:
;   bind_port (2 bytes LE) + host_private_key (32 bytes) + host_public_key (32 bytes)
;   + pass_len (4 bytes LE) + password (pass_len bytes)
;
; Flow:
;   1. net_listen(port) -> listen_fd
;   2. net_accept(listen_fd) -> client_fd
;   3. ssh_kex_server(client_fd, &state, &keypair)
;   4. ssh_auth_server_any(client_fd, &state, password, pass_len, NULL, 0)
;   5. ssh_channel_table_init(&chan_table)
;   6. ssh_client_event_loop_v2(client_fd, &state, &chan_table)
;   7. Close client_fd, loop back to accept

%include "ssh.inc"
%include "syscall.inc"

%define SSH_STATE_SIZE       176

extern net_listen
extern net_accept
extern net_close
extern ssh_kex_server
extern ssh_auth_server_any
extern ssh_client_event_loop_v2
extern ssh_channel_table_init

; Provide stub server_ip/server_port symbols
section .rodata
align 8
global server_ip
server_ip:      dd 0x0100007F
global server_port
server_port:    dw 0x1600

section .bss
    input_buf:      resb 512
    ssh_state:      resb SSH_STATE_SIZE
    chan_table:      resb CHAN_TABLE_SIZE
    host_keypair:   resb 64
    password_buf:   resb 256

section .data
    listen_fd:      dd 0
    pass_len:       dd 0

section .text
global _start

_start:
    ; Read bind_port (2 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 2
    syscall
    cmp rax, 2
    jne .exit_fail

    movzx r12d, word [rel input_buf]

    ; Read host_private_key (32) + host_public_key (32) = 64 bytes
    xor eax, eax
    xor edi, edi
    lea rsi, [rel host_keypair]
    mov edx, 64
    syscall
    cmp rax, 64
    jne .exit_fail

    ; Read pass_len (4 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r13d, [rel input_buf]
    mov [rel pass_len], r13d

    ; Read password
    test r13d, r13d
    jz .do_listen
    xor eax, eax
    xor edi, edi
    lea rsi, [rel password_buf]
    mov edx, r13d
    syscall
    cmp eax, r13d
    jne .exit_fail

.do_listen:
    mov esi, r12d
    call net_listen
    cmp rax, -1
    je .exit_fail
    mov r14d, eax
    mov [rel listen_fd], eax

    ; Signal ready
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ready_msg]
    mov edx, ready_msg_len
    syscall

.accept_loop:
    mov edi, r14d
    call net_accept
    cmp rax, -1
    je .accept_loop
    mov r15d, eax

    ; Zero SSH state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; Kex as server
    mov edi, r15d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .close_client

    ; Auth as server
    mov edi, r15d
    lea rsi, [rel ssh_state]
    lea rdx, [rel password_buf]
    mov ecx, [rel pass_len]
    xor r8d, r8d
    xor r9d, r9d
    call ssh_auth_server_any
    test rax, rax
    jnz .close_client

    ; Init channel table
    lea rdi, [rel chan_table]
    call ssh_channel_table_init

    ; Event loop
    mov edi, r15d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_table]
    call ssh_client_event_loop_v2

.close_client:
    mov edi, r15d
    call net_close
    jmp .accept_loop

.exit_success:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

section .rodata
    ready_msg: db "LISTENING", 10
    ready_msg_len equ $ - ready_msg
