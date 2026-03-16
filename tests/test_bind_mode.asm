; Test harness for bind mode (assembly acts as SSH server)
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
;
; Exit code: 0=success, 1=failure

%include "ssh.inc"
%include "syscall.inc"

; SSH state offsets
%define SSH_STATE_SIZE       176

; Extern functions
extern net_listen
extern net_accept
extern net_close
extern ssh_kex_server
extern ssh_auth_server_any
extern ssh_client_event_loop_v2
extern ssh_channel_table_init

; Provide stub server_ip/server_port symbols (ssh_client.asm extern references)
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
    xor eax, eax               ; SYS_READ
    xor edi, edi               ; stdin
    lea rsi, [rel input_buf]
    mov edx, 2
    syscall
    cmp rax, 2
    jne .exit_fail

    movzx r12d, word [rel input_buf]  ; r12d = port (host order)

    ; Read host_private_key (32 bytes) + host_public_key (32 bytes) = 64 bytes
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

    mov r13d, [rel input_buf]  ; pass_len
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
    ; Listen on the specified port
    mov esi, r12d
    call net_listen
    cmp rax, -1
    je .exit_fail
    mov r14d, eax               ; r14d = listen_fd
    mov [rel listen_fd], eax

    ; Write "LISTENING\n" to stdout to signal ready
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel ready_msg]
    mov edx, ready_msg_len
    syscall

.accept_loop:
    mov edi, r14d
    call net_accept
    cmp rax, -1
    je .accept_loop             ; retry on error
    mov r15d, eax               ; r15d = client_fd

    ; Zero SSH state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, SSH_STATE_SIZE
    rep stosb

    ; SSH kex as server
    mov edi, r15d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .close_client

    ; Auth as server (password only for test, no pubkeys)
    mov edi, r15d
    lea rsi, [rel ssh_state]
    lea rdx, [rel password_buf]
    mov ecx, [rel pass_len]
    xor r8d, r8d               ; authorized_keys = NULL
    xor r9d, r9d               ; num_keys = 0
    call ssh_auth_server_any
    test rax, rax
    jnz .close_client

    ; Initialize channel table
    lea rdi, [rel chan_table]
    call ssh_channel_table_init

    ; Event loop (blocks until client disconnects)
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
