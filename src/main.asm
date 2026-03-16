; main.asm - SSH server entry point
; Connects to server, optionally wraps connection in TLS 1.3, authenticates,
; enters event loop to serve operator sessions.
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "tls.inc"
%include "syscall.inc"
%include "config.inc"

extern ssh_client_connect
extern ssh_kex_client
extern ssh_auth_client_password
extern ssh_client_event_loop_v2
extern ssh_channel_table_init
extern net_connect
extern net_listen
extern net_accept
extern net_close

; Bind mode (server-side functions)
extern ssh_kex_server
extern ssh_auth_server_any

; TLS support
extern tls13_handshake
extern tls_read_exact
extern tls_write_all
extern tls_io_state
extern tls_io_fd

; I/O dispatch (function pointer table)
extern io_read_fn
extern io_write_fn

section .bss
    ssh_state: resb 176          ; SSH_STATE_SIZE
    chan_table: resb CHAN_TABLE_SIZE  ; 384 bytes (MAX_CHANNELS * CHAN_STATE_SIZE)
    tls_state: resb TLS_STATE_SIZE   ; 104 bytes

section .text
global _start
_start:
    ; Step 0: Check bind mode
    cmp byte [rel bind_mode], 1
    je .bind_mode_start

    ; ---- Reverse mode (default) ----
    ; Check TLS mode
    cmp byte [rel tls_mode], 1
    je .tls_connect

    ; ---- Raw TCP mode (default) ----
    call ssh_client_connect
    cmp rax, -1
    je .exit_fail
    mov r12d, eax               ; save sock_fd
    jmp .do_ssh

.tls_connect:
    ; ---- TLS mode: connect to port 443, do TLS handshake, swap I/O ----
    ; Connect to server on TLS port
    mov edi, [rel server_ip]
    movzx esi, word [rel server_port_tls]
    call net_connect
    cmp rax, -1
    je .exit_fail
    mov r12d, eax               ; save sock_fd

    ; Zero TLS state
    lea rdi, [rel tls_state]
    xor eax, eax
    mov ecx, TLS_STATE_SIZE
    rep stosb

    ; Perform TLS 1.3 handshake
    mov edi, r12d
    lea rsi, [rel tls_state]
    call tls13_handshake
    test rax, rax
    jnz .exit_fail

    ; Configure TLS I/O layer with state and fd
    lea rax, [rel tls_state]
    mov [rel tls_io_state], rax
    mov [rel tls_io_fd], r12d

    ; Swap I/O function pointers: SSH transport now goes through TLS
    lea rax, [rel tls_read_exact]
    mov [rel io_read_fn], rax
    lea rax, [rel tls_write_all]
    mov [rel io_write_fn], rax

.do_ssh:
    ; Step 2: Key exchange (over raw TCP or TLS, depending on mode)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    call ssh_kex_client
    test rax, rax
    jnz .exit_fail

    ; Step 3: Authenticate
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel ssh_username]
    mov ecx, ssh_username_len
    lea r8, [rel ssh_password]
    mov r9d, ssh_password_len
    call ssh_auth_client_password
    test rax, rax
    jnz .exit_fail

    ; Step 4: Initialize channel table
    lea rdi, [rel chan_table]
    call ssh_channel_table_init

    ; Step 5: Enter v2 event loop (serve operator sessions)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_table]
    call ssh_client_event_loop_v2

    ; If event loop returns (connection dropped), exit
    jmp .exit_ok

    ; ================================================================
    ; Bind mode: act as SSH server, accept clients sequentially
    ; ================================================================
.bind_mode_start:
    ; Listen on bind port
    movzx esi, word [rel bind_port]
    call net_listen
    cmp rax, -1
    je .exit_fail
    mov r14d, eax               ; r14d = listen_fd

.bind_accept_loop:
    mov edi, r14d
    call net_accept
    cmp rax, -1
    je .bind_accept_loop        ; retry on error
    mov r12d, eax               ; r12d = client_fd

    ; Zero SSH state
    lea rdi, [rel ssh_state]
    xor eax, eax
    mov ecx, 176
    rep stosb

    ; Zero TLS state
    lea rdi, [rel tls_state]
    xor eax, eax
    mov ecx, TLS_STATE_SIZE
    rep stosb

    ; Optional TLS handshake (if tls_mode=1, accept TLS from client)
    cmp byte [rel tls_mode], 1
    jne .bind_no_tls

    ; For bind+TLS: the connecting client does TLS ClientHello
    ; We don't do server-side TLS in v1 bind mode — skip TLS
    ; (TLS server requires cert infrastructure not yet implemented)
    jmp .bind_no_tls

.bind_no_tls:
    ; SSH kex as server
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel host_keypair]
    call ssh_kex_server
    test rax, rax
    jnz .bind_close_client

    ; Auth as server (accept password or pubkey)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel ssh_password]
    mov ecx, ssh_password_len
    lea r8, [rel authorized_keys]
    mov r9d, [rel num_authorized_keys]
    call ssh_auth_server_any
    test rax, rax
    jnz .bind_close_client

    ; Initialize channel table for this session
    lea rdi, [rel chan_table]
    call ssh_channel_table_init

    ; Event loop (blocks until client disconnects)
    mov edi, r12d
    lea rsi, [rel ssh_state]
    lea rdx, [rel chan_table]
    call ssh_client_event_loop_v2

.bind_close_client:
    mov edi, r12d
    call net_close
    jmp .bind_accept_loop

.exit_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
