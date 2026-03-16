; ssh_remote_forward.asm - SSH remote port forwarding (ssh -R, RFC 4254 Section 7.1)
; Handles SSH_MSG_GLOBAL_REQUEST "tcpip-forward" from the operator/client.
; The program (as SSH server) starts listening on the requested port.
; When a connection arrives, it sends CHANNEL_OPEN "forwarded-tcpip" back.
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "syscall.inc"

extern net_listen
extern net_accept
extern decode_uint32
extern encode_uint32
extern encode_string

; Forward table entry layout
%define FWD_LISTEN_FD    0    ; 4 bytes - listen socket fd
%define FWD_PORT         4    ; 4 bytes - bound port (host byte order)
%define FWD_ACTIVE       8    ; 4 bytes - 0=unused, 1=active
%define FWD_ENTRY_SIZE   16   ; padded to 16 for alignment
%define MAX_REMOTE_FWDS  4

section .bss
global remote_fwd_table
global remote_fwd_count
remote_fwd_table: resb FWD_ENTRY_SIZE * MAX_REMOTE_FWDS  ; 64 bytes
remote_fwd_count: resd 1

section .text

; ============================================================================
; ssh_remote_fwd_init()
; Zeros the remote forward table.
; ============================================================================
global ssh_remote_fwd_init
ssh_remote_fwd_init:
    lea rdi, [rel remote_fwd_table]
    xor eax, eax
    mov ecx, FWD_ENTRY_SIZE * MAX_REMOTE_FWDS
    rep stosb
    mov dword [rel remote_fwd_count], 0
    ret


; ============================================================================
; ssh_remote_fwd_handle_global_request(rdi=payload, esi=payload_len,
;                                       edx=sock_fd, rcx=state_ptr)
;     -> rax=0 success, -1 failure
;
; Parses SSH_MSG_GLOBAL_REQUEST:
;   [byte 80][string request_name][boolean want_reply][... request-specific data]
;
; For "tcpip-forward":
;   [string bind_address][uint32 bind_port]
;   Calls net_listen(bind_port), stores in forward table.
;   Sends SSH_MSG_REQUEST_SUCCESS [byte 81][uint32 bound_port] if want_reply.
;
; For "cancel-tcpip-forward":
;   [string bind_address][uint32 bind_port]
;   Finds and closes the matching forward entry.
;   Sends SSH_MSG_REQUEST_SUCCESS [byte 81] if want_reply.
;
; For unknown requests:
;   Sends SSH_MSG_REQUEST_FAILURE [byte 82] if want_reply.
; ============================================================================
global ssh_remote_fwd_handle_global_request
ssh_remote_fwd_handle_global_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 1024              ; work buffer for send

    mov r12, rdi               ; payload ptr
    mov r13d, esi              ; payload len
    mov r14d, edx              ; sock_fd
    mov r15, rcx               ; state_ptr

    ; Parse: [byte 80][string request_name][byte want_reply]
    ; request_name length at offset 1
    lea rdi, [r12 + 1]
    call decode_uint32         ; eax = name string length
    mov ebx, eax               ; ebx = name_len

    ; name string data at offset 5
    ; want_reply at offset 5 + name_len
    lea ecx, [ebx + 5]
    movzx ebp, byte [r12 + rcx]  ; ebp = want_reply (0 or 1)

    ; Request-specific data starts at offset 5 + name_len + 1 = 6 + name_len
    lea r13d, [ebx + 6]       ; r13d = offset to request-specific data

    ; Check "tcpip-forward" (13 bytes)
    cmp ebx, 13
    jne .check_cancel

    cmp byte [r12 + 5], 't'
    jne .check_cancel
    cmp byte [r12 + 6], 'c'
    jne .check_cancel
    cmp byte [r12 + 7], 'p'
    jne .check_cancel
    cmp byte [r12 + 8], 'i'
    jne .check_cancel
    cmp byte [r12 + 9], 'p'
    jne .check_cancel
    cmp byte [r12 + 10], '-'
    jne .check_cancel
    cmp byte [r12 + 11], 'f'
    jne .check_cancel
    cmp byte [r12 + 12], 'o'
    jne .check_cancel
    cmp byte [r12 + 13], 'r'
    jne .check_cancel
    cmp byte [r12 + 14], 'w'
    jne .check_cancel
    cmp byte [r12 + 15], 'a'
    jne .check_cancel
    cmp byte [r12 + 16], 'r'
    jne .check_cancel
    cmp byte [r12 + 17], 'd'
    jne .check_cancel
    jmp .handle_tcpip_forward

.check_cancel:
    ; Check "cancel-tcpip-forward" (20 bytes)
    cmp ebx, 20
    jne .unknown_request

    cmp byte [r12 + 5], 'c'
    jne .unknown_request
    cmp byte [r12 + 6], 'a'
    jne .unknown_request
    cmp byte [r12 + 7], 'n'
    jne .unknown_request
    cmp byte [r12 + 8], 'c'
    jne .unknown_request
    cmp byte [r12 + 9], 'e'
    jne .unknown_request
    cmp byte [r12 + 10], 'l'
    jne .unknown_request
    cmp byte [r12 + 11], '-'
    jne .unknown_request
    ; rest is "tcpip-forward" which we trust if prefix matched
    jmp .handle_cancel_forward

    ; ---- Handle tcpip-forward ----
.handle_tcpip_forward:
    ; Request-specific data at offset r13d:
    ;   [string bind_address][uint32 bind_port]

    ; Parse bind_address string (skip it, we always bind 0.0.0.0)
    movzx eax, r13w
    lea rdi, [r12 + rax]
    call decode_uint32         ; eax = bind_address string length
    ; Skip past: 4 (len field) + string data
    lea eax, [eax + 4]
    add r13d, eax              ; r13d now points to bind_port

    ; Parse bind_port
    movzx eax, r13w
    lea rdi, [r12 + rax]
    call decode_uint32         ; eax = bind_port (host byte order per SSH spec)
    mov ebx, eax               ; ebx = requested port

    ; Find a free forward table entry
    lea r13, [rel remote_fwd_table]
    xor ecx, ecx
.find_free_slot:
    cmp ecx, MAX_REMOTE_FWDS
    jge .table_full

    cmp dword [r13 + FWD_ACTIVE], 0
    je .found_free_slot

    add r13, FWD_ENTRY_SIZE
    inc ecx
    jmp .find_free_slot

.found_free_slot:
    ; Call net_listen(bind_port)
    mov esi, ebx               ; port in host byte order
    push r13
    push rbx
    call net_listen
    pop rbx
    pop r13
    cmp rax, -1
    je .listen_failed

    ; Store in forward table entry
    mov [r13 + FWD_LISTEN_FD], eax
    mov [r13 + FWD_PORT], ebx
    mov dword [r13 + FWD_ACTIVE], 1
    inc dword [rel remote_fwd_count]

    ; If bind_port was 0, we need to find what port was assigned
    ; Use getsockname. For simplicity, if port was 0, read it back.
    test ebx, ebx
    jnz .send_success_with_port

    ; getsockname(fd, &addr, &addrlen) to get the assigned port
    ; SYS_GETSOCKNAME = 51
    sub rsp, 32
    mov word [rsp], AF_INET
    mov qword [rsp + 16], 16   ; addrlen = 16
    mov eax, 51                ; SYS_GETSOCKNAME
    mov edi, [r13 + FWD_LISTEN_FD]
    lea rsi, [rsp]             ; addr buffer
    lea rdx, [rsp + 16]       ; addrlen ptr
    syscall
    ; Port is at [rsp + 2] in network byte order
    movzx eax, word [rsp + 2]
    xchg al, ah                ; convert to host byte order
    mov ebx, eax               ; ebx = actual port
    mov [r13 + FWD_PORT], ebx
    add rsp, 32

.send_success_with_port:
    ; Send SSH_MSG_REQUEST_SUCCESS if want_reply
    test ebp, ebp
    jz .success_done

    ; Build: [byte 81][uint32 bound_port]
    lea rdi, [rsp]
    mov byte [rdi], SSH_MSG_REQUEST_SUCCESS
    lea rdi, [rsp + 1]
    mov esi, ebx               ; bound port
    call encode_uint32

    ; Send encrypted
    extern ssh_send_packet_enc
    mov edi, r14d              ; sock_fd
    lea rsi, [rsp]             ; payload
    mov edx, 5                 ; 1 + 4
    mov rcx, r15               ; state_ptr
    call ssh_send_packet_enc

.success_done:
    xor eax, eax
    jmp .done

.table_full:
.listen_failed:
    ; Send SSH_MSG_REQUEST_FAILURE if want_reply
    test ebp, ebp
    jz .fail_done

    mov byte [rsp], SSH_MSG_REQUEST_FAILURE
    mov edi, r14d
    lea rsi, [rsp]
    mov edx, 1
    mov rcx, r15
    call ssh_send_packet_enc

.fail_done:
    mov rax, -1
    jmp .done

    ; ---- Handle cancel-tcpip-forward ----
.handle_cancel_forward:
    ; Parse bind_address (skip) and bind_port
    movzx eax, r13w
    lea rdi, [r12 + rax]
    call decode_uint32         ; eax = bind_address string length
    lea eax, [eax + 4]
    add r13d, eax

    movzx eax, r13w
    lea rdi, [r12 + rax]
    call decode_uint32         ; eax = bind_port
    mov ebx, eax               ; ebx = port to cancel

    ; Find matching entry
    lea r13, [rel remote_fwd_table]
    xor ecx, ecx
.find_cancel_slot:
    cmp ecx, MAX_REMOTE_FWDS
    jge .cancel_not_found

    cmp dword [r13 + FWD_ACTIVE], 1
    jne .cancel_next
    cmp [r13 + FWD_PORT], ebx
    je .found_cancel_slot

.cancel_next:
    add r13, FWD_ENTRY_SIZE
    inc ecx
    jmp .find_cancel_slot

.found_cancel_slot:
    ; Close the listen fd
    mov eax, SYS_CLOSE
    mov edi, [r13 + FWD_LISTEN_FD]
    syscall

    ; Clear the entry
    mov dword [r13 + FWD_LISTEN_FD], 0
    mov dword [r13 + FWD_PORT], 0
    mov dword [r13 + FWD_ACTIVE], 0
    dec dword [rel remote_fwd_count]

    ; Send SUCCESS if want_reply
    test ebp, ebp
    jz .cancel_success_done

    mov byte [rsp], SSH_MSG_REQUEST_SUCCESS
    mov edi, r14d
    lea rsi, [rsp]
    mov edx, 1
    mov rcx, r15
    call ssh_send_packet_enc

.cancel_success_done:
    xor eax, eax
    jmp .done

.cancel_not_found:
    ; Send FAILURE if want_reply
    test ebp, ebp
    jz .cancel_fail_done

    mov byte [rsp], SSH_MSG_REQUEST_FAILURE
    mov edi, r14d
    lea rsi, [rsp]
    mov edx, 1
    mov rcx, r15
    call ssh_send_packet_enc

.cancel_fail_done:
    mov rax, -1
    jmp .done

    ; ---- Unknown request ----
.unknown_request:
    ; Send REQUEST_FAILURE if want_reply
    test ebp, ebp
    jz .unknown_done

    mov byte [rsp], SSH_MSG_REQUEST_FAILURE
    mov edi, r14d
    lea rsi, [rsp]
    mov edx, 1
    mov rcx, r15
    call ssh_send_packet_enc

.unknown_done:
    mov rax, -1

.done:
    add rsp, 1024
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_remote_fwd_build_channel_open(rdi=send_buf, esi=sender_channel,
;                                    edx=port, ecx=initial_window,
;                                    r8d=max_packet)
;     -> rax=payload_len
;
; Builds SSH_MSG_CHANNEL_OPEN "forwarded-tcpip" payload:
;   [byte 90][string "forwarded-tcpip"]
;   [uint32 sender_channel][uint32 initial_window][uint32 max_packet]
;   [string connected_address="127.0.0.1"][uint32 connected_port]
;   [string originator_address="127.0.0.1"][uint32 originator_port=0]
; ============================================================================
global ssh_remote_fwd_build_channel_open
ssh_remote_fwd_build_channel_open:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi               ; send_buf
    mov r13d, esi              ; sender_channel
    mov r14d, edx              ; port
    mov r15d, ecx              ; initial_window
    mov ebx, r8d               ; max_packet

    ; [byte 90]
    mov byte [r12], SSH_MSG_CHANNEL_OPEN

    ; [string "forwarded-tcpip"] (15 bytes)
    lea rdi, [r12 + 1]
    mov esi, 15
    call encode_uint32         ; write length
    ; Write the string data
    mov byte [r12 + 5], 'f'
    mov byte [r12 + 6], 'o'
    mov byte [r12 + 7], 'r'
    mov byte [r12 + 8], 'w'
    mov byte [r12 + 9], 'a'
    mov byte [r12 + 10], 'r'
    mov byte [r12 + 11], 'd'
    mov byte [r12 + 12], 'e'
    mov byte [r12 + 13], 'd'
    mov byte [r12 + 14], '-'
    mov byte [r12 + 15], 't'
    mov byte [r12 + 16], 'c'
    mov byte [r12 + 17], 'p'
    mov byte [r12 + 18], 'i'
    mov byte [r12 + 19], 'p'
    ; offset is now 1 + 4 + 15 = 20

    ; [uint32 sender_channel]
    lea rdi, [r12 + 20]
    mov esi, r13d
    call encode_uint32

    ; [uint32 initial_window]
    lea rdi, [r12 + 24]
    mov esi, r15d
    call encode_uint32

    ; [uint32 max_packet]
    lea rdi, [r12 + 28]
    mov esi, ebx
    call encode_uint32

    ; [string connected_address="127.0.0.1"] (9 bytes)
    lea rdi, [r12 + 32]
    mov esi, 9
    call encode_uint32
    mov byte [r12 + 36], '1'
    mov byte [r12 + 37], '2'
    mov byte [r12 + 38], '7'
    mov byte [r12 + 39], '.'
    mov byte [r12 + 40], '0'
    mov byte [r12 + 41], '.'
    mov byte [r12 + 42], '0'
    mov byte [r12 + 43], '.'
    mov byte [r12 + 44], '1'
    ; offset = 32 + 4 + 9 = 45

    ; [uint32 connected_port]
    lea rdi, [r12 + 45]
    mov esi, r14d
    call encode_uint32
    ; offset = 49

    ; [string originator_address="127.0.0.1"] (9 bytes)
    lea rdi, [r12 + 49]
    mov esi, 9
    call encode_uint32
    mov byte [r12 + 53], '1'
    mov byte [r12 + 54], '2'
    mov byte [r12 + 55], '7'
    mov byte [r12 + 56], '.'
    mov byte [r12 + 57], '0'
    mov byte [r12 + 58], '.'
    mov byte [r12 + 59], '0'
    mov byte [r12 + 60], '.'
    mov byte [r12 + 61], '1'
    ; offset = 49 + 4 + 9 = 62

    ; [uint32 originator_port=0]
    lea rdi, [r12 + 62]
    xor esi, esi
    call encode_uint32
    ; total = 66

    mov eax, 66

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_remote_fwd_cleanup()
; Close all active forward listen fds.
; ============================================================================
global ssh_remote_fwd_cleanup
ssh_remote_fwd_cleanup:
    push rbx
    push r12

    lea r12, [rel remote_fwd_table]
    xor ebx, ebx

.cleanup_loop:
    cmp ebx, MAX_REMOTE_FWDS
    jge .cleanup_done

    cmp dword [r12 + FWD_ACTIVE], 1
    jne .cleanup_next

    mov eax, SYS_CLOSE
    mov edi, [r12 + FWD_LISTEN_FD]
    syscall

    mov dword [r12 + FWD_ACTIVE], 0
    mov dword [r12 + FWD_LISTEN_FD], 0

.cleanup_next:
    add r12, FWD_ENTRY_SIZE
    inc ebx
    jmp .cleanup_loop

.cleanup_done:
    mov dword [rel remote_fwd_count], 0
    pop r12
    pop rbx
    ret
