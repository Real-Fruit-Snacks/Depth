; ssh_forward.asm - SSH direct-tcpip port forwarding (RFC 4254 Section 7.2)
; Parses direct-tcpip CHANNEL_OPEN payload and connects to target
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "syscall.inc"

extern net_connect_ip4
extern decode_uint32

section .text

; ============================================================================
; ssh_forward_open(rdi=payload_ptr, esi=payload_len) -> rax=sock_fd or -1
;
; Parses a direct-tcpip CHANNEL_OPEN payload (the type-specific data AFTER
; the standard channel open header: type string + sender + window + maxpkt).
;
; The payload_ptr points at the beginning of:
;   [string host_to_connect]           ← target host (dotted-quad IP)
;   [uint32 port_to_connect]           ← target port (host byte order in SSH)
;   [string originator_ip_address]     ← ignored
;   [uint32 originator_port]           ← ignored
;
; Extracts host and port, calls net_connect_ip4, returns the socket fd.
; Returns -1 on parse error or connection failure.
; ============================================================================
global ssh_forward_open
ssh_forward_open:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi                ; payload_ptr
    mov r13d, esi               ; payload_len

    ; Parse host_to_connect string: [uint32 len][data]
    ; Need at least 4 bytes for length
    cmp r13d, 4
    jl .fwd_fail

    mov rdi, r12
    call decode_uint32          ; eax = host string length
    mov ebx, eax                ; ebx = host_len

    ; Validate: 4 + host_len + 4 (port) must fit in payload
    lea eax, [ebx + 8]         ; 4 (host len field) + host_len + 4 (port)
    cmp eax, r13d
    ja .fwd_fail

    ; Host string data at r12 + 4
    lea r14, [r12 + 4]         ; r14 = host string pointer

    ; Port at r12 + 4 + host_len
    lea eax, [ebx + 4]
    lea rdi, [r12 + rax]
    call decode_uint32          ; eax = port (host byte order per SSH spec)
    mov edx, eax                ; edx = port_host_order (3rd arg)

    ; Call net_connect_ip4(host_ptr, host_len, port_host_order)
    mov rdi, r14                ; ip_string
    mov esi, ebx                ; ip_len
    ; edx already set to port
    call net_connect_ip4
    ; rax = sock_fd or -1
    jmp .fwd_done

.fwd_fail:
    mov rax, -1

.fwd_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
