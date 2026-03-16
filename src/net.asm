; net.asm - TCP networking for SSH program
; Pure x86-64 Linux syscalls, no libc

%include "syscall.inc"

section .text

; ============================================================================
; stack_probe - no-op on Linux (kernel handles stack growth automatically)
; Input: rax = allocation size (ignored)
; Called before large sub rsp to touch guard pages on Windows.
; On Linux this is a no-op — just a call+ret (~2 cycles overhead).
; ============================================================================
global stack_probe
stack_probe:
    ret

; ============================================================================
; platform_getrandom(rdi=buf, esi=len) -> rax=bytes_generated or -1
; Platform abstraction for random number generation.
; On Linux, wraps SYS_GETRANDOM. On Windows, hal_win_net provides equivalent.
; ============================================================================
global platform_getrandom
platform_getrandom:
    mov eax, SYS_GETRANDOM     ; 318
    ; rdi already has buf
    movzx rsi, esi              ; buflen (zero-extend to 64-bit)
    xor edx, edx               ; flags = 0
    syscall
    ret

; ============================================================================
; net_connect(rdi=ip_be32, esi=port_be16) -> rax=socket_fd or -1
; Creates TCP socket, connects to IP:port, returns fd
; ============================================================================
global net_connect
net_connect:
    push rbx
    push r12
    push r13
    mov r12d, edi               ; save IP (network byte order)
    movzx r13d, si              ; save port (network byte order)

    ; socket(AF_INET, SOCK_STREAM, 0)
    mov eax, SYS_SOCKET
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test eax, eax
    js .connect_fail
    mov ebx, eax                ; ebx = sockfd

    ; Build sockaddr_in on stack
    sub rsp, 16
    mov word [rsp], AF_INET     ; sin_family
    mov word [rsp + 2], r13w    ; sin_port (already BE)
    mov dword [rsp + 4], r12d   ; sin_addr (already BE)
    mov qword [rsp + 8], 0      ; padding

    ; connect(sockfd, &addr, 16)
    mov eax, SYS_CONNECT
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 16
    syscall
    add rsp, 16
    test eax, eax
    js .connect_close

    mov eax, ebx                ; return sockfd
    pop r13
    pop r12
    pop rbx
    ret

.connect_close:
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall
.connect_fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; net_read_exact(edi=fd, rsi=buf, edx=len) -> rax=0 success, -1 error
; Reads exactly len bytes, retrying on partial reads
; ============================================================================
global net_read_exact
net_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi                ; fd
    mov r12, rsi                ; buffer
    mov r13d, edx               ; total length
    xor r14d, r14d              ; bytes read so far

.read_loop:
    cmp r14d, r13d
    jge .read_done

    xor eax, eax                ; SYS_READ = 0
    mov edi, ebx
    lea rsi, [r12 + r14]
    mov edx, r13d
    sub edx, r14d
    movzx rdx, edx
    syscall
    test rax, rax
    jle .read_fail              ; error or EOF
    add r14d, eax
    jmp .read_loop

.read_done:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.read_fail:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; net_write_all(edi=fd, rsi=buf, edx=len) -> rax=0 success, -1 error
; Writes all bytes, retrying on partial writes
; ============================================================================
global net_write_all
net_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi                ; fd
    mov r12, rsi                ; buffer
    mov r13d, edx               ; total length
    xor r14d, r14d              ; bytes written so far

.write_loop:
    cmp r14d, r13d
    jge .write_done

    mov eax, SYS_WRITE
    mov edi, ebx
    lea rsi, [r12 + r14]
    mov edx, r13d
    sub edx, r14d
    movzx rdx, edx
    syscall
    test rax, rax
    js .write_fail
    add r14d, eax
    jmp .write_loop

.write_done:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.write_fail:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; net_connect_ip4(rdi=ip_string, esi=ip_len, edx=port_host_order) -> rax=sock_fd or -1
; Parses dotted-quad IP string (e.g., "10.10.10.5"), converts to network byte order,
; connects via TCP. Returns socket fd.
;
; IP parsing: split on '.', convert each octet to uint8 via repeated multiply-by-10
; Port conversion: bswap16 to network byte order
; Only supports dotted-quad IPv4 addresses, not hostnames.
; ============================================================================
global net_connect_ip4
net_connect_ip4:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                ; ip_string pointer
    mov r13d, esi               ; ip_len
    mov r14d, edx               ; port (host byte order)

    ; Parse dotted-quad IP into 4 bytes (network byte order)
    ; Register allocation:
    ;   r8d  = char index
    ;   r9d  = current octet accumulator
    ;   r10d = octet count (0..3)
    ;   r15d = ip_be32 result (byte 0 at bits 0-7, etc.)
    xor r15d, r15d
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d

.ip4_parse_loop:
    cmp r8d, r13d
    jge .ip4_store_last

    movzx eax, byte [r12 + r8]
    inc r8d

    cmp al, '.'
    je .ip4_store_octet

    ; Digit: accumulate = accumulate * 10 + (c - '0')
    sub al, '0'
    cmp al, 9
    ja .ip4_fail                ; not a digit — invalid IP
    imul r9d, r9d, 10
    movzx eax, al
    add r9d, eax
    jmp .ip4_parse_loop

.ip4_store_octet:
    cmp r9d, 255
    ja .ip4_fail
    cmp r10d, 3
    jge .ip4_fail               ; too many dots

    ; Store octet at byte position r10d in r15d
    mov ecx, r10d
    shl ecx, 3                  ; bit offset = octet_count * 8
    mov eax, r9d
    and eax, 0xFF
    shl eax, cl
    or r15d, eax

    inc r10d
    xor r9d, r9d
    jmp .ip4_parse_loop

.ip4_store_last:
    ; Store the final (4th) octet
    cmp r9d, 255
    ja .ip4_fail
    cmp r10d, 3
    jne .ip4_fail               ; must have exactly 3 dots (4 octets)

    mov ecx, r10d
    shl ecx, 3
    mov eax, r9d
    and eax, 0xFF
    shl eax, cl
    or r15d, eax

    ; r15d = IP in network byte order (first octet in lowest byte = correct for sockaddr_in)
    ; Convert port to network byte order (big-endian 16-bit)
    mov eax, r14d
    xchg al, ah                 ; bswap16
    movzx esi, ax               ; port_be16

    ; Call net_connect(ip_be32, port_be16)
    mov edi, r15d
    call net_connect
    ; rax = sock_fd or -1
    jmp .ip4_done

.ip4_fail:
    mov rax, -1

.ip4_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; net_listen(esi=port_host_order) -> rax=listen_fd or -1
; Creates TCP socket, sets SO_REUSEADDR, binds to 0.0.0.0:port, listens(5)
; ============================================================================
global net_listen
net_listen:
    push rbx
    push r12

    movzx r12d, si              ; save port (host byte order)

    ; socket(AF_INET, SOCK_STREAM, 0)
    mov eax, SYS_SOCKET
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test eax, eax
    js .listen_fail
    mov ebx, eax                ; ebx = sockfd

    ; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4)
    sub rsp, 16
    mov dword [rsp], 1          ; optval = 1
    mov eax, SYS_SETSOCKOPT
    mov edi, ebx
    mov esi, SOL_SOCKET
    mov edx, SO_REUSEADDR
    lea r10, [rsp]              ; optval ptr
    mov r8d, 4                  ; optlen
    syscall
    ; Ignore setsockopt error (non-fatal)

    ; Build sockaddr_in on stack: AF_INET, port (big-endian), 0.0.0.0
    mov word [rsp], AF_INET     ; sin_family
    ; Convert port to network byte order (big-endian 16-bit)
    mov eax, r12d
    xchg al, ah
    mov word [rsp + 2], ax      ; sin_port (BE)
    mov dword [rsp + 4], 0      ; sin_addr = 0.0.0.0 (INADDR_ANY)
    mov qword [rsp + 8], 0      ; padding

    ; bind(sockfd, &addr, 16)
    mov eax, SYS_BIND
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 16
    syscall
    add rsp, 16
    test eax, eax
    js .listen_close

    ; listen(sockfd, 5)
    mov eax, SYS_LISTEN
    mov edi, ebx
    mov esi, 5
    syscall
    test eax, eax
    js .listen_close

    mov eax, ebx                ; return listen_fd
    pop r12
    pop rbx
    ret

.listen_close:
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall
.listen_fail:
    mov rax, -1
    pop r12
    pop rbx
    ret

; ============================================================================
; net_accept(edi=listen_fd) -> rax=client_fd or -1
; accept(listen_fd, NULL, NULL) — blocks until a client connects
; ============================================================================
global net_accept
net_accept:
    mov eax, SYS_ACCEPT
    ; rdi already has listen_fd
    xor esi, esi                ; addr = NULL
    xor edx, edx               ; addrlen = NULL
    syscall
    ; rax = client_fd or negative errno
    test eax, eax
    js .accept_fail
    ret
.accept_fail:
    mov rax, -1
    ret

; ============================================================================
; net_close(edi=fd)
; ============================================================================
global net_close
net_close:
    mov eax, SYS_CLOSE
    syscall
    ret
