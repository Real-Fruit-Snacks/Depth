; Test harness for SSH transport functions
; Commands via stdin:
;   'v' - test ssh_build_kexinit: outputs the KEXINIT payload
;   'p' - test plaintext packet send: reads payload_len(4 LE) + payload,
;          builds packet and writes it to stdout
;   'r' - test plaintext packet recv: reads raw_len(4 LE) + raw_packet_bytes,
;          feeds through a socketpair, returns extracted payload
;   'n' - test net_read_exact + net_write_all through socketpair:
;          reads data_len(4 LE) + data, sends through socketpair, reads back, outputs

%include "ssh.inc"
%include "syscall.inc"

extern ssh_build_kexinit
extern ssh_send_packet_plain
extern ssh_recv_packet_plain
extern ssh_send_version
extern ssh_recv_version
extern net_read_exact
extern net_write_all
extern net_close
extern encode_uint32

section .bss
    input_buf:  resb 65536
    output_buf: resb 65536
    work_buf:   resb 65536

section .text
global _start

_start:
    ; Read 1 byte command
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 1
    syscall
    test rax, rax
    jle .exit_fail

    movzx eax, byte [rel input_buf]

    cmp al, 'v'
    je .cmd_kexinit
    cmp al, 'p'
    je .cmd_packet_build
    cmp al, 'r'
    je .cmd_packet_parse
    cmp al, 'n'
    je .cmd_net_roundtrip
    jmp .exit_fail

; --- Build KEXINIT payload and output it ---
.cmd_kexinit:
    lea rdi, [rel output_buf]
    call ssh_build_kexinit
    ; rax = payload length

    mov rdx, rax
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

; --- Build plaintext SSH packet from payload ---
; Input: payload_len(4 LE) + payload
; Output: raw SSH packet bytes [pkt_len(4 BE)][pad_len(1)][payload][padding]
.cmd_packet_build:
    ; Read payload_len (4 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]   ; payload_len

    ; Read payload
    test r12d, r12d
    jz .do_packet_build
    xor r13d, r13d
.read_payload_build:
    xor eax, eax
    xor edi, edi
    lea rsi, [rel work_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_packet_build
    add r13d, eax
    cmp r13d, r12d
    jl .read_payload_build

.do_packet_build:
    ; We need a socketpair to use ssh_send_packet_plain (it writes to fd)
    ; Instead, let's build the packet manually using the same logic
    ; to test the format. Actually let's use pipe.

    ; Create pipe: pipe2(pipefd, 0)
    sub rsp, 16                 ; space for 2 ints
    mov eax, SYS_PIPE2
    lea rdi, [rsp]
    xor esi, esi
    syscall
    test eax, eax
    jnz .exit_fail_stack16

    mov r14d, [rsp]             ; read end
    mov r15d, [rsp + 4]         ; write end
    add rsp, 16

    ; Send packet through pipe
    mov edi, r15d
    lea rsi, [rel work_buf]
    mov edx, r12d
    call ssh_send_packet_plain

    ; Close write end
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall

    ; Read all available data from read end
    ; First, read the 4-byte packet length
    xor eax, eax
    mov edi, r14d
    lea rsi, [rel output_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    ; Decode pkt_len to know how much more to read
    mov eax, [rel output_buf]
    bswap eax                   ; big-endian to host
    mov r13d, eax               ; pkt_len

    ; Read pkt_len more bytes
    xor r15d, r15d
.read_pipe_rest:
    cmp r15d, r13d
    jge .read_pipe_done
    xor eax, eax
    mov edi, r14d
    lea rsi, [rel output_buf + 4]
    add rsi, r15
    mov edx, r13d
    sub edx, r15d
    syscall
    test rax, rax
    jle .read_pipe_done
    add r15d, eax
    jmp .read_pipe_rest
.read_pipe_done:

    ; Close read end
    mov eax, SYS_CLOSE
    mov edi, r14d
    syscall

    ; Write total packet (4 + pkt_len) to stdout
    lea edx, [r13d + 4]
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

; --- Parse plaintext SSH packet ---
; Input: raw_len(4 LE) + raw_packet_bytes
; Output: extracted payload
.cmd_packet_parse:
    ; Read raw_len (4 bytes LE)
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]   ; raw_len

    ; Read raw packet bytes
    xor r13d, r13d
.read_raw:
    cmp r13d, r12d
    jge .do_parse
    xor eax, eax
    xor edi, edi
    lea rsi, [rel work_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_parse
    add r13d, eax
    cmp r13d, r12d
    jl .read_raw

.do_parse:
    ; Create pipe, write raw data, then recv_packet_plain from read end
    sub rsp, 16
    mov eax, SYS_PIPE2
    lea rdi, [rsp]
    xor esi, esi
    syscall
    test eax, eax
    jnz .exit_fail_stack16

    mov r14d, [rsp]             ; read end
    mov r15d, [rsp + 4]         ; write end
    add rsp, 16

    ; Write raw packet to pipe
    mov eax, SYS_WRITE
    mov edi, r15d
    lea rsi, [rel work_buf]
    mov edx, r12d
    syscall

    ; Close write end
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall

    ; Receive packet from read end
    mov edi, r14d
    lea rsi, [rel output_buf]
    mov edx, 65000
    call ssh_recv_packet_plain
    ; rax = payload_len or -1

    push rax                    ; save payload_len

    ; Close read end
    mov eax, SYS_CLOSE
    mov edi, r14d
    syscall

    pop rax
    cmp rax, -1
    je .exit_fail

    ; Write payload to stdout
    mov rdx, rax
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

; --- Net roundtrip test ---
; Input: data_len(4 LE) + data
; Uses pipe to test net_write_all -> net_read_exact roundtrip
.cmd_net_roundtrip:
    ; Read data_len
    xor eax, eax
    xor edi, edi
    lea rsi, [rel input_buf]
    mov edx, 4
    syscall
    cmp rax, 4
    jne .exit_fail

    mov r12d, [rel input_buf]

    ; Read data
    xor r13d, r13d
.read_net_data:
    cmp r13d, r12d
    jge .do_net_test
    xor eax, eax
    xor edi, edi
    lea rsi, [rel work_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d
    syscall
    test rax, rax
    jle .do_net_test
    add r13d, eax
    cmp r13d, r12d
    jl .read_net_data

.do_net_test:
    ; Create pipe
    sub rsp, 16
    mov eax, SYS_PIPE2
    lea rdi, [rsp]
    xor esi, esi
    syscall
    test eax, eax
    jnz .exit_fail_stack16

    mov r14d, [rsp]             ; read end
    mov r15d, [rsp + 4]         ; write end
    add rsp, 16

    ; Write data through pipe using net_write_all
    mov edi, r15d
    lea rsi, [rel work_buf]
    mov edx, r12d
    call net_write_all
    test rax, rax
    jnz .exit_fail

    ; Close write end
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall

    ; Read data back using net_read_exact
    mov edi, r14d
    lea rsi, [rel output_buf]
    mov edx, r12d
    call net_read_exact
    test rax, rax
    jnz .exit_fail

    ; Close read end
    mov eax, SYS_CLOSE
    mov edi, r14d
    syscall

    ; Write to stdout
    mov edx, r12d
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel output_buf]
    syscall
    jmp .exit_ok

.exit_fail_stack16:
    add rsp, 16
.exit_fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

.exit_ok:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
