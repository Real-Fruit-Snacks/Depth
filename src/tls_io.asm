; tls_io.asm — Buffered TLS I/O for SSH-inside-TLS transport
;
; Provides tls_read_exact and tls_write_all with the SAME signatures as
; net_read_exact / net_write_all. When main.asm sets io_read_fn/io_write_fn
; to these functions, all SSH traffic flows through TLS records transparently.
;
; Read buffering: TLS records don't align with SSH packet boundaries.
; A single TLS record may contain parts of multiple SSH packets, or one SSH
; packet may span multiple TLS records. We maintain a read buffer that
; accumulates decrypted TLS application data and serves it to callers
; in the exact amounts they request.
;
; Write: wraps the data in a single TLS application data record.

%include "tls.inc"
%include "syscall.inc"

extern tls_record_write_enc
extern tls_record_read_enc

section .bss
; Read buffer — holds decrypted TLS record data between calls
tls_read_buf:   resb TLS_MAX_RECORD    ; 16640 bytes
tls_read_pos:   resd 1                 ; current read offset
tls_read_avail: resd 1                 ; bytes available from tls_read_pos

section .data
; TLS state pointer — set by main.asm before enabling TLS I/O
global tls_io_state
tls_io_state:   dq 0

; Socket fd for TLS — set by main.asm
global tls_io_fd
tls_io_fd:      dd 0

section .text

; =============================================================================
; tls_read_exact(edi=fd, rsi=buf, edx=len) -> rax=0 success, -1 error
;
; Reads exactly `len` bytes from TLS records into `buf`.
; Uses internal buffer to handle TLS record boundary misalignment.
; The fd parameter is ignored (tls_io_fd is used internally).
; =============================================================================
global tls_read_exact
tls_read_exact:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rsi                ; destination buffer
    mov r13d, edx               ; total bytes needed
    xor r14d, r14d              ; bytes copied so far

.read_loop:
    cmp r14d, r13d
    jge .read_done

    ; Check if buffer has data
    mov eax, [rel tls_read_avail]
    test eax, eax
    jz .read_fill_buffer

    ; Copy min(available, needed) bytes
    mov ecx, r13d
    sub ecx, r14d               ; bytes still needed
    cmp ecx, eax
    jbe .read_copy              ; need <= available
    mov ecx, eax               ; need > available, take what we have

.read_copy:
    ; Copy ecx bytes from tls_read_buf + tls_read_pos to dest + r14
    push rcx                    ; save count
    mov esi, [rel tls_read_pos]
    lea rsi, [rel tls_read_buf]
    add rsi, rax                ; rsi = tls_read_buf (need to use tls_read_pos)
    ; Redo: load pos properly
    pop rcx
    push rcx

    mov eax, [rel tls_read_pos]
    lea rsi, [rel tls_read_buf]
    add rsi, rax                ; rsi = &tls_read_buf[tls_read_pos]
    lea rdi, [r12 + r14]        ; rdi = dest + bytes_so_far
    rep movsb

    pop rcx                     ; restore count
    add r14d, ecx               ; bytes_copied += count

    ; Advance buffer position
    add [rel tls_read_pos], ecx
    sub [rel tls_read_avail], ecx

    jmp .read_loop

.read_fill_buffer:
    ; Buffer empty — read next TLS record
    ; tls_record_read_enc(edi=sock_fd, rsi=tls_state, rdx=output, ecx=max_len)
    ;   -> rax=plaintext_len or -1, inner content_type in r8b
    mov edi, [rel tls_io_fd]
    mov rsi, [rel tls_io_state]
    lea rdx, [rel tls_read_buf]
    mov ecx, TLS_MAX_RECORD
    call tls_record_read_enc
    cmp rax, -1
    je .read_fail

    ; Check it's application data (skip other record types like alerts)
    cmp r8b, TLS_CT_APPLICATION
    jne .read_fill_buffer       ; skip non-application records, read next

    ; Reset buffer position and set available bytes
    mov dword [rel tls_read_pos], 0
    mov [rel tls_read_avail], eax

    jmp .read_loop

.read_done:
    xor eax, eax               ; success
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.read_fail:
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; =============================================================================
; tls_write_all(edi=fd, rsi=buf, edx=len) -> rax=0 success, -1 error
;
; Wraps data in a TLS application data record and sends it.
; The fd parameter is ignored (tls_io_fd is used internally).
; For large writes, splits into multiple TLS records of max 16384 bytes.
; =============================================================================
global tls_write_all
tls_write_all:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rsi                ; source buffer
    mov r13d, edx               ; total bytes to write
    xor r14d, r14d              ; bytes written so far

.write_loop:
    cmp r14d, r13d
    jge .write_done

    ; Calculate chunk size: min(remaining, 16384)
    mov ecx, r13d
    sub ecx, r14d               ; remaining
    cmp ecx, 16384
    jbe .write_chunk
    mov ecx, 16384

.write_chunk:
    mov ebx, ecx               ; save chunk size

    ; tls_record_write_enc(edi=sock_fd, rsi=tls_state, edx=inner_ct, rcx=data, r8d=data_len)
    mov edi, [rel tls_io_fd]
    mov rsi, [rel tls_io_state]
    mov edx, TLS_CT_APPLICATION
    lea rcx, [r12 + r14]       ; data pointer
    mov r8d, ebx               ; data_len = chunk size
    call tls_record_write_enc
    test rax, rax
    jnz .write_fail

    add r14d, ebx
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
