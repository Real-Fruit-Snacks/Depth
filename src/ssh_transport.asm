; ssh_transport.asm - SSH packet framing, KEXINIT, and key exchange
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
; syscall.inc no longer needed — SYS_GETRANDOM replaced by platform_getrandom

; External functions — I/O goes through function pointer table (io_dispatch.asm)
extern io_read_fn
extern io_write_fn
extern encode_uint32
extern encode_string
extern encode_mpint
extern encode_mpint_be
extern decode_uint32
extern sha256
extern x25519
extern x25519_base
extern ssh_aead_encrypt
extern ssh_aead_decrypt
extern ssh_aead_decrypt_length
extern ed25519_sign
extern ed25519_pubkey
extern platform_getrandom
extern stack_probe

; SSH state structure offsets
%define SSH_STATE_K1_C2S     0      ; 32 bytes - chacha20 key pair client->server
%define SSH_STATE_K2_C2S     32     ; 32 bytes
%define SSH_STATE_SEQ_C2S    64     ; 4 bytes
%define SSH_STATE_K1_S2C     68     ; 32 bytes - chacha20 key pair server->client
%define SSH_STATE_K2_S2C     100    ; 32 bytes
%define SSH_STATE_SEQ_S2C    132    ; 4 bytes
%define SSH_STATE_SESSION_ID 136    ; 32 bytes
%define SSH_STATE_ROLE       168    ; 1 byte (0=client, 1=server)
%define SSH_STATE_SIZE       176

; Algorithm name strings
section .rodata
align 8
version_string:     db "SSH-2.0-OpenSSH_9.0", 13, 10
version_string_len  equ $ - version_string
version_id:         db "SSH-2.0-OpenSSH_9.0"
version_id_len      equ $ - version_id

kex_algo:           db "curve25519-sha256"
kex_algo_len        equ $ - kex_algo
host_key_algo:      db "ssh-ed25519"
host_key_algo_len   equ $ - host_key_algo
cipher_algo:        db "chacha20-poly1305@openssh.com"
cipher_algo_len     equ $ - cipher_algo
mac_algo:           db "hmac-sha2-256"
mac_algo_len        equ $ - mac_algo
compress_algo:      db "none"
compress_algo_len   equ $ - compress_algo

section .text

; ============================================================================
; ssh_send_version(edi=sock_fd) -> rax=0 success
; Sends "SSH-2.0-OpenSSH_9.0\r\n"
; ============================================================================
global ssh_send_version
ssh_send_version:
    lea rsi, [rel version_string]
    mov edx, version_string_len
    ; edi already has sock_fd — tail-call through I/O dispatch
    mov rax, [rel io_write_fn]
    jmp rax

; ============================================================================
; ssh_recv_version(edi=sock_fd, rsi=buf, edx=max_len) -> rax=version_len or -1
; Reads byte-by-byte until \n, stores version string (without \r\n) in buf
; ============================================================================
global ssh_recv_version
ssh_recv_version:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx, edi                ; sock_fd
    mov r12, rsi                ; output buffer
    mov r13d, edx               ; max_len
    xor r14d, r14d              ; bytes received
    sub rsp, 8                  ; 1-byte read buffer (aligned to 16 with 5 pushes + sub 8 = 48+8=56... need alignment)
    sub rsp, 8                  ; alignment pad (total: 5 pushes=40 + 16 = 56, but we need 16-aligned before call)

.recv_ver_loop:
    cmp r14d, r13d
    jge .recv_ver_fail          ; buffer full, no newline found

    ; Read 1 byte through I/O dispatch (supports raw TCP and TLS)
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 1
    mov rax, [rel io_read_fn]
    call rax
    test rax, rax
    jnz .recv_ver_fail          ; io_read_fn returns 0=success, -1=error

    movzx eax, byte [rsp]
    cmp al, 10                  ; '\n'
    je .recv_ver_done

    ; Store byte in output
    mov [r12 + r14], al
    inc r14d
    jmp .recv_ver_loop

.recv_ver_done:
    ; Strip trailing \r if present
    test r14d, r14d
    jz .recv_ver_return
    lea eax, [r14d - 1]
    cmp byte [r12 + rax], 13    ; '\r'
    jne .recv_ver_return
    dec r14d

.recv_ver_return:
    movzx rax, r14d             ; return length
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.recv_ver_fail:
    mov rax, -1
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_send_packet_plain(edi=sock_fd, rsi=payload, edx=payload_len) -> rax=0
; Sends unencrypted SSH packet: [pkt_len(4)][pad_len(1)][payload][padding]
; Block size = 8 for plaintext, minimum padding = 4
; ============================================================================
global ssh_send_packet_plain
ssh_send_packet_plain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax, SSH_MAX_PACKET_SIZE + 16
    call stack_probe
    sub rsp, SSH_MAX_PACKET_SIZE + 16  ; packet build buffer

    mov ebx, edi                ; sock_fd
    mov r12, rsi                ; payload pointer
    mov r13d, edx               ; payload_len

    ; Calculate padding:
    ; unpadded = 4 + 1 + payload_len
    ; padding = 8 - (unpadded % 8)
    ; if padding < 4: padding += 8
    lea eax, [r13d + 5]         ; unpadded = 4 + 1 + payload_len
    mov ecx, eax
    and ecx, 7                  ; unpadded % 8
    mov r14d, 8
    sub r14d, ecx               ; padding = 8 - (unpadded % 8)
    and r14d, 7                 ; handle case where remainder is 0
    cmp r14d, SSH_MIN_PADDING
    jge .pad_ok
    add r14d, 8
.pad_ok:

    ; pkt_len = 1 + payload_len + padding_len
    lea r15d, [r13d + 1]
    add r15d, r14d              ; r15d = pkt_len

    ; Build packet in buffer on stack
    ; [pkt_len(4 BE)][pad_len(1)][payload][padding(zeros)]
    lea rdi, [rsp]
    mov esi, r15d
    call encode_uint32          ; write pkt_len as BE uint32

    ; Write pad_len byte
    mov byte [rsp + 4], r14b

    ; Copy payload
    lea rdi, [rsp + 5]
    mov rsi, r12
    mov ecx, r13d
    rep movsb

    ; Zero padding bytes
    lea rdi, [rsp + 5]
    add rdi, r13                ; point past payload
    xor eax, eax
    mov ecx, r14d
    rep stosb

    ; Total wire bytes = 4 + pkt_len
    lea edx, [r15d + 4]        ; total length

    ; Send
    mov edi, ebx
    lea rsi, [rsp]
    mov rax, [rel io_write_fn]
    call rax

    add rsp, SSH_MAX_PACKET_SIZE + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_recv_packet_plain(edi=sock_fd, rsi=buf, edx=max_len) -> rax=payload_len or -1
; Receives unencrypted SSH packet, copies payload into buf
; ============================================================================
global ssh_recv_packet_plain
ssh_recv_packet_plain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax, SSH_MAX_PACKET_SIZE + 16
    call stack_probe
    sub rsp, SSH_MAX_PACKET_SIZE + 16

    mov ebx, edi                ; sock_fd
    mov r12, rsi                ; output buffer
    mov r13d, edx               ; max_len

    ; Read 4-byte packet length
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 4
    mov rax, [rel io_read_fn]
    call rax
    test rax, rax
    jnz .recv_plain_fail

    ; Decode pkt_len (big-endian)
    lea rdi, [rsp]
    call decode_uint32
    mov r14d, eax               ; r14d = pkt_len

    ; Sanity check
    cmp r14d, SSH_MAX_PACKET_SIZE
    ja .recv_plain_fail
    cmp r14d, 2                 ; minimum: 1 pad_len + 1 padding
    jb .recv_plain_fail

    ; Read pkt_len bytes
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, r14d
    mov rax, [rel io_read_fn]
    call rax
    test rax, rax
    jnz .recv_plain_fail

    ; Parse: [pad_len(1)][payload][padding]
    movzx r15d, byte [rsp]     ; pad_len
    ; payload_len = pkt_len - 1 - pad_len
    mov eax, r14d
    sub eax, 1
    sub eax, r15d
    js .recv_plain_fail         ; invalid if negative

    ; Check fits in output buffer
    cmp eax, r13d
    ja .recv_plain_fail

    ; Copy payload to output buffer
    mov ecx, eax
    push rax                    ; save payload_len
    lea rsi, [rsp + 8 + 1]     ; payload starts after pad_len byte (account for push)
    mov rdi, r12
    rep movsb
    pop rax                     ; restore payload_len

    add rsp, SSH_MAX_PACKET_SIZE + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.recv_plain_fail:
    mov rax, -1
    add rsp, SSH_MAX_PACKET_SIZE + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_send_packet_enc(edi=sock_fd, rsi=payload, edx=payload_len, rcx=state_ptr) -> rax=0
; Sends encrypted packet using chacha20-poly1305@openssh.com
; Uses c2s keys if role==client, s2c keys if role==server
; ============================================================================
; Stack layout for encrypted send/recv:
;   [rsp + 0                          ]: wire data buffer (SSH_MAX_PACKET_SIZE bytes)
;   [rsp + SSH_MAX_PACKET_SIZE        ]: plaintext/decrypted buffer (SSH_MAX_PACKET_SIZE bytes)
;   [rsp + SSH_MAX_PACKET_SIZE*2      ]: seq pointer (8 bytes)
;   [rsp + SSH_MAX_PACKET_SIZE*2 + 8  ]: padding_len (4 bytes)
;   [rsp + SSH_MAX_PACKET_SIZE*2 + 12 ]: pkt_len (4 bytes)
;   [rsp + SSH_MAX_PACKET_SIZE*2 + 16 ]: decrypt_length output (4 bytes)
;   [rsp + SSH_MAX_PACKET_SIZE*2 + 20 ]: saved pkt_len for recv (4 bytes)
%define ENC_FRAME_SIZE      (SSH_MAX_PACKET_SIZE * 2 + 64)
%define ENC_WIRE            0
%define ENC_PLAIN           SSH_MAX_PACKET_SIZE
%define ENC_SEQ_PTR         (SSH_MAX_PACKET_SIZE * 2)
%define ENC_PAD_LEN         (SSH_MAX_PACKET_SIZE * 2 + 8)
%define ENC_PKT_LEN         (SSH_MAX_PACKET_SIZE * 2 + 12)
%define ENC_DEC_LEN_OUT     (SSH_MAX_PACKET_SIZE * 2 + 16)
%define ENC_SAVED_PKTLEN    (SSH_MAX_PACKET_SIZE * 2 + 20)

global ssh_send_packet_enc
ssh_send_packet_enc:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, ENC_FRAME_SIZE
    call stack_probe
    sub rsp, ENC_FRAME_SIZE

    mov ebx, edi                ; sock_fd
    mov r12, rsi                ; payload
    mov r13d, edx               ; payload_len
    mov rbp, rcx                ; state_ptr

    ; Determine which key set to use for sending
    ; client sends with c2s keys, server sends with s2c keys
    movzx eax, byte [rbp + SSH_STATE_ROLE]
    test eax, eax
    jnz .send_enc_server_keys
    ; Client: use c2s
    lea r14, [rbp + SSH_STATE_K1_C2S]   ; k1
    lea r15, [rbp + SSH_STATE_K2_C2S]   ; k2
    lea rcx, [rbp + SSH_STATE_SEQ_C2S]  ; seq pointer
    jmp .send_enc_have_keys
.send_enc_server_keys:
    lea r14, [rbp + SSH_STATE_K1_S2C]
    lea r15, [rbp + SSH_STATE_K2_S2C]
    lea rcx, [rbp + SSH_STATE_SEQ_S2C]
.send_enc_have_keys:
    mov r8d, [rcx]              ; current seq number
    mov [rsp + ENC_SEQ_PTR], rcx  ; save seq pointer for increment

    ; Calculate padding (block size = 8 for chacha20-poly1305)
    ; unpadded = 1 + payload_len
    ; total = unpadded + padding must be multiple of 8, padding >= 4
    lea eax, [r13d + 1]        ; 1 + payload_len
    mov ecx, eax
    and ecx, 7
    mov edx, 8
    sub edx, ecx
    and edx, 7
    cmp edx, SSH_MIN_PADDING
    jge .send_enc_pad_ok
    add edx, 8
.send_enc_pad_ok:
    mov [rsp + ENC_PAD_LEN], edx  ; save padding_len

    ; pkt_len = 1 + payload_len + padding_len
    lea ecx, [r13d + 1]
    add ecx, edx               ; ecx = pkt_len
    mov [rsp + ENC_PKT_LEN], ecx  ; save pkt_len

    ; Build plaintext packet content: [pad_len(1)][payload][random_padding]
    ; into plaintext buffer at ENC_PLAIN
    lea rdi, [rsp + ENC_PLAIN]
    mov byte [rdi], dl          ; pad_len
    inc rdi
    ; Copy payload
    mov rsi, r12
    push rcx
    mov ecx, r13d
    rep movsb
    pop rcx

    ; Generate random padding
    ; rdi already points past payload
    mov esi, [rsp + ENC_PAD_LEN]  ; padding_len
    call platform_getrandom

    ; Encrypt: ssh_aead_encrypt(output, plaintext, pkt_len, k1, k2, seq)
    mov rax, [rsp + ENC_SEQ_PTR]   ; seq pointer
    mov r9d, [rax]                  ; seq number

    lea rdi, [rsp + ENC_WIRE]       ; output (wire buffer)
    lea rsi, [rsp + ENC_PLAIN]      ; plaintext content
    mov edx, [rsp + ENC_PKT_LEN]   ; pkt_len
    mov rcx, r14                    ; k1
    mov r8, r15                     ; k2
    ; r9d already set
    call ssh_aead_encrypt
    ; rax = total output bytes (4 + pkt_len + 16)
    mov r13d, eax               ; save wire length

    ; Send encrypted packet
    mov edi, ebx
    lea rsi, [rsp + ENC_WIRE]
    mov edx, r13d
    mov rax, [rel io_write_fn]
    call rax
    push rax                    ; save result

    ; Increment sequence number
    mov rcx, [rsp + ENC_SEQ_PTR + 8]  ; +8 for the push
    mov eax, [rcx]
    inc eax
    mov [rcx], eax

    pop rax                     ; restore write result

    add rsp, ENC_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_recv_packet_enc(edi=sock_fd, rsi=buf, edx=max_len, rcx=state_ptr) -> rax=payload_len or -1
; Receives encrypted packet, verifies MAC, decrypts, returns payload
; ============================================================================
global ssh_recv_packet_enc
ssh_recv_packet_enc:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, ENC_FRAME_SIZE
    call stack_probe
    sub rsp, ENC_FRAME_SIZE

    mov ebx, edi                ; sock_fd
    mov r12, rsi                ; output buffer
    mov r13d, edx               ; max_len
    mov rbp, rcx                ; state_ptr

    ; Determine recv keys (client recvs with s2c, server with c2s)
    movzx eax, byte [rbp + SSH_STATE_ROLE]
    test eax, eax
    jnz .recv_enc_server_keys
    ; Client: recv with s2c
    lea r14, [rbp + SSH_STATE_K1_S2C]
    lea r15, [rbp + SSH_STATE_K2_S2C]
    lea rcx, [rbp + SSH_STATE_SEQ_S2C]
    jmp .recv_enc_have_keys
.recv_enc_server_keys:
    lea r14, [rbp + SSH_STATE_K1_C2S]
    lea r15, [rbp + SSH_STATE_K2_C2S]
    lea rcx, [rbp + SSH_STATE_SEQ_C2S]
.recv_enc_have_keys:
    mov [rsp + ENC_SEQ_PTR], rcx   ; save seq pointer

    ; Step 1: Read 4 bytes (encrypted length)
    mov edi, ebx
    lea rsi, [rsp + ENC_WIRE]
    mov edx, 4
    mov rax, [rel io_read_fn]
    call rax
    test rax, rax
    jnz .recv_enc_fail

    ; Step 2: Decrypt length
    ; ssh_aead_decrypt_length(output4, enc4, k2, seq)
    lea rdi, [rsp + ENC_DEC_LEN_OUT]            ; output (4 bytes)
    lea rsi, [rsp + ENC_WIRE]                    ; encrypted length
    mov rdx, r15                                 ; k2
    mov rcx, [rsp + ENC_SEQ_PTR]                 ; seq pointer
    mov ecx, [rcx]                               ; seq number
    call ssh_aead_decrypt_length
    ; eax = pkt_len (host byte order)

    mov r8d, eax                ; save pkt_len
    ; Sanity check
    cmp r8d, SSH_MAX_PACKET_SIZE
    ja .recv_enc_fail
    cmp r8d, 2
    jb .recv_enc_fail
    mov [rsp + ENC_SAVED_PKTLEN], r8d   ; save pkt_len

    ; Step 3: Read pkt_len bytes (encrypted payload) + 16 bytes (MAC)
    lea edx, [r8d + 16]        ; bytes to read
    mov edi, ebx
    lea rsi, [rsp + ENC_WIRE + 4]   ; read after the 4-byte encrypted length
    mov rax, [rel io_read_fn]
    call rax
    test rax, rax
    jnz .recv_enc_fail

    ; Step 4: Decrypt full packet
    ; Total input to decrypt = 4 (enc_len) + pkt_len (enc_payload) + 16 (mac)
    mov r8d, [rsp + ENC_SAVED_PKTLEN]
    lea edx, [r8d + 20]        ; total_input_len

    ; ssh_aead_decrypt(output, input, total_len, k1, k2, seq)
    lea rdi, [rsp + ENC_PLAIN]                   ; decrypted output (full buffer)
    lea rsi, [rsp + ENC_WIRE]                     ; input (enc_len + enc_payload + mac)
    ; edx already set
    mov rcx, r14                                  ; k1
    mov r8, r15                                   ; k2
    mov r9, [rsp + ENC_SEQ_PTR]                   ; seq pointer
    mov r9d, [r9]                                 ; seq number
    call ssh_aead_decrypt
    ; rax = payload_len or -1

    cmp rax, -1
    je .recv_enc_fail

    ; rax = decrypted pkt_len bytes
    ; Content at ENC_PLAIN: [pad_len(1)][payload][padding]
    mov r8d, [rsp + ENC_SAVED_PKTLEN]             ; pkt_len
    movzx ecx, byte [rsp + ENC_PLAIN]             ; pad_len
    ; payload_len = pkt_len - 1 - pad_len
    mov eax, r8d
    sub eax, 1
    sub eax, ecx
    js .recv_enc_fail

    ; Check fits in output buffer
    cmp eax, r13d
    ja .recv_enc_fail

    ; Copy payload to output
    mov ecx, eax
    push rax
    lea rsi, [rsp + ENC_PLAIN + 1 + 8]  ; +8 for push, +1 for pad_len byte
    mov rdi, r12
    rep movsb
    pop rax

    ; Increment sequence number
    mov rcx, [rsp + ENC_SEQ_PTR]
    mov edx, [rcx]
    inc edx
    mov [rcx], edx

    add rsp, ENC_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.recv_enc_fail:
    mov rax, -1
    add rsp, ENC_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_build_kexinit(rdi=output) -> rax=payload_length
; Builds SSH_MSG_KEXINIT payload
; ============================================================================
global ssh_build_kexinit
ssh_build_kexinit:
    push rbx
    push r12
    push r13
    mov r12, rdi                ; output buffer
    mov r13, rdi                ; save start for length calculation

    ; byte 20 = SSH_MSG_KEXINIT
    mov byte [r12], SSH_MSG_KEXINIT
    inc r12

    ; 16 bytes random cookie
    mov rdi, r12
    mov esi, 16
    call platform_getrandom
    add r12, 16

    ; name-list: kex_algorithms = "curve25519-sha256"
    mov rdi, r12
    lea rsi, [rel kex_algo]
    mov edx, kex_algo_len
    call encode_string
    add r12, rax

    ; name-list: server_host_key_algorithms = "ssh-ed25519"
    mov rdi, r12
    lea rsi, [rel host_key_algo]
    mov edx, host_key_algo_len
    call encode_string
    add r12, rax

    ; name-list: encryption_algorithms_client_to_server = "chacha20-poly1305@openssh.com"
    mov rdi, r12
    lea rsi, [rel cipher_algo]
    mov edx, cipher_algo_len
    call encode_string
    add r12, rax

    ; name-list: encryption_algorithms_server_to_client = "chacha20-poly1305@openssh.com"
    mov rdi, r12
    lea rsi, [rel cipher_algo]
    mov edx, cipher_algo_len
    call encode_string
    add r12, rax

    ; name-list: mac_algorithms_client_to_server = "hmac-sha2-256"
    ; (never used with chacha20-poly1305 AEAD, but required for client compat)
    mov rdi, r12
    lea rsi, [rel mac_algo]
    mov edx, mac_algo_len
    call encode_string
    add r12, rax

    ; name-list: mac_algorithms_server_to_client = "hmac-sha2-256"
    mov rdi, r12
    lea rsi, [rel mac_algo]
    mov edx, mac_algo_len
    call encode_string
    add r12, rax

    ; name-list: compression_algorithms_client_to_server = "none"
    mov rdi, r12
    lea rsi, [rel compress_algo]
    mov edx, compress_algo_len
    call encode_string
    add r12, rax

    ; name-list: compression_algorithms_server_to_client = "none"
    mov rdi, r12
    lea rsi, [rel compress_algo]
    mov edx, compress_algo_len
    call encode_string
    add r12, rax

    ; name-list: languages_client_to_server = ""
    mov rdi, r12
    xor edx, edx
    xor esi, esi
    call encode_string
    add r12, rax

    ; name-list: languages_server_to_client = ""
    mov rdi, r12
    xor edx, edx
    xor esi, esi
    call encode_string
    add r12, rax

    ; boolean: first_kex_packet_follows = FALSE
    mov byte [r12], 0
    inc r12

    ; uint32: reserved = 0
    mov dword [r12], 0
    add r12, 4

    ; Return payload length
    mov rax, r12
    sub rax, r13

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_kex_client(edi=sock_fd, rsi=state_ptr) -> rax=0 success, -1 failure
;
; Full client-side key exchange:
;   1. Send/recv version strings
;   2. Build and send KEXINIT, recv server KEXINIT
;   3. Generate ephemeral X25519 keypair
;   4. Send SSH_MSG_KEX_ECDH_INIT
;   5. Recv SSH_MSG_KEX_ECDH_REPLY
;   6. Compute shared secret K via X25519
;   7. Compute exchange hash H
;   8. Derive session keys
;   9. Send/recv SSH_MSG_NEWKEYS
;   10. Populate state
;
; Stack layout (large frame ~8KB):
;   rsp+0      : work buffer (4096 bytes) for building packets/hash input
;   rsp+4096   : client version string (256 bytes)
;   rsp+4352   : server version string (256 bytes)
;   rsp+4608   : client KEXINIT payload (512 bytes)
;   rsp+5120   : server KEXINIT payload (512 bytes)
;   rsp+5632   : ephemeral private key (32 bytes)
;   rsp+5664   : ephemeral public key (32 bytes)
;   rsp+5696   : server ephemeral public key (32 bytes)
;   rsp+5728   : shared secret K (32 bytes)
;   rsp+5760   : server host key blob (256 bytes)
;   rsp+6016   : signature blob (256 bytes)
;   rsp+6272   : exchange hash H (32 bytes)
;   rsp+6304   : derived keys buffer (256 bytes)
;   rsp+6560   : client version len (4 bytes)
;   rsp+6564   : server version len (4 bytes)
;   rsp+6568   : client kexinit len (4 bytes)
;   rsp+6572   : server kexinit len (4 bytes)
;   rsp+6576   : server host key blob len (4 bytes)
;   rsp+6580   : signature blob len (4 bytes)
;   rsp+6584   : padding/alignment
;   Total:      ~6600 bytes, round to 6656 (0x1A00)
; ============================================================================

%define KEX_FRAME_SIZE      17408
%define KEX_WORK            0
%define KEX_V_C             4096
%define KEX_V_S             4352
%define KEX_I_C             4608       ; 4096 bytes (was 512)
%define KEX_I_S             8704       ; 4096 bytes (was 512) — OpenSSH KEXINIT ~2046 bytes
%define KEX_EPHEM_PRIV      12800
%define KEX_EPHEM_PUB       12832
%define KEX_SERVER_EPHEM    12864
%define KEX_SHARED_K        12896
%define KEX_HOST_KEY_BLOB   12928
%define KEX_SIG_BLOB        13184
%define KEX_HASH_H          13440
%define KEX_DERIVED_KEYS    13472
%define KEX_V_C_LEN         13728
%define KEX_V_S_LEN         13732
%define KEX_I_C_LEN         13736
%define KEX_I_S_LEN         13740
%define KEX_HOST_KEY_LEN    13744
%define KEX_SIG_LEN         13748

global ssh_kex_client
ssh_kex_client:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, KEX_FRAME_SIZE
    call stack_probe
    sub rsp, KEX_FRAME_SIZE

    mov ebx, edi                ; sock_fd
    mov rbp, rsi                ; state_ptr
    mov byte [rbp + SSH_STATE_ROLE], 0  ; client role

    ; === Step 1: Exchange version strings ===

    ; Send our version
    mov edi, ebx
    call ssh_send_version
    test rax, rax
    jnz .kex_fail

    ; Save our version identifier (without \r\n) for hash
    lea rdi, [rsp + KEX_V_C]
    lea rsi, [rel version_id]
    mov ecx, version_id_len
    rep movsb
    mov dword [rsp + KEX_V_C_LEN], version_id_len

    ; Receive server version
    mov edi, ebx
    lea rsi, [rsp + KEX_V_S]
    mov edx, 255
    call ssh_recv_version
    cmp rax, -1
    je .kex_fail
    mov [rsp + KEX_V_S_LEN], eax

    ; === Step 2: Exchange KEXINIT ===

    ; Build our KEXINIT
    lea rdi, [rsp + KEX_I_C]
    call ssh_build_kexinit
    mov [rsp + KEX_I_C_LEN], eax

    ; Send KEXINIT as plaintext packet
    mov edi, ebx
    lea rsi, [rsp + KEX_I_C]
    mov edx, [rsp + KEX_I_C_LEN]
    call ssh_send_packet_plain
    test rax, rax
    jnz .kex_fail

    ; Receive server KEXINIT
    mov edi, ebx
    lea rsi, [rsp + KEX_I_S]
    mov edx, 4096
    call ssh_recv_packet_plain
    cmp rax, -1
    je .kex_fail
    mov [rsp + KEX_I_S_LEN], eax

    ; Verify it's a KEXINIT (byte 0 = 20)
    cmp byte [rsp + KEX_I_S], SSH_MSG_KEXINIT
    jne .kex_fail

    ; === Step 3: Generate ephemeral X25519 keypair ===

    ; Generate 32 random bytes for private key
    lea rdi, [rsp + KEX_EPHEM_PRIV]
    mov esi, 32
    call platform_getrandom
    cmp rax, 32
    jne .kex_fail

    ; Clamp private key per RFC 7748
    and byte [rsp + KEX_EPHEM_PRIV], 0xF8
    and byte [rsp + KEX_EPHEM_PRIV + 31], 0x7F
    or  byte [rsp + KEX_EPHEM_PRIV + 31], 0x40

    ; Compute public key = x25519_base(priv)
    lea rdi, [rsp + KEX_EPHEM_PUB]
    lea rsi, [rsp + KEX_EPHEM_PRIV]
    call x25519_base

    ; === Step 4: Send SSH_MSG_KEX_ECDH_INIT ===
    ; Payload: [byte 30][string: client_ephemeral_pubkey(32)]

    lea rdi, [rsp + KEX_WORK]
    mov byte [rdi], SSH_MSG_KEX_ECDH_INIT
    lea rdi, [rsp + KEX_WORK + 1]
    lea rsi, [rsp + KEX_EPHEM_PUB]
    mov edx, 32
    call encode_string          ; writes 4+32 = 36 bytes
    ; Total payload = 1 + 36 = 37

    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 37
    call ssh_send_packet_plain
    test rax, rax
    jnz .kex_fail

    ; === Step 5: Recv SSH_MSG_KEX_ECDH_REPLY ===
    ; Payload: [byte 31][string K_S][string server_ephem][string sig]

    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 4096
    call ssh_recv_packet_plain
    cmp rax, -1
    je .kex_fail
    mov r13d, eax               ; total reply payload length

    ; Verify message type
    cmp byte [rsp + KEX_WORK], SSH_MSG_KEX_ECDH_REPLY
    jne .kex_fail

    ; Parse K_S (server host key blob)
    lea rdi, [rsp + KEX_WORK + 1]
    call decode_uint32          ; eax = K_S length
    mov r14d, eax               ; host key blob length
    mov [rsp + KEX_HOST_KEY_LEN], eax

    ; Copy host key blob
    cmp r14d, 256
    ja .kex_fail
    lea rsi, [rsp + KEX_WORK + 5]   ; data after type(1) + len(4)
    lea rdi, [rsp + KEX_HOST_KEY_BLOB]
    mov ecx, r14d
    rep movsb

    ; Parse server ephemeral public key (string after K_S)
    ; Offset: 1 + 4 + K_S_len + 4 (string header for ephem)
    lea r15d, [r14d + 5]       ; offset past type + K_S string
    lea rdi, [rsp + KEX_WORK]
    add rdi, r15                ; points to string length of server_ephem
    call decode_uint32          ; eax = ephem key length
    cmp eax, 32
    jne .kex_fail

    ; Copy server ephemeral key
    lea rsi, [rsp + KEX_WORK]
    add rsi, r15
    add rsi, 4                  ; past string length
    lea rdi, [rsp + KEX_SERVER_EPHEM]
    mov ecx, 32
    rep movsb

    ; Parse signature blob
    ; Offset: 1 + 4 + K_S_len + 4 + 32
    lea r15d, [r14d + 5 + 4 + 32]
    lea rdi, [rsp + KEX_WORK]
    add rdi, r15
    call decode_uint32          ; eax = sig blob length
    mov [rsp + KEX_SIG_LEN], eax
    cmp eax, 256
    ja .kex_fail

    ; Copy signature blob
    lea rsi, [rsp + KEX_WORK]
    add rsi, r15
    add rsi, 4
    lea rdi, [rsp + KEX_SIG_BLOB]
    mov ecx, [rsp + KEX_SIG_LEN]
    rep movsb

    ; === Step 6: Compute shared secret K ===
    ; K = x25519(our_private, server_ephemeral)
    lea rdi, [rsp + KEX_SHARED_K]
    lea rsi, [rsp + KEX_EPHEM_PRIV]
    lea rdx, [rsp + KEX_SERVER_EPHEM]
    call x25519

    ; === Step 7: Compute exchange hash H ===
    ; H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
    ; All encoded as strings (with uint32 length prefix), K as mpint
    ; Build in KEX_WORK buffer

    xor r13d, r13d              ; offset into work buffer

    ; V_C (client version string)
    lea rdi, [rsp + KEX_WORK]
    lea rsi, [rsp + KEX_V_C]
    mov edx, [rsp + KEX_V_C_LEN]
    call encode_string
    add r13d, eax

    ; V_S (server version string)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_V_S]
    mov edx, [rsp + KEX_V_S_LEN]
    call encode_string
    add r13d, eax

    ; I_C (client KEXINIT payload — includes msg type byte)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_I_C]
    mov edx, [rsp + KEX_I_C_LEN]
    call encode_string
    add r13d, eax

    ; I_S (server KEXINIT payload)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_I_S]
    mov edx, [rsp + KEX_I_S_LEN]
    call encode_string
    add r13d, eax

    ; K_S (server host key blob)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_HOST_KEY_BLOB]
    mov edx, [rsp + KEX_HOST_KEY_LEN]
    call encode_string
    add r13d, eax

    ; e (client ephemeral public key, as string)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_EPHEM_PUB]
    mov edx, 32
    call encode_string
    add r13d, eax

    ; f (server ephemeral public key, as string)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_SERVER_EPHEM]
    mov edx, 32
    call encode_string
    add r13d, eax

    ; K (shared secret as mpint — raw X25519 output treated as BE per OpenSSH convention)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_SHARED_K]
    mov edx, 32
    call encode_mpint_be
    add r13d, eax

    ; SHA-256 the whole thing
    lea rdi, [rsp + KEX_WORK]
    movzx rsi, r13d             ; length
    lea rdx, [rsp + KEX_HASH_H]
    call sha256

    ; Session ID = H (on first kex)
    lea rsi, [rsp + KEX_HASH_H]
    lea rdi, [rbp + SSH_STATE_SESSION_ID]
    mov ecx, 32
    rep movsb

    ; === Step 8: Skip host key verification (TOFU) ===

    ; === Step 9: Derive session keys ===
    ; For chacha20-poly1305@openssh.com, 64 bytes per direction
    ; key = SHA-256(K_mpint || H || letter || session_id) first 32 bytes
    ;     + SHA-256(K_mpint || H || first_32_bytes) next 32 bytes
    ;
    ; C2S (client to server): letter = 'C' (0x43) -> K1+K2 at state+0
    ; S2C (server to client): letter = 'D' (0x44) -> K1+K2 at state+68

    ; First, encode K as mpint once into KEX_DERIVED_KEYS area (temp)
    ; We need K_mpint for each derivation. Build it at work+0
    lea rdi, [rsp + KEX_WORK]
    lea rsi, [rsp + KEX_SHARED_K]
    mov edx, 32
    call encode_mpint_be
    mov r14d, eax               ; r14d = K_mpint length

    ; Derive C2S key (64 bytes) with letter 'C'
    lea rdi, [rbp + SSH_STATE_K1_C2S]
    mov sil, 0x43               ; 'C'
    call .derive_key_64

    ; Derive S2C key (64 bytes) with letter 'D'
    lea rdi, [rbp + SSH_STATE_K1_S2C]
    mov sil, 0x44               ; 'D'
    call .derive_key_64

    ; Set sequence numbers to post-NEWKEYS values.
    ; Client sent: KEXINIT(0), ECDH_INIT(1), NEWKEYS(2) -> next=3
    ; Client recv: KEXINIT(0), ECDH_REPLY(1), NEWKEYS(2) -> next=3
    mov dword [rbp + SSH_STATE_SEQ_C2S], 3
    mov dword [rbp + SSH_STATE_SEQ_S2C], 3

    ; === Step 10: Send/recv SSH_MSG_NEWKEYS ===

    ; Send NEWKEYS (payload = single byte 21)
    lea rdi, [rsp + KEX_WORK]
    mov byte [rdi], SSH_MSG_NEWKEYS
    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 1
    call ssh_send_packet_plain
    test rax, rax
    jnz .kex_fail

    ; Recv NEWKEYS
    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 256
    call ssh_recv_packet_plain
    cmp rax, -1
    je .kex_fail
    cmp byte [rsp + KEX_WORK], SSH_MSG_NEWKEYS
    jne .kex_fail

    ; Success
    xor eax, eax
    jmp .kex_done

.kex_fail:
    mov rax, -1

.kex_done:
    add rsp, KEX_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; Internal: derive_key_64 - derives 64 bytes of key material
; Input: rdi = output (64 bytes), sil = letter byte
;        Uses stack-frame locals: KEX_WORK has K_mpint at offset 0 (r14d bytes)
;        KEX_HASH_H has exchange hash H
;        state_ptr (rbp) has session_id
; Clobbers: all caller-saved regs
; ---------------------------------------------------------------------------
.derive_key_64:
    push rbx
    push r12
    push r13
    push r15
    mov r12, rdi                ; output pointer
    movzx r13d, sil             ; letter

    ; Build hash input: K_mpint || H || letter || session_id
    ; rsp is 40 bytes below kex frame (4 pushes + call return address)
    ; Build in KEX_WORK+256 (safe area not overlapping K_mpint at offset 0)
    lea r15, [rsp + 40 + KEX_WORK + 256]

    ; Copy K_mpint
    mov rdi, r15
    lea rsi, [rsp + 40 + KEX_WORK]          ; K_mpint source
    mov ecx, r14d
    rep movsb
    ; rdi now points past K_mpint

    ; Copy H (32 bytes)
    lea rsi, [rsp + 40 + KEX_HASH_H]
    mov ecx, 32
    rep movsb

    ; Letter byte
    mov [rdi], r13b
    inc rdi

    ; Session ID (32 bytes)
    lea rsi, [rbp + SSH_STATE_SESSION_ID]
    mov ecx, 32
    rep movsb

    ; Total hash input length = r14d + 32 + 1 + 32
    lea ebx, [r14d + 65]       ; hash input length

    ; First 32 bytes: SHA-256(K_mpint || H || letter || session_id)
    mov rdi, r15                ; message
    movzx rsi, ebx             ; length
    mov rdx, r12                ; output first 32 bytes
    call sha256

    ; Second 32 bytes: SHA-256(K_mpint || H || first_32_bytes)
    ; Build: K_mpint || H || key_so_far(32)
    ; Reuse r15 buffer, overwrite from K_mpint
    mov rdi, r15
    lea rsi, [rsp + 40 + KEX_WORK]   ; K_mpint
    mov ecx, r14d
    rep movsb

    lea rsi, [rsp + 40 + KEX_HASH_H]
    mov ecx, 32
    rep movsb

    ; Append first 32 bytes of derived key
    mov rsi, r12
    mov ecx, 32
    rep movsb

    ; Hash input length = r14d + 32 + 32
    lea ebx, [r14d + 64]

    mov rdi, r15
    movzx rsi, ebx
    lea rdx, [r12 + 32]        ; output bytes 32-63
    call sha256

    pop r15
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; ssh_kex_server(edi=sock_fd, rsi=state_ptr, rdx=host_key_64bytes) -> rax=0 success, -1 failure
;   host_key_64bytes = 32-byte Ed25519 private key + 32-byte public key
;
; Server-side key exchange (mirror of ssh_kex_client):
;   1. Recv client version, send our version
;   2. Recv client KEXINIT, build and send our KEXINIT
;   3. Recv SSH_MSG_KEX_ECDH_INIT (client ephemeral pub key)
;   4. Generate ephemeral X25519 keypair
;   5. Compute shared secret K = x25519(our_priv, client_ephem_pub)
;   6. Build exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
;   7. Sign H with host key (Ed25519)
;   8. Send SSH_MSG_KEX_ECDH_REPLY with host_key_blob + server_ephem_pub + signature
;   9. Derive session keys (same as client but role=server)
;   10. Send/recv SSH_MSG_NEWKEYS
;
; Stack layout: reuses KEX_FRAME_SIZE layout from client
;   Additional server-specific storage carved from KEX_DERIVED_KEYS area:
;   We extend the frame by 256 bytes for:
;     KEX_HOST_KEY_PTR (8 bytes) - saved host key pointer
;     KEX_SIG_OUT (64 bytes) - Ed25519 signature output
;     KEX_CLIENT_EPHEM (32 bytes) - client ephemeral public key
; ============================================================================

%define SRVKEX_FRAME_SIZE      17920    ; KEX_FRAME_SIZE + 512 extra
%define SRVKEX_HOST_KEY_PTR    17408    ; 8 bytes
%define SRVKEX_SIG_OUT         17416    ; 64 bytes
%define SRVKEX_CLIENT_EPHEM    17480    ; 32 bytes

global ssh_kex_server
ssh_kex_server:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, SRVKEX_FRAME_SIZE
    call stack_probe
    sub rsp, SRVKEX_FRAME_SIZE

    mov ebx, edi                ; sock_fd
    mov rbp, rsi                ; state_ptr
    mov [rsp + SRVKEX_HOST_KEY_PTR], rdx  ; save host key pointer
    mov byte [rbp + SSH_STATE_ROLE], 1     ; server role

    ; === Step 1: Exchange version strings (server sends first per RFC 4253) ===

    ; Send our version first
    mov edi, ebx
    call ssh_send_version
    test rax, rax
    jnz .skex_fail

    ; Save our version identifier for hash
    lea rdi, [rsp + KEX_V_S]
    lea rsi, [rel version_id]
    mov ecx, version_id_len
    rep movsb
    mov dword [rsp + KEX_V_S_LEN], version_id_len

    ; Receive client version
    mov edi, ebx
    lea rsi, [rsp + KEX_V_C]
    mov edx, 255
    call ssh_recv_version
    cmp rax, -1
    je .skex_fail
    mov [rsp + KEX_V_C_LEN], eax

    ; === Step 2: Exchange KEXINIT (server sends first per RFC 4253) ===

    ; Build our KEXINIT
    lea rdi, [rsp + KEX_I_S]
    call ssh_build_kexinit
    mov [rsp + KEX_I_S_LEN], eax

    ; Send KEXINIT first
    mov edi, ebx
    lea rsi, [rsp + KEX_I_S]
    mov edx, [rsp + KEX_I_S_LEN]
    call ssh_send_packet_plain
    test rax, rax
    jnz .skex_fail

    ; Receive client KEXINIT
    mov edi, ebx
    lea rsi, [rsp + KEX_I_C]
    mov edx, 4096
    call ssh_recv_packet_plain
    cmp rax, -1
    je .skex_fail
    mov [rsp + KEX_I_C_LEN], eax

    ; Verify it's a KEXINIT
    cmp byte [rsp + KEX_I_C], SSH_MSG_KEXINIT
    jne .skex_fail

    ; === Step 3: Recv SSH_MSG_KEX_ECDH_INIT (client ephemeral pub key) ===

    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 4096
    call ssh_recv_packet_plain
    cmp rax, -1
    je .skex_fail

    ; Verify message type
    cmp byte [rsp + KEX_WORK], SSH_MSG_KEX_ECDH_INIT
    jne .skex_fail

    ; Parse client ephemeral public key: [byte 30][string(32 bytes)]
    lea rdi, [rsp + KEX_WORK + 1]
    call decode_uint32
    cmp eax, 32
    jne .skex_fail

    ; Copy client ephemeral public key
    lea rsi, [rsp + KEX_WORK + 5]
    lea rdi, [rsp + SRVKEX_CLIENT_EPHEM]
    mov ecx, 32
    rep movsb

    ; === Step 4: Generate ephemeral X25519 keypair ===

    lea rdi, [rsp + KEX_EPHEM_PRIV]
    mov esi, 32
    call platform_getrandom
    cmp rax, 32
    jne .skex_fail

    ; Clamp private key per RFC 7748
    and byte [rsp + KEX_EPHEM_PRIV], 0xF8
    and byte [rsp + KEX_EPHEM_PRIV + 31], 0x7F
    or  byte [rsp + KEX_EPHEM_PRIV + 31], 0x40

    ; Compute public key
    lea rdi, [rsp + KEX_EPHEM_PUB]
    lea rsi, [rsp + KEX_EPHEM_PRIV]
    call x25519_base

    ; === Step 5: Compute shared secret K ===
    ; K = x25519(our_private, client_ephemeral)
    lea rdi, [rsp + KEX_SHARED_K]
    lea rsi, [rsp + KEX_EPHEM_PRIV]
    lea rdx, [rsp + SRVKEX_CLIENT_EPHEM]
    call x25519

    ; === Step 6: Build exchange hash H ===
    ; H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
    ; V_C = client version, V_S = server version
    ; I_C = client KEXINIT, I_S = server KEXINIT
    ; K_S = host key blob, e = client ephem, f = server ephem, K = shared secret (mpint)

    ; First, build the host key blob: string("ssh-ed25519") + string(pubkey_32)
    ; Build in KEX_HOST_KEY_BLOB
    lea rdi, [rsp + KEX_HOST_KEY_BLOB]
    lea rsi, [rel host_key_algo]
    mov edx, host_key_algo_len
    call encode_string
    mov r13d, eax               ; offset into host key blob

    lea rdi, [rsp + KEX_HOST_KEY_BLOB]
    add rdi, r13
    mov rsi, [rsp + SRVKEX_HOST_KEY_PTR]
    add rsi, 32                 ; public key is second 32 bytes
    mov edx, 32
    call encode_string
    add r13d, eax
    mov [rsp + KEX_HOST_KEY_LEN], r13d  ; total host key blob length

    ; Build hash input in KEX_WORK
    xor r13d, r13d

    ; V_C (client version)
    lea rdi, [rsp + KEX_WORK]
    lea rsi, [rsp + KEX_V_C]
    mov edx, [rsp + KEX_V_C_LEN]
    call encode_string
    add r13d, eax

    ; V_S (server version)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_V_S]
    mov edx, [rsp + KEX_V_S_LEN]
    call encode_string
    add r13d, eax

    ; I_C (client KEXINIT payload)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_I_C]
    mov edx, [rsp + KEX_I_C_LEN]
    call encode_string
    add r13d, eax

    ; I_S (server KEXINIT payload)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_I_S]
    mov edx, [rsp + KEX_I_S_LEN]
    call encode_string
    add r13d, eax

    ; K_S (host key blob)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_HOST_KEY_BLOB]
    mov edx, [rsp + KEX_HOST_KEY_LEN]
    call encode_string
    add r13d, eax

    ; e (client ephemeral public key, as string)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + SRVKEX_CLIENT_EPHEM]
    mov edx, 32
    call encode_string
    add r13d, eax

    ; f (server ephemeral public key, as string)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_EPHEM_PUB]
    mov edx, 32
    call encode_string
    add r13d, eax

    ; K (shared secret as mpint — raw X25519 treated as BE per OpenSSH)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_SHARED_K]
    mov edx, 32
    call encode_mpint_be
    add r13d, eax

    ; SHA-256 the whole thing
    lea rdi, [rsp + KEX_WORK]
    movzx rsi, r13d
    lea rdx, [rsp + KEX_HASH_H]
    call sha256

    ; Session ID = H (on first kex)
    lea rsi, [rsp + KEX_HASH_H]
    lea rdi, [rbp + SSH_STATE_SESSION_ID]
    mov ecx, 32
    rep movsb

    ; === Step 7: Sign H with host key (Ed25519) ===
    ; ed25519_sign(rdi=sig64_out, rsi=msg, rdx=msg_len, rcx=keypair64)
    lea rdi, [rsp + SRVKEX_SIG_OUT]
    lea rsi, [rsp + KEX_HASH_H]
    mov edx, 32
    mov rcx, [rsp + SRVKEX_HOST_KEY_PTR]
    call ed25519_sign

    ; === Step 8: Send SSH_MSG_KEX_ECDH_REPLY ===
    ; Payload: [byte 31][string K_S][string f][string sig_blob]
    ; sig_blob = string("ssh-ed25519") + string(raw_sig_64)

    ; Build signature blob in KEX_SIG_BLOB
    lea rdi, [rsp + KEX_SIG_BLOB]
    lea rsi, [rel host_key_algo]
    mov edx, host_key_algo_len
    call encode_string
    mov r14d, eax               ; offset into sig blob

    lea rdi, [rsp + KEX_SIG_BLOB]
    add rdi, r14
    lea rsi, [rsp + SRVKEX_SIG_OUT]
    mov edx, 64
    call encode_string
    add r14d, eax
    mov [rsp + KEX_SIG_LEN], r14d   ; total sig blob length

    ; Build ECDH_REPLY payload in KEX_WORK
    lea rdi, [rsp + KEX_WORK]
    mov byte [rdi], SSH_MSG_KEX_ECDH_REPLY
    xor r13d, r13d
    inc r13d                    ; r13d = 1 (past msg type byte)

    ; string K_S (host key blob)
    lea rdi, [rsp + KEX_WORK + 1]
    lea rsi, [rsp + KEX_HOST_KEY_BLOB]
    mov edx, [rsp + KEX_HOST_KEY_LEN]
    call encode_string
    add r13d, eax

    ; string f (server ephemeral public key)
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_EPHEM_PUB]
    mov edx, 32
    call encode_string
    add r13d, eax

    ; string sig_blob
    lea rdi, [rsp + KEX_WORK]
    add rdi, r13
    lea rsi, [rsp + KEX_SIG_BLOB]
    mov edx, [rsp + KEX_SIG_LEN]
    call encode_string
    add r13d, eax

    ; Send ECDH_REPLY
    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, r13d
    call ssh_send_packet_plain
    test rax, rax
    jnz .skex_fail

    ; === Step 9: Derive session keys ===
    ; Encode K as mpint into KEX_WORK (for key derivation, BE per OpenSSH)
    lea rdi, [rsp + KEX_WORK]
    lea rsi, [rsp + KEX_SHARED_K]
    mov edx, 32
    call encode_mpint_be
    mov r14d, eax               ; r14d = K_mpint length

    ; Derive C2S key (64 bytes) with letter 'C'
    lea rdi, [rbp + SSH_STATE_K1_C2S]
    mov sil, 0x43
    call .skex_derive_key_64

    ; Derive S2C key (64 bytes) with letter 'D'
    lea rdi, [rbp + SSH_STATE_K1_S2C]
    mov sil, 0x44
    call .skex_derive_key_64

    ; NOTE: Do NOT reset sequence numbers here.
    ; They continue from the plaintext exchange (KEXINIT, ECDH, NEWKEYS).
    ; The ssh_send_packet_plain/ssh_recv_packet_plain functions don't
    ; update state->seq, so we set them to the correct post-NEWKEYS values.
    ; Server sent: KEXINIT(0), ECDH_REPLY(1), NEWKEYS(2) -> next=3
    ; Server recv: KEXINIT(0), ECDH_INIT(1), NEWKEYS(2) -> next=3
    mov dword [rbp + SSH_STATE_SEQ_S2C], 3
    mov dword [rbp + SSH_STATE_SEQ_C2S], 3

    ; === Step 10: Send/recv SSH_MSG_NEWKEYS (server sends first, then receives) ===

    ; Send NEWKEYS
    lea rdi, [rsp + KEX_WORK]
    mov byte [rdi], SSH_MSG_NEWKEYS
    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 1
    call ssh_send_packet_plain
    test rax, rax
    jnz .skex_fail

    ; Recv NEWKEYS
    mov edi, ebx
    lea rsi, [rsp + KEX_WORK]
    mov edx, 256
    call ssh_recv_packet_plain
    cmp rax, -1
    je .skex_fail
    cmp byte [rsp + KEX_WORK], SSH_MSG_NEWKEYS
    jne .skex_fail

    ; Success
    xor eax, eax
    jmp .skex_done

.skex_fail:
    mov rax, -1

.skex_done:
    add rsp, SRVKEX_FRAME_SIZE
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; Internal: skex_derive_key_64 - derives 64 bytes of key material (server version)
; Input: rdi = output (64 bytes), sil = letter byte
;        Uses stack-frame locals: KEX_WORK has K_mpint at offset 0 (r14d bytes)
;        KEX_HASH_H has exchange hash H
;        state_ptr (rbp) has session_id
; Clobbers: all caller-saved regs
; ---------------------------------------------------------------------------
.skex_derive_key_64:
    push rbx
    push r12
    push r13
    push r15
    mov r12, rdi                ; output pointer
    movzx r13d, sil             ; letter

    ; Build hash input: K_mpint || H || letter || session_id
    ; rsp is 40 bytes below kex frame (4 pushes + call return address)
    ; Build in KEX_WORK+256 (safe area not overlapping K_mpint at offset 0)
    lea r15, [rsp + 40 + KEX_WORK + 256]

    ; Copy K_mpint
    mov rdi, r15
    lea rsi, [rsp + 40 + KEX_WORK]
    mov ecx, r14d
    rep movsb

    ; Copy H (32 bytes)
    lea rsi, [rsp + 40 + KEX_HASH_H]
    mov ecx, 32
    rep movsb

    ; Letter byte
    mov [rdi], r13b
    inc rdi

    ; Session ID (32 bytes)
    lea rsi, [rbp + SSH_STATE_SESSION_ID]
    mov ecx, 32
    rep movsb

    ; Total hash input length = r14d + 32 + 1 + 32
    lea ebx, [r14d + 65]

    ; First 32 bytes
    mov rdi, r15
    movzx rsi, ebx
    mov rdx, r12
    call sha256

    ; Second 32 bytes: SHA-256(K_mpint || H || first_32_bytes)
    mov rdi, r15
    lea rsi, [rsp + 40 + KEX_WORK]
    mov ecx, r14d
    rep movsb

    lea rsi, [rsp + 40 + KEX_HASH_H]
    mov ecx, 32
    rep movsb

    mov rsi, r12
    mov ecx, 32
    rep movsb

    lea ebx, [r14d + 64]

    mov rdi, r15
    movzx rsi, ebx
    lea rdx, [r12 + 32]
    call sha256

    pop r15
    pop r13
    pop r12
    pop rbx
    ret
