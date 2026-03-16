; tls13.asm — TLS 1.3 client handshake (1-RTT)
; Cipher suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
; Key exchange: X25519
; Simplifications: no PSK, no cert verification (TOFU), no HelloRetryRequest

%include "ssh.inc"
%include "tls.inc"
; syscall.inc no longer needed — SYS_GETRANDOM replaced by platform_getrandom

; Config symbols (defined in config.inc, included by main.asm)
extern sni_hostname
extern sni_hostname_len

extern tls_record_write_plain
extern tls_record_read_plain
extern tls_record_write_enc
extern tls_record_read_enc
extern x25519
extern x25519_base
extern sha256
extern hmac_sha256
extern hkdf_extract
extern hkdf_expand_label
extern derive_secret
extern platform_getrandom
extern stack_probe

section .data
align 16
; Labels for key schedule
label_derived:      db "derived"
label_derived_len   equ 7
label_c_hs_traffic: db "c hs traffic"
label_c_hs_len      equ 12
label_s_hs_traffic: db "s hs traffic"
label_s_hs_len      equ 12
label_c_ap_traffic: db "c ap traffic"
label_c_ap_len      equ 12
label_s_ap_traffic: db "s ap traffic"
label_s_ap_len      equ 12
label_key:          db "key"
label_key_len       equ 3
label_iv:           db "iv"
label_iv_len        equ 2
label_finished:     db "finished"
label_finished_len  equ 8

; 32 zero bytes for IKM/salt
zero_ikm: times 32 db 0

section .text
global tls13_handshake

; =============================================================================
; tls13_handshake(edi=sock_fd, rsi=tls_state_ptr) -> rax=0 or -1
;
; Performs full TLS 1.3 1-RTT client handshake.
; On success, tls_state is populated with application read/write keys.
; =============================================================================
;
; Stack frame — large, ~12KB for transcript buffer and key material.
; All offsets relative to rbp:
;
; Saved registers: rbp-8..rbp-40 (rbx, r12-r15)
; Local variables:
;   rbp-44          sock_fd (4 bytes)
;   rbp-52          tls_state_ptr (8 bytes)
;   rbp-84          client_private_key (32 bytes) [rbp-84..rbp-53]
;   rbp-116         client_public_key (32 bytes) [rbp-116..rbp-85]
;   rbp-148         server_public_key (32 bytes) [rbp-148..rbp-117]
;   rbp-180         shared_secret (32 bytes) [rbp-180..rbp-149]
;   rbp-212         early_secret (32 bytes) [rbp-212..rbp-181]
;   rbp-244         derived_secret_1 (32 bytes) [rbp-244..rbp-213]
;   rbp-276         handshake_secret (32 bytes) [rbp-276..rbp-245]
;   rbp-308         client_hs_traffic (32 bytes) [rbp-308..rbp-277]
;   rbp-340         server_hs_traffic (32 bytes) [rbp-340..rbp-309]
;   rbp-372         derived_secret_2 (32 bytes) [rbp-372..rbp-341]
;   rbp-404         master_secret (32 bytes) [rbp-404..rbp-373]
;   rbp-436         client_app_traffic (32 bytes) [rbp-436..rbp-405]
;   rbp-468         server_app_traffic (32 bytes) [rbp-468..rbp-437]
;   rbp-500         temp_key (32 bytes) [rbp-500..rbp-469]
;   rbp-512         temp_iv (12 bytes) [rbp-512..rbp-501]
;   rbp-544         finished_key (32 bytes) [rbp-544..rbp-513]
;   rbp-576         expected_verify (32 bytes) [rbp-576..rbp-545]
;   rbp-608         transcript_hash (32 bytes) [rbp-608..rbp-577]
;   rbp-612         transcript_len (4 bytes)
;   rbp-8804        transcript_buf (8192 bytes) [rbp-8804..rbp-613]
;   rbp-25188       record_buf (16384 bytes) [rbp-25188..rbp-8805]
;   rbp-25192       client_hello_len (4 bytes)
;   rbp-25196       server_finished_transcript_len (4 bytes)
;
FRAME_SIZE equ 25200

tls13_handshake:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax, FRAME_SIZE
    call stack_probe
    sub rsp, FRAME_SIZE

    mov [rbp-44], edi           ; sock_fd
    mov [rbp-52], rsi           ; tls_state_ptr
    mov dword [rbp-612], 0      ; transcript_len = 0

    ; ===== Step 1: Generate ephemeral X25519 keypair =====
    ; Get 32 random bytes for private key
    lea rdi, [rbp-84]           ; buffer = client_private_key
    mov esi, 32
    call platform_getrandom
    cmp rax, 32
    jne .hs_fail

    ; Compute public key: x25519_base(output, scalar)
    lea rdi, [rbp-116]          ; output = client_public_key
    lea rsi, [rbp-84]           ; scalar = client_private_key
    call x25519_base

    ; ===== Step 2: Build ClientHello =====
    ; Build it in record_buf, then send as plaintext record
    lea rdi, [rbp-25188]        ; record_buf = build target

    ; Handshake header: type=1 (ClientHello), length filled later
    mov byte [rdi], TLS_HS_CLIENT_HELLO
    add rdi, 4                  ; skip type(1) + length(3), fill length later

    ; ProtocolVersion: 0x03 0x03 (legacy TLS 1.2)
    mov byte [rdi], 0x03
    mov byte [rdi+1], 0x03
    add rdi, 2

    ; Random: 32 random bytes
    push rdi
    ; rdi already points to target buffer
    mov esi, 32
    call platform_getrandom
    pop rdi
    add rdi, 32

    ; Session ID length: 0 (no legacy session ID)
    mov byte [rdi], 0
    inc rdi

    ; Cipher suites: length=2, TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    mov byte [rdi], 0x00
    mov byte [rdi+1], 0x02
    mov byte [rdi+2], 0x13
    mov byte [rdi+3], 0x03
    add rdi, 4

    ; Compression methods: length=1, null(0)
    mov byte [rdi], 0x01
    mov byte [rdi+1], 0x00
    add rdi, 2

    ; --- Extensions ---
    ; Save position for extensions length (2 bytes)
    mov r14, rdi                ; r14 = extensions_length position
    add rdi, 2

    ; Extension: supported_versions (0x002B)
    mov byte [rdi], 0x00
    mov byte [rdi+1], 0x2B
    mov byte [rdi+2], 0x00     ; ext data length = 3
    mov byte [rdi+3], 0x03
    mov byte [rdi+4], 0x02     ; versions list length = 2
    mov byte [rdi+5], 0x03     ; TLS 1.3 = 0x0304
    mov byte [rdi+6], 0x04
    add rdi, 7

    ; Extension: supported_groups (0x000A)
    mov byte [rdi], 0x00
    mov byte [rdi+1], 0x0A
    mov byte [rdi+2], 0x00     ; ext data length = 4
    mov byte [rdi+3], 0x04
    mov byte [rdi+4], 0x00     ; groups list length = 2
    mov byte [rdi+5], 0x02
    mov byte [rdi+6], 0x00     ; x25519 = 0x001D
    mov byte [rdi+7], 0x1D
    add rdi, 8

    ; Extension: signature_algorithms (0x000D)
    mov byte [rdi], 0x00
    mov byte [rdi+1], 0x0D
    mov byte [rdi+2], 0x00     ; ext data length = 8
    mov byte [rdi+3], 0x08
    mov byte [rdi+4], 0x00     ; algos list length = 6
    mov byte [rdi+5], 0x06
    mov byte [rdi+6], 0x04     ; ecdsa_secp256r1_sha256 = 0x0403
    mov byte [rdi+7], 0x03
    mov byte [rdi+8], 0x08     ; ed25519 = 0x0807
    mov byte [rdi+9], 0x07
    mov byte [rdi+10], 0x08    ; rsa_pss_rsae_sha256 = 0x0804
    mov byte [rdi+11], 0x04
    add rdi, 12

    ; Extension: key_share (0x0033)
    mov byte [rdi], 0x00
    mov byte [rdi+1], 0x33
    mov byte [rdi+2], 0x00     ; ext data length = 38
    mov byte [rdi+3], 0x26
    mov byte [rdi+4], 0x00     ; key shares list length = 36
    mov byte [rdi+5], 0x24
    mov byte [rdi+6], 0x00     ; x25519 group = 0x001D
    mov byte [rdi+7], 0x1D
    mov byte [rdi+8], 0x00     ; key length = 32
    mov byte [rdi+9], 0x20
    add rdi, 10

    ; Copy client public key (32 bytes)
    push rdi
    lea rsi, [rbp-116]
    mov ecx, 32
    rep movsb
    pop rax                     ; rax was pre-copy rdi
    add rdi, 0                  ; rdi already advanced by rep movsb

    ; Extension: server_name / SNI (0x0000)
    ; Structure: [type(2)][ext_len(2)][list_len(2)][name_type(1)][name_len(2)][hostname...]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00   ; extension type = 0x0000 (server_name)
    ; ext_data_len = 2 (list_len) + 1 (name_type) + 2 (name_len) + hostname_len = 5 + hostname_len
    mov eax, [rel sni_hostname_len]
    add eax, 5
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], al     ; ext_len low byte (assumes < 256)
    ; server_name_list_len = 1 + 2 + hostname_len = 3 + hostname_len
    mov eax, [rel sni_hostname_len]
    add eax, 3
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], al     ; list_len low byte
    mov byte [rdi + 6], 0x00   ; name_type = host_name (0)
    ; name_len (2 bytes, big-endian)
    mov byte [rdi + 7], 0x00
    mov eax, [rel sni_hostname_len]
    mov byte [rdi + 8], al     ; name_len low byte
    ; Copy hostname
    add rdi, 9
    push rdi
    lea rsi, [rel sni_hostname]
    mov ecx, [rel sni_hostname_len]
    rep movsb
    pop rax                     ; discard saved pre-copy rdi
    ; rdi already advanced by rep movsb

    ; Extension: ALPN (0x0010)
    ; Protocols: "h2" (2 bytes) + "http/1.1" (8 bytes)
    ; Structure: [type(2)][ext_len(2)][list_len(2)][proto1_len(1)"h2"][proto2_len(1)"http/1.1"]
    ; ext_len = 2 (list_len) + 1+2 + 1+8 = 14
    ; list_len = 1+2 + 1+8 = 12
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x10   ; extension type = 0x0010 (ALPN)
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 14     ; ext_len = 14
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 12     ; list_len = 12
    ; "h2"
    mov byte [rdi + 6], 2      ; protocol_len
    mov byte [rdi + 7], 'h'
    mov byte [rdi + 8], '2'
    ; "http/1.1"
    mov byte [rdi + 9], 8      ; protocol_len
    mov byte [rdi + 10], 'h'
    mov byte [rdi + 11], 't'
    mov byte [rdi + 12], 't'
    mov byte [rdi + 13], 'p'
    mov byte [rdi + 14], '/'
    mov byte [rdi + 15], '1'
    mov byte [rdi + 16], '.'
    mov byte [rdi + 17], '1'
    add rdi, 18

    ; Fill extensions length
    mov rax, rdi
    sub rax, r14
    sub rax, 2                  ; extensions_length = total - 2 bytes for the length field
    mov ecx, eax
    shr ecx, 8
    mov byte [r14], cl          ; extensions_length high byte
    mov byte [r14+1], al        ; extensions_length low byte

    ; Fill handshake length (3 bytes at record_buf+1)
    lea rax, [rbp-25188]       ; record_buf start
    mov rcx, rdi
    sub rcx, rax               ; total handshake message length
    sub rcx, 4                  ; minus type(1) + length(3)
    mov byte [rax+1], 0        ; high byte (always 0 for our small CH)
    mov edx, ecx
    shr edx, 8
    mov byte [rax+2], dl       ; middle byte
    mov byte [rax+3], cl       ; low byte

    ; Total ClientHello length (including handshake header)
    mov rcx, rdi
    lea rax, [rbp-25188]
    sub rcx, rax
    mov [rbp-25192], ecx       ; client_hello_len

    ; Add ClientHello to transcript
    lea rdi, [rbp-8804]        ; transcript_buf
    lea rsi, [rbp-25188]       ; CH data
    mov ecx, [rbp-25192]
    add [rbp-612], ecx         ; transcript_len += client_hello_len
    rep movsb

    ; Send ClientHello as plaintext record
    mov edi, [rbp-44]
    mov esi, TLS_CT_HANDSHAKE
    lea rdx, [rbp-25188]
    mov ecx, [rbp-25192]
    call tls_record_write_plain
    test rax, rax
    jnz .hs_fail

    ; ===== Step 3: Receive ServerHello =====
.read_server_hello:
    mov edi, [rbp-44]
    lea rsi, [rbp-25188]       ; record_buf for SH
    mov edx, 16384
    call tls_record_read_plain
    cmp rax, -1
    je .hs_fail

    ; r8b has content_type
    ; Check for ChangeCipherSpec (type 20) — skip
    cmp r8b, TLS_CT_CHANGE_CIPHER
    je .read_server_hello

    ; Must be handshake (type 22)
    cmp r8b, TLS_CT_HANDSHAKE
    jne .hs_fail

    ; rax = data_len
    mov r12d, eax               ; r12d = SH record length

    ; Verify it's a ServerHello (type=2)
    lea rsi, [rbp-25188]
    cmp byte [rsi], TLS_HS_SERVER_HELLO
    jne .hs_fail

    ; Add ServerHello to transcript
    lea rdi, [rbp-8804]
    mov eax, [rbp-612]
    add rdi, rax                ; transcript_buf + transcript_len
    lea rsi, [rbp-25188]
    mov ecx, r12d
    rep movsb
    add [rbp-612], r12d

    ; ===== Step 4: Parse ServerHello, extract X25519 key share =====
    ; Layout: [type(1)][length(3)][version(2)][random(32)][session_id_len(1)][session_id][cipher(2)][comp(1)][ext_len(2)][extensions...]
    lea rsi, [rbp-25188]
    add rsi, 4                  ; skip handshake header
    add rsi, 2                  ; skip version
    add rsi, 32                ; skip random

    ; Session ID
    movzx eax, byte [rsi]
    inc rsi
    add rsi, rax                ; skip session_id bytes

    ; Cipher suite (should be 0x1303)
    add rsi, 2                  ; skip cipher suite

    ; Compression
    inc rsi                     ; skip compression byte

    ; Extensions length
    movzx r13d, byte [rsi]
    shl r13d, 8
    movzx eax, byte [rsi+1]
    or r13d, eax                ; r13d = extensions_length
    add rsi, 2

    ; Parse extensions to find key_share (0x0033)
    mov r14, rsi                ; r14 = extensions start
    lea r15, [rsi + r13]       ; r15 = extensions end

.parse_sh_ext:
    cmp r14, r15
    jge .hs_fail                ; didn't find key_share

    ; Extension type
    movzx eax, byte [r14]
    shl eax, 8
    movzx ecx, byte [r14+1]
    or eax, ecx                 ; eax = extension type
    add r14, 2

    ; Extension data length
    movzx ecx, byte [r14]
    shl ecx, 8
    movzx edx, byte [r14+1]
    or ecx, edx                 ; ecx = ext data length
    add r14, 2

    cmp eax, TLS_EXT_KEY_SHARE
    je .found_key_share

    ; Skip this extension
    add r14, rcx
    jmp .parse_sh_ext

.found_key_share:
    ; key_share extension data: [group(2)][key_len(2)][key(32)]
    ; Skip group
    add r14, 2
    ; Skip key_len
    add r14, 2
    ; Copy 32-byte server public key
    lea rdi, [rbp-148]
    mov rsi, r14
    mov ecx, 32
    rep movsb

    ; ===== Step 5: Compute shared secret =====
    lea rdi, [rbp-180]          ; output = shared_secret
    lea rsi, [rbp-84]           ; scalar = client_private_key
    lea rdx, [rbp-148]          ; point = server_public_key
    call x25519

    ; ===== Step 6: Key schedule =====
    ; 6a. early_secret = HKDF-Extract(zero_salt=NULL, zero_ikm)
    xor edi, edi                ; NULL salt -> uses 32 zero bytes
    xor esi, esi
    lea rdx, [rel zero_ikm]
    mov ecx, 32
    lea r8, [rbp-212]           ; output = early_secret
    call hkdf_extract

    ; 6b. derived = Derive-Secret(early_secret, "derived", "")
    lea rdi, [rbp-212]          ; secret = early_secret
    lea rsi, [rel label_derived]
    mov edx, label_derived_len
    xor ecx, ecx               ; messages = NULL (empty)
    xor r8d, r8d               ; messages_len = 0
    lea r9, [rbp-244]           ; output = derived_secret_1
    call derive_secret

    ; 6c. handshake_secret = HKDF-Extract(derived, shared_secret)
    lea rdi, [rbp-244]          ; salt = derived_secret_1
    mov esi, 32
    lea rdx, [rbp-180]          ; ikm = shared_secret
    mov ecx, 32
    lea r8, [rbp-276]           ; output = handshake_secret
    call hkdf_extract

    ; 6d. client_hs_traffic = Derive-Secret(hs_secret, "c hs traffic", CH||SH)
    lea rdi, [rbp-276]          ; secret = handshake_secret
    lea rsi, [rel label_c_hs_traffic]
    mov edx, label_c_hs_len
    lea rcx, [rbp-8804]         ; messages = transcript_buf
    mov r8d, [rbp-612]          ; messages_len = transcript_len (CH+SH)
    lea r9, [rbp-308]           ; output = client_hs_traffic
    call derive_secret

    ; 6e. server_hs_traffic = Derive-Secret(hs_secret, "s hs traffic", CH||SH)
    lea rdi, [rbp-276]
    lea rsi, [rel label_s_hs_traffic]
    mov edx, label_s_hs_len
    lea rcx, [rbp-8804]
    mov r8d, [rbp-612]
    lea r9, [rbp-340]           ; output = server_hs_traffic
    call derive_secret

    ; 6f. Derive server handshake key + IV
    ;   key = HKDF-Expand-Label(server_hs_traffic, "key", "", 32)
    ;   iv  = HKDF-Expand-Label(server_hs_traffic, "iv", "", 12)
    lea rdi, [rbp-340]          ; secret
    lea rsi, [rel label_key]
    mov edx, label_key_len
    xor ecx, ecx               ; context = NULL
    xor r8d, r8d               ; context_len = 0
    mov r9d, 32                 ; output_len
    lea rax, [rbp-500]          ; temp_key
    push rax
    call hkdf_expand_label
    add rsp, 8

    lea rdi, [rbp-340]
    lea rsi, [rel label_iv]
    mov edx, label_iv_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 12
    lea rax, [rbp-512]          ; temp_iv
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; ===== Step 7: Set TLS state read keys to server handshake keys =====
    mov r12, [rbp-52]           ; tls_state

    ; read_key = server handshake key
    lea rdi, [r12 + TLS_STATE_READ_KEY]
    lea rsi, [rbp-500]
    mov ecx, 32
    rep movsb

    ; read_iv = server handshake IV
    lea rdi, [r12 + TLS_STATE_READ_IV]
    lea rsi, [rbp-512]
    mov ecx, 12
    rep movsb

    ; read_seq = 0
    mov qword [r12 + TLS_STATE_READ_SEQ], 0

    ; ===== Step 8: Read encrypted handshake messages =====
    ; We expect: EncryptedExtensions, Certificate, CertificateVerify, Finished
    ; (some servers may omit Certificate/CertificateVerify)
    ; We accumulate ALL handshake message bytes into the transcript.
    ; Multiple messages may arrive in a single record, or spread across multiple records.
    ; We loop until we get a Finished message.

    ; Use record_buf as decryption output
.read_hs_msg:
    mov edi, [rbp-44]
    mov rsi, [rbp-52]           ; tls_state
    lea rdx, [rbp-25188]        ; output buffer
    mov ecx, 16384
    call tls_record_read_enc
    cmp rax, -1
    je .hs_fail

    ; rax = plaintext_len, r8b = inner content type
    ; Must be handshake
    cmp r8b, TLS_CT_HANDSHAKE
    jne .hs_fail

    mov r12d, eax               ; r12d = total plaintext bytes from this record

    ; Parse potentially multiple handshake messages in this record
    lea r13, [rbp-25188]        ; current parse position
    xor r14d, r14d              ; bytes consumed

.parse_hs_record:
    ; Remaining bytes in this record
    mov eax, r12d
    sub eax, r14d
    cmp eax, 4                  ; need at least type(1) + length(3)
    jb .read_hs_msg             ; not enough for another message, read next record

    ; Parse handshake header
    movzx ebx, byte [r13]      ; handshake type

    ; Parse 3-byte length
    movzx ecx, byte [r13+1]
    shl ecx, 16
    movzx edx, byte [r13+2]
    shl edx, 8
    or ecx, edx
    movzx edx, byte [r13+3]
    or ecx, edx                 ; ecx = handshake body length

    ; Total message length = 4 + body_length
    lea edx, [ecx + 4]

    ; Verify we have enough data
    mov eax, r12d
    sub eax, r14d
    cmp eax, edx
    jb .read_hs_msg             ; partial message, read more (shouldn't happen with standard servers)

    ; Add this complete handshake message to transcript
    lea rdi, [rbp-8804]
    mov eax, [rbp-612]
    add rdi, rax
    mov rsi, r13
    push rcx
    push rdx
    mov ecx, edx               ; message length (header + body)
    rep movsb
    pop rdx
    pop rcx
    add [rbp-612], edx

    ; Check message type
    cmp bl, TLS_HS_FINISHED
    je .got_finished

    ; Not Finished — advance to next message in record
    add r13, rdx
    add r14d, edx
    jmp .parse_hs_record

.got_finished:
    ; Save transcript length INCLUDING server Finished for app secret derivation
    mov eax, [rbp-612]
    mov [rbp-25196], eax        ; server_finished_transcript_len

    ; ===== Step 9: Verify server Finished =====
    ; finished_key = HKDF-Expand-Label(server_hs_traffic, "finished", "", 32)
    lea rdi, [rbp-340]          ; server_hs_traffic
    lea rsi, [rel label_finished]
    mov edx, label_finished_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 32
    lea rax, [rbp-544]          ; finished_key
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Transcript hash up to (but NOT including) the Finished message itself
    ; The Finished message was just added to transcript. We need the hash
    ; of everything BEFORE it.
    ; edx still holds the Finished message total length from above.
    ; transcript_len currently includes the Finished message.
    ; transcript_up_to_cv_len = transcript_len - finished_msg_len
    ; But actually we already added it. Let's compute the transcript hash
    ; of everything before Finished:
    ;   finished_msg_len = 4 + ecx (ecx was the body length = 32)
    ;   pre_finished_len = transcript_len - (4 + 32) = transcript_len - 36

    mov eax, [rbp-612]
    sub eax, 36                 ; pre_finished_len (Finished = 4 header + 32 verify_data)
    mov r15d, eax               ; save pre_finished_len

    ; Hash transcript up to CertificateVerify (everything before Finished)
    lea rdi, [rbp-8804]
    movzx rsi, r15d
    lea rdx, [rbp-608]          ; transcript_hash
    call sha256

    ; expected_verify = HMAC-SHA256(finished_key, transcript_hash)
    lea rdi, [rbp-544]          ; key = finished_key
    mov esi, 32
    lea rdx, [rbp-608]          ; msg = transcript_hash
    mov ecx, 32
    lea r8, [rbp-576]           ; output = expected_verify
    call hmac_sha256

    ; Compare with received verify_data (at r13+4, 32 bytes)
    lea rsi, [r13+4]            ; received verify_data
    lea rdi, [rbp-576]          ; expected verify_data
    xor eax, eax
%assign i 0
%rep 32
    movzx ecx, byte [rsi + i]
    movzx edx, byte [rdi + i]
    xor ecx, edx
    or eax, ecx
%assign i i+1
%endrep
    test eax, eax
    jnz .hs_fail

    ; ===== Step 10: Derive client handshake key/IV and set write keys =====
    lea rdi, [rbp-308]          ; client_hs_traffic
    lea rsi, [rel label_key]
    mov edx, label_key_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 32
    lea rax, [rbp-500]          ; temp_key
    push rax
    call hkdf_expand_label
    add rsp, 8

    lea rdi, [rbp-308]
    lea rsi, [rel label_iv]
    mov edx, label_iv_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 12
    lea rax, [rbp-512]          ; temp_iv
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Set write keys to client handshake keys
    mov r12, [rbp-52]
    lea rdi, [r12 + TLS_STATE_WRITE_KEY]
    lea rsi, [rbp-500]
    mov ecx, 32
    rep movsb

    lea rdi, [r12 + TLS_STATE_WRITE_IV]
    lea rsi, [rbp-512]
    mov ecx, 12
    rep movsb

    mov qword [r12 + TLS_STATE_WRITE_SEQ], 0

    ; ===== Step 11: Send client Finished =====
    ; finished_key = HKDF-Expand-Label(client_hs_traffic, "finished", "", 32)
    lea rdi, [rbp-308]
    lea rsi, [rel label_finished]
    mov edx, label_finished_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 32
    lea rax, [rbp-544]
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Hash the full transcript (including server Finished)
    lea rdi, [rbp-8804]
    mov esi, [rbp-612]
    lea rdx, [rbp-608]
    call sha256

    ; verify_data = HMAC-SHA256(finished_key, transcript_hash)
    lea rdi, [rbp-544]
    mov esi, 32
    lea rdx, [rbp-608]
    mov ecx, 32
    lea r8, [rbp-576]           ; reuse expected_verify as our verify_data
    call hmac_sha256

    ; Build Finished handshake message: [type=20][length=0x000020][verify_data(32)]
    lea rdi, [rbp-25188]
    mov byte [rdi], TLS_HS_FINISHED
    mov byte [rdi+1], 0x00
    mov byte [rdi+2], 0x00
    mov byte [rdi+3], 0x20      ; length = 32
    lea rsi, [rbp-576]
    lea rdi, [rbp-25184]        ; rdi+4
    mov ecx, 32
    rep movsb

    ; Add client Finished to transcript before sending
    lea rdi, [rbp-8804]
    mov eax, [rbp-612]
    add rdi, rax
    lea rsi, [rbp-25188]
    mov ecx, 36                 ; 4 header + 32 data
    rep movsb
    add dword [rbp-612], 36

    ; Send client Finished as encrypted record
    mov edi, [rbp-44]
    mov rsi, [rbp-52]
    mov edx, TLS_CT_HANDSHAKE
    lea rcx, [rbp-25188]
    mov r8d, 36                 ; 4 + 32
    call tls_record_write_enc
    test rax, rax
    jnz .hs_fail

    ; ===== Step 12: Derive application traffic secrets =====
    ; derived2 = Derive-Secret(handshake_secret, "derived", "")
    lea rdi, [rbp-276]          ; handshake_secret
    lea rsi, [rel label_derived]
    mov edx, label_derived_len
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rbp-372]           ; output = derived_secret_2
    call derive_secret

    ; master_secret = HKDF-Extract(derived2, zero)
    lea rdi, [rbp-372]          ; salt = derived_secret_2
    mov esi, 32
    lea rdx, [rel zero_ikm]    ; ikm = zero
    mov ecx, 32
    lea r8, [rbp-404]           ; output = master_secret
    call hkdf_extract

    ; App traffic secrets use transcript through server Finished (NOT client Finished)
    ; Per RFC 8446 Section 7.1

    ; client_app_traffic = Derive-Secret(master_secret, "c ap traffic", CH..server Finished)
    lea rdi, [rbp-404]
    lea rsi, [rel label_c_ap_traffic]
    mov edx, label_c_ap_len
    lea rcx, [rbp-8804]
    mov r8d, [rbp-25196]        ; server_finished_transcript_len
    lea r9, [rbp-436]
    call derive_secret

    ; server_app_traffic = Derive-Secret(master_secret, "s ap traffic", CH..server Finished)
    lea rdi, [rbp-404]
    lea rsi, [rel label_s_ap_traffic]
    mov edx, label_s_ap_len
    lea rcx, [rbp-8804]
    mov r8d, [rbp-25196]        ; server_finished_transcript_len
    lea r9, [rbp-468]
    call derive_secret

    ; ===== Step 13: Derive application keys/IVs and set TLS state =====
    ; Client write key
    lea rdi, [rbp-436]
    lea rsi, [rel label_key]
    mov edx, label_key_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 32
    lea rax, [rbp-500]
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Client write IV
    lea rdi, [rbp-436]
    lea rsi, [rel label_iv]
    mov edx, label_iv_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 12
    lea rax, [rbp-512]
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Set write keys
    mov r12, [rbp-52]
    lea rdi, [r12 + TLS_STATE_WRITE_KEY]
    lea rsi, [rbp-500]
    mov ecx, 32
    rep movsb
    lea rdi, [r12 + TLS_STATE_WRITE_IV]
    lea rsi, [rbp-512]
    mov ecx, 12
    rep movsb
    mov qword [r12 + TLS_STATE_WRITE_SEQ], 0

    ; Server read key
    lea rdi, [rbp-468]
    lea rsi, [rel label_key]
    mov edx, label_key_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 32
    lea rax, [rbp-500]
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Server read IV
    lea rdi, [rbp-468]
    lea rsi, [rel label_iv]
    mov edx, label_iv_len
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 12
    lea rax, [rbp-512]
    push rax
    call hkdf_expand_label
    add rsp, 8

    ; Set read keys
    lea rdi, [r12 + TLS_STATE_READ_KEY]
    lea rsi, [rbp-500]
    mov ecx, 32
    rep movsb
    lea rdi, [r12 + TLS_STATE_READ_IV]
    lea rsi, [rbp-512]
    mov ecx, 12
    rep movsb
    mov qword [r12 + TLS_STATE_READ_SEQ], 0

    ; Success
    xor eax, eax
    jmp .hs_ret

.hs_fail:
    mov rax, -1

.hs_ret:
    lea rsp, [rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
