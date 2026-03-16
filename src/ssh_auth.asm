; ssh_auth.asm - SSH password authentication (RFC 4252)
; Works over the ENCRYPTED transport (after key exchange)
; Pure x86-64 Linux syscalls, no libc

%include "ssh.inc"
%include "syscall.inc"

; External functions
extern ssh_send_packet_enc
extern ssh_recv_packet_enc
extern encode_string
extern encode_uint32
extern decode_uint32
extern ed25519_verify

; SSH state structure offsets (must match ssh_transport.asm)
%define SSH_STATE_K1_C2S     0
%define SSH_STATE_K2_C2S     32
%define SSH_STATE_SEQ_C2S    64
%define SSH_STATE_K1_S2C     68
%define SSH_STATE_K2_S2C     100
%define SSH_STATE_SEQ_S2C    132
%define SSH_STATE_SESSION_ID 136
%define SSH_STATE_ROLE       168
%define SSH_STATE_SIZE       176

section .rodata
align 8
str_ssh_userauth:       db "ssh-userauth"
str_ssh_userauth_len    equ $ - str_ssh_userauth
str_ssh_connection:     db "ssh-connection"
str_ssh_connection_len  equ $ - str_ssh_connection
str_password:           db "password"
str_password_len        equ $ - str_password
str_publickey:          db "publickey"
str_publickey_len       equ $ - str_publickey
str_ssh_ed25519:        db "ssh-ed25519"
str_ssh_ed25519_len     equ $ - str_ssh_ed25519

section .text

; ============================================================================
; ssh_auth_client_password(edi=sock_fd, rsi=state_ptr, rdx=username, ecx=user_len,
;                          r8=password, r9d=pass_len) -> rax=0 success, -1 failure
;
; Protocol:
; 1. Send SSH_MSG_SERVICE_REQUEST("ssh-userauth")
; 2. Recv SSH_MSG_SERVICE_ACCEPT (byte 6)
; 3. Send SSH_MSG_USERAUTH_REQUEST with password
; 4. Recv SSH_MSG_USERAUTH_SUCCESS (byte 52) or FAILURE (byte 51)
; ============================================================================
global ssh_auth_client_password
ssh_auth_client_password:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 1088              ; stack buffer for payloads + recv buffer

    ; Save all arguments
    mov r12d, edi              ; sock_fd
    mov r13, rsi               ; state_ptr
    mov r14, rdx               ; username
    mov r15d, ecx              ; user_len
    mov [rsp + 1024], r8       ; password ptr (save to stack)
    mov [rsp + 1032], r9d      ; pass_len (save to stack)

    ; --- Step 1: Send SSH_MSG_SERVICE_REQUEST("ssh-userauth") ---
    lea rbp, [rsp]             ; payload buffer

    ; byte 5 = SSH_MSG_SERVICE_REQUEST
    mov byte [rbp], SSH_MSG_SERVICE_REQUEST
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_userauth]
    mov edx, str_ssh_userauth_len
    call encode_string
    ; rax = bytes written for the string
    lea edx, [eax + 1]        ; payload_len = 1 + string

    ; Send encrypted packet
    mov edi, r12d              ; sock_fd
    lea rsi, [rbp]             ; payload
    ; edx already set
    mov rcx, r13               ; state_ptr
    call ssh_send_packet_enc
    test rax, rax
    jnz .client_fail

    ; --- Step 2: Recv SSH_MSG_SERVICE_ACCEPT ---
    lea rsi, [rsp + 512]      ; recv buffer
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .client_fail

    ; Check msg type == 6 (SSH_MSG_SERVICE_ACCEPT)
    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_SERVICE_ACCEPT
    jne .client_fail

    ; --- Step 3: Send SSH_MSG_USERAUTH_REQUEST ---
    lea rbp, [rsp]             ; payload buffer

    ; byte 50 = SSH_MSG_USERAUTH_REQUEST
    mov byte [rbp], SSH_MSG_USERAUTH_REQUEST
    mov ebx, 1                ; offset = 1

    ; string username
    lea rdi, [rbp + rbx]
    mov rsi, r14               ; username ptr
    mov edx, r15d              ; user_len
    call encode_string
    add ebx, eax

    ; string "ssh-connection"
    lea rdi, [rbp + rbx]
    lea rsi, [rel str_ssh_connection]
    mov edx, str_ssh_connection_len
    call encode_string
    add ebx, eax

    ; string "password"
    lea rdi, [rbp + rbx]
    lea rsi, [rel str_password]
    mov edx, str_password_len
    call encode_string
    add ebx, eax

    ; byte 0 (FALSE - not a password change)
    mov byte [rbp + rbx], 0
    inc ebx

    ; string password
    lea rdi, [rbp + rbx]
    mov rsi, [rsp + 1024]     ; password ptr
    mov edx, [rsp + 1032]     ; pass_len
    call encode_string
    add ebx, eax

    ; Send encrypted packet
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, ebx              ; payload_len
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .client_fail

    ; --- Step 4: Recv response ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .client_fail

    ; Check msg type
    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_SUCCESS
    jne .client_fail

    ; Success
    xor eax, eax
    jmp .client_done

.client_fail:
    mov rax, -1

.client_done:
    add rsp, 1088
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_auth_server_password(edi=sock_fd, rsi=state_ptr, rdx=expected_pass,
;                          ecx=pass_len) -> rax=0 success, -1 failure
;
; Protocol:
; 1. Recv SSH_MSG_SERVICE_REQUEST, verify "ssh-userauth"
; 2. Send SSH_MSG_SERVICE_ACCEPT("ssh-userauth")
; 3. Recv SSH_MSG_USERAUTH_REQUEST, extract and compare password
; 4. Send SUCCESS or FAILURE
; ============================================================================
global ssh_auth_server_password
ssh_auth_server_password:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 1088

    ; Save arguments
    mov r12d, edi              ; sock_fd
    mov r13, rsi               ; state_ptr
    mov r14, rdx               ; expected_pass
    mov r15d, ecx              ; pass_len

    ; --- Step 1: Recv SSH_MSG_SERVICE_REQUEST ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .server_fail

    ; Check msg type == 5 (SSH_MSG_SERVICE_REQUEST)
    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_SERVICE_REQUEST
    jne .server_fail

    ; Verify service name is "ssh-userauth"
    ; At offset 1: string with uint32 length + data
    lea rdi, [rbp + 1]
    call decode_uint32         ; eax = service name length
    cmp eax, str_ssh_userauth_len
    jne .server_fail

    ; Compare service name bytes
    lea rsi, [rbp + 5]        ; data starts at offset 1+4=5
    lea rdi, [rel str_ssh_userauth]
    mov ecx, str_ssh_userauth_len
    repe cmpsb
    jne .server_fail

    ; --- Step 2: Send SSH_MSG_SERVICE_ACCEPT("ssh-userauth") ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_SERVICE_ACCEPT
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_userauth]
    mov edx, str_ssh_userauth_len
    call encode_string
    lea edx, [eax + 1]        ; payload_len

    mov edi, r12d
    lea rsi, [rbp]
    ; edx set
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .server_fail

    ; --- Step 3: Recv SSH_MSG_USERAUTH_REQUEST ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .server_fail
    mov ebx, eax              ; save payload length for bounds

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_REQUEST
    jne .server_fail

    ; Parse: [byte 50][string user][string service][string method][byte FALSE][string password]
    ; Walk through the payload to find the password
    mov ecx, 1                ; offset past msg type byte

    ; Skip username string: uint32 len + len bytes
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; eax = user_len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip past username

    ; Skip service string: uint32 len + len bytes
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; eax = service_len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip past service

    ; Skip method string: uint32 len + len bytes
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; eax = method_len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip past method

    ; Skip FALSE byte
    inc ecx

    ; Now at password string: uint32 len + data
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; eax = received pass_len
    pop rcx
    add ecx, 4                ; ecx now points to password data

    ; Compare password length
    cmp eax, r15d
    jne .server_send_failure

    ; Compare password bytes (byte-by-byte)
    mov edx, eax              ; password length
    lea rsi, [rbp + rcx]      ; received password
    mov rdi, r14               ; expected password
    test edx, edx
    jz .server_send_success    ; empty password matches empty

.cmp_loop:
    movzx eax, byte [rsi]
    cmp al, [rdi]
    jne .server_send_failure
    inc rsi
    inc rdi
    dec edx
    jnz .cmp_loop

.server_send_success:
    ; --- Step 4a: Send SSH_MSG_USERAUTH_SUCCESS ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_SUCCESS
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, 1
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .server_fail

    xor eax, eax
    jmp .server_done

.server_send_failure:
    ; --- Step 4b: Send SSH_MSG_USERAUTH_FAILURE ---
    ; Payload: [byte 51][string name-list][byte 0 (partial success)]
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_FAILURE
    ; name-list of allowed methods (empty for simplicity)
    lea rdi, [rbp + 1]
    lea rsi, [rel str_password]
    mov edx, str_password_len
    call encode_string
    lea edx, [eax + 1]        ; 1 + string
    ; partial success byte = 0
    mov byte [rbp + rdx], 0
    inc edx

    mov edi, r12d
    lea rsi, [rbp]
    ; edx set
    mov rcx, r13
    call ssh_send_packet_enc

    ; Always return failure
.server_fail:
    mov rax, -1

.server_done:
    add rsp, 1088
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_auth_server_pubkey(edi=sock_fd, rsi=state_ptr, rdx=authorized_keys_ptr,
;                        ecx=num_keys) -> rax=0 success, -1 failure
;
; Handles two-phase Ed25519 public key auth (RFC 4252 Section 7):
; 1. Recv SERVICE_REQUEST "ssh-userauth", send ACCEPT
; 2. Recv USERAUTH_REQUEST with method "publickey"
;    - If boolean=FALSE (probe): check key, send PK_OK or FAILURE
;    - If boolean=TRUE: verify signature, send SUCCESS or FAILURE
; 3. For probe: recv second USERAUTH_REQUEST with boolean=TRUE and signature
;
; Stack layout (2560 bytes):
;   [rsp+0 .. rsp+511]    - send payload buffer
;   [rsp+512 .. rsp+1023] - recv buffer
;   [rsp+1024 .. rsp+1423]- signed data construction buffer (400 bytes)
;   [rsp+1424 .. rsp+1431]- saved authorized_keys_ptr
;   [rsp+1432 .. rsp+1435]- saved num_keys
;   [rsp+1440 .. rsp+1471]- extracted raw pubkey (32 bytes)
;   [rsp+1472 .. rsp+1535]- extracted raw signature (64 bytes)
;   [rsp+1536 .. rsp+1539]- pubkey_blob_offset in recv buffer
;   [rsp+1540 .. rsp+1543]- pubkey_blob_len
;   [rsp+1544 .. rsp+2559]- extra workspace
; ============================================================================
global ssh_auth_server_pubkey
ssh_auth_server_pubkey:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 2560

    ; Save arguments
    mov r12d, edi              ; sock_fd
    mov r13, rsi               ; state_ptr
    mov [rsp + 1424], rdx      ; authorized_keys_ptr
    mov [rsp + 1432], ecx      ; num_keys

    ; --- Step 1: Recv SSH_MSG_SERVICE_REQUEST ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .pk_fail

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_SERVICE_REQUEST
    jne .pk_fail

    ; Verify service name is "ssh-userauth"
    lea rdi, [rbp + 1]
    call decode_uint32
    cmp eax, str_ssh_userauth_len
    jne .pk_fail
    lea rsi, [rbp + 5]
    lea rdi, [rel str_ssh_userauth]
    mov ecx, str_ssh_userauth_len
    repe cmpsb
    jne .pk_fail

    ; --- Step 2: Send SSH_MSG_SERVICE_ACCEPT ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_SERVICE_ACCEPT
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_userauth]
    mov edx, str_ssh_userauth_len
    call encode_string
    lea edx, [eax + 1]
    mov edi, r12d
    lea rsi, [rbp]
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .pk_fail

    ; --- Step 3: Recv first USERAUTH_REQUEST ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .pk_fail
    mov ebx, eax              ; payload length

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_REQUEST
    jne .pk_fail

    ; Parse: [byte 50][string user][string service][string method]...
    mov ecx, 1                ; offset past msg type

    ; Skip username (save offset for later signed data construction)
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    mov r14d, ecx             ; r14d = offset of username string start
    add ecx, 4
    add ecx, eax

    ; Skip service string
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Read method string
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    ; eax = method_len, method data at rbp + rcx + 4
    cmp eax, str_publickey_len
    jne .pk_send_failure

    ; Compare method with "publickey"
    push rcx
    push rax
    lea rsi, [rbp + rcx + 4]
    lea rdi, [rel str_publickey]
    mov ecx, str_publickey_len
    repe cmpsb
    pop rax
    pop rcx
    jne .pk_send_failure

    add ecx, 4
    add ecx, eax              ; skip past method string

    ; Read boolean (FALSE=probe, TRUE=verify)
    movzx r15d, byte [rbp + rcx]
    inc ecx

    ; Read algorithm name string "ssh-ed25519"
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    ; eax = algo_len; verify it's "ssh-ed25519"
    cmp eax, str_ssh_ed25519_len
    jne .pk_send_failure
    push rcx
    push rax
    lea rsi, [rbp + rcx + 4]
    lea rdi, [rel str_ssh_ed25519]
    mov ecx, str_ssh_ed25519_len
    repe cmpsb
    pop rax
    pop rcx
    jne .pk_send_failure
    add ecx, 4
    add ecx, eax              ; skip past algo name

    ; Read public_key_blob: [uint32 blob_len][blob_data]
    ; blob_data = [string "ssh-ed25519"][string raw_pubkey_32]
    mov [rsp + 1536], ecx     ; save offset to blob start (the uint32 len)
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    mov [rsp + 1540], eax     ; blob_len
    add ecx, 4                ; ecx now points to blob data

    ; Parse inside the blob: skip "ssh-ed25519" string, then read raw pubkey
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; inner algo string len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip inner algo string

    ; Now at raw pubkey string: [uint32 32][32 bytes key]
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 32
    jne .pk_send_failure
    add ecx, 4

    ; Copy 32-byte raw pubkey to our buffer
    lea rdi, [rsp + 1440]
    lea rsi, [rbp + rcx]
    push rcx
    mov ecx, 32
    rep movsb
    pop rcx
    add ecx, 32               ; past raw pubkey in blob

    ; --- Check if key is authorized ---
    mov r14d, [rsp + 1432]    ; num_keys
    mov rdi, [rsp + 1424]     ; authorized_keys_ptr
    test r14d, r14d
    jz .pk_send_failure        ; no keys -> reject

    xor eax, eax              ; key index
.pk_key_scan:
    cmp eax, r14d
    jge .pk_send_failure       ; key not found

    ; Compare 32 bytes
    push rax
    push rdi
    lea rsi, [rsp + 1440 + 16] ; +16 for two pushes
    ; rdi already points to current key slot
    mov ecx, 32
    repe cmpsb
    pop rdi
    pop rax
    je .pk_key_found

    add rdi, 32               ; next key slot
    inc eax
    jmp .pk_key_scan

.pk_key_found:
    ; Key is authorized. Check if this is probe (r15=0) or verify (r15=1)
    test r15d, r15d
    jnz .pk_verify_signature

    ; --- PROBE: Send SSH_MSG_USERAUTH_PK_OK ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_PK_OK

    ; [string "ssh-ed25519"]
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_ed25519]
    mov edx, str_ssh_ed25519_len
    call encode_string
    mov ebx, eax
    inc ebx                    ; offset = 1 + algo_string

    ; [string public_key_blob] - copy from recv buffer
    lea rdi, [rbp + rbx]
    mov ecx, [rsp + 1536]     ; offset to blob in recv buffer
    lea rsi, [rsp + 512 + rcx]; point to uint32+blob in recv buffer
    mov eax, [rsp + 1540]     ; blob_len
    lea edx, [eax + 4]        ; include the uint32 length prefix
    push rbx
    mov ecx, edx
    rep movsb
    pop rbx
    add ebx, edx

    mov edi, r12d
    lea rsi, [rsp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .pk_fail

    ; --- Recv second USERAUTH_REQUEST (with signature) ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .pk_fail
    mov ebx, eax

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_REQUEST
    jne .pk_fail

    ; Re-parse the second request: [byte 50][string user][string svc][string method][byte TRUE][string algo][string blob][string sig_blob]
    mov ecx, 1

    ; Skip username
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip service
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip method
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Check boolean == TRUE
    cmp byte [rbp + rcx], 1
    jne .pk_send_failure
    inc ecx

    ; Skip algo string
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Save blob offset/len for signed data
    mov [rsp + 1536], ecx     ; blob offset
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    mov [rsp + 1540], eax     ; blob_len
    add ecx, 4
    add ecx, eax              ; skip past blob data

    ; Re-extract raw pubkey from the new blob
    mov r14d, [rsp + 1536]    ; blob offset
    movzx r14, r14d           ; zero-extend to 64-bit
    lea rdi, [rbp + r14 + 4] ; start of blob data (skip outer uint32 len)
    push rcx
    call decode_uint32         ; inner algo string len
    pop rcx
    ; skip inner algo string
    mov edx, r14d
    add edx, 4                ; past outer len
    add edx, 4                ; past inner algo len field
    add edx, eax              ; past inner algo string
    ; Now at inner raw pubkey string
    lea rdi, [rbp + rdx]
    push rcx
    push rdx
    call decode_uint32         ; should be 32
    pop rdx
    pop rcx
    cmp eax, 32
    jne .pk_send_failure
    add edx, 4
    ; Copy raw pubkey
    push rcx
    lea rdi, [rsp + 1440 + 8] ; +8 for push
    lea rsi, [rbp + rdx]
    mov ecx, 32
    rep movsb
    pop rcx

    ; Read signature_blob: [uint32 sig_blob_len][sig_blob_data]
    ; sig_blob_data = [string "ssh-ed25519"][string raw_sig_64]
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4                ; past sig_blob length field
    ; Now parse inside sig_blob
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; inner sig algo string len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip "ssh-ed25519"

    ; Read raw signature (64 bytes)
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 64
    jne .pk_send_failure
    add ecx, 4

    ; Copy raw signature to buffer
    push rcx
    lea rdi, [rsp + 1472 + 8] ; +8 for push
    lea rsi, [rbp + rcx]
    mov ecx, 64
    rep movsb
    pop rcx

    jmp .pk_verify_signature_phase2

.pk_verify_signature:
    ; Direct verify (boolean was TRUE in first message)
    ; We need to extract the signature from the current packet (rbp = rsp+512)
    ; ecx already past the blob. Read signature_blob.
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    ; Parse inside sig_blob
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32         ; sig algo len
    pop rcx
    add ecx, 4
    add ecx, eax              ; skip "ssh-ed25519"

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 64
    jne .pk_send_failure
    add ecx, 4

    ; Copy raw signature
    push rcx
    lea rdi, [rsp + 1472 + 8]
    lea rsi, [rbp + rcx]
    mov ecx, 64
    rep movsb
    pop rcx

.pk_verify_signature_phase2:
    ; Build the signed data in rsp+1024:
    ; [string session_id(32)] + [byte 50] + rest of USERAUTH_REQUEST fields
    ; (everything from the current rbp packet EXCEPT the signature_blob at the end)
    ;
    ; signed_data = [string session_id]
    ;             + [byte 50]
    ;             + [string username]
    ;             + [string "ssh-connection"]
    ;             + [string "publickey"]
    ;             + [byte TRUE]
    ;             + [string "ssh-ed25519"]
    ;             + [string public_key_blob]

    lea rbp, [rsp + 1024]     ; signed data buffer
    xor ebx, ebx              ; offset in signed data

    ; [string session_id] - 4 + 32 = 36 bytes
    lea rdi, [rbp]
    lea rsi, [r13 + SSH_STATE_SESSION_ID]
    mov edx, 32
    call encode_string
    add ebx, eax

    ; [byte 50]
    mov byte [rbp + rbx], SSH_MSG_USERAUTH_REQUEST
    inc ebx

    ; Now we need to copy the USERAUTH_REQUEST fields (user, svc, method, TRUE, algo, blob)
    ; from the recv buffer. Re-parse to find the extent.
    ; The recv buffer at rsp+512 has: [byte 50][string user][string svc][string method][byte 1][string algo][string blob][string sig_blob]
    ; We need everything from [string user] through [string blob], i.e. offset 1 to just before sig_blob.

    ; Walk the recv buffer to find where sig_blob starts
    lea r14, [rsp + 512]      ; recv buffer
    mov ecx, 1                ; skip msg type

    ; Skip username string
    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip service string
    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip method string
    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip boolean byte
    inc ecx

    ; Skip algo string
    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip public_key_blob string
    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; ecx = offset of sig_blob = end of fields we want to copy
    ; Copy from offset 1 to ecx from recv buffer
    mov edx, ecx
    dec edx                    ; length = ecx - 1 (skip the msg type byte we already wrote)
    lea rsi, [r14 + 1]        ; source: right after msg type
    lea rdi, [rbp + rbx]      ; dest in signed data
    push rcx
    mov ecx, edx
    rep movsb
    pop rcx
    add ebx, edx

    ; Now call ed25519_verify(rdi=sig64, rsi=msg, rdx=msg_len, rcx=pubkey32)
    lea rdi, [rsp + 1472]     ; raw signature (64 bytes)
    lea rsi, [rsp + 1024]     ; signed data
    mov edx, ebx              ; signed data length
    lea rcx, [rsp + 1440]     ; raw pubkey (32 bytes)
    call ed25519_verify
    test eax, eax
    jnz .pk_send_failure

    ; --- Signature valid: Send SSH_MSG_USERAUTH_SUCCESS ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_SUCCESS
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, 1
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .pk_fail

    xor eax, eax
    jmp .pk_done

.pk_send_failure:
    ; Send SSH_MSG_USERAUTH_FAILURE
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_FAILURE
    lea rdi, [rbp + 1]
    lea rsi, [rel str_publickey]
    mov edx, str_publickey_len
    call encode_string
    lea edx, [eax + 1]
    mov byte [rbp + rdx], 0    ; partial success = FALSE
    inc edx
    mov edi, r12d
    lea rsi, [rbp]
    mov rcx, r13
    call ssh_send_packet_enc

.pk_fail:
    mov rax, -1
    jmp .pk_done

.pk_done:
    add rsp, 2560
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_auth_server_any(edi=sock_fd, rsi=state_ptr, rdx=password_ptr,
;                     ecx=password_len, r8=authorized_keys_ptr,
;                     r9d=num_keys) -> rax=0 success, -1 failure
;
; Accepts EITHER password OR publickey auth.
; Handles SERVICE_REQUEST/ACCEPT, then checks the method in USERAUTH_REQUEST.
; If "password": verify password
; If "publickey": handle pubkey flow (probe + verify)
;
; Stack layout (2560 bytes):
;   [rsp+0..511]     - send payload buffer
;   [rsp+512..1023]  - recv buffer
;   [rsp+1024..1423] - signed data construction buffer
;   [rsp+1424..1431] - saved password_ptr
;   [rsp+1432..1435] - saved password_len
;   [rsp+1440..1471] - extracted raw pubkey (32 bytes)
;   [rsp+1472..1535] - extracted raw signature (64 bytes)
;   [rsp+1536..1543] - blob offset + blob_len
;   [rsp+1544..1551] - saved authorized_keys_ptr
;   [rsp+1552..1555] - saved num_keys
; ============================================================================
global ssh_auth_server_any
ssh_auth_server_any:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 2560

    ; Save arguments
    mov r12d, edi              ; sock_fd
    mov r13, rsi               ; state_ptr
    mov [rsp + 1424], rdx      ; password_ptr
    mov [rsp + 1432], ecx      ; password_len
    mov [rsp + 1544], r8       ; authorized_keys_ptr
    mov [rsp + 1552], r9d      ; num_keys

    ; --- Step 1: Recv SSH_MSG_SERVICE_REQUEST ---
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .any_fail

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_SERVICE_REQUEST
    jne .any_fail

    lea rdi, [rbp + 1]
    call decode_uint32
    cmp eax, str_ssh_userauth_len
    jne .any_fail
    lea rsi, [rbp + 5]
    lea rdi, [rel str_ssh_userauth]
    mov ecx, str_ssh_userauth_len
    repe cmpsb
    jne .any_fail

    ; --- Step 2: Send SSH_MSG_SERVICE_ACCEPT ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_SERVICE_ACCEPT
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_userauth]
    mov edx, str_ssh_userauth_len
    call encode_string
    lea edx, [eax + 1]
    mov edi, r12d
    lea rsi, [rbp]
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .any_fail

    ; --- Step 3: Recv USERAUTH_REQUEST (may loop for "none" probe) ---
.any_recv_userauth:
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .any_fail
    mov ebx, eax

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_REQUEST
    jne .any_fail

    ; Parse: skip username, service, read method
    mov ecx, 1

    ; Skip username
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Skip service
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Read method
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    ; eax = method_len, data at rbp+rcx+4

    ; Check if method == "password"
    cmp eax, str_password_len
    jne .any_check_pubkey
    push rcx
    push rax
    lea rsi, [rbp + rcx + 4]
    lea rdi, [rel str_password]
    mov ecx, str_password_len
    repe cmpsb
    pop rax
    pop rcx
    jne .any_check_pubkey

    ; --- PASSWORD AUTH ---
    add ecx, 4
    add ecx, eax              ; skip method string
    inc ecx                    ; skip FALSE byte

    ; Read password string
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    ; eax = received password len
    add ecx, 4

    ; Compare password length
    cmp eax, [rsp + 1432]
    jne .any_send_failure

    ; Compare password bytes
    mov edx, eax
    lea rsi, [rbp + rcx]
    mov rdi, [rsp + 1424]
    test edx, edx
    jz .any_send_success

.any_pwd_cmp:
    movzx eax, byte [rsi]
    cmp al, [rdi]
    jne .any_send_failure
    inc rsi
    inc rdi
    dec edx
    jnz .any_pwd_cmp
    jmp .any_send_success

.any_check_pubkey:
    ; Check if method == "publickey"
    cmp eax, str_publickey_len
    jne .any_send_failure
    push rcx
    push rax
    lea rsi, [rbp + rcx + 4]
    lea rdi, [rel str_publickey]
    mov ecx, str_publickey_len
    repe cmpsb
    pop rax
    pop rcx
    jne .any_send_failure

    add ecx, 4
    add ecx, eax              ; skip method string

    ; Read boolean
    movzx r15d, byte [rbp + rcx]
    inc ecx

    ; Read algo string, verify "ssh-ed25519"
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, str_ssh_ed25519_len
    jne .any_send_failure
    push rcx
    push rax
    lea rsi, [rbp + rcx + 4]
    lea rdi, [rel str_ssh_ed25519]
    mov ecx, str_ssh_ed25519_len
    repe cmpsb
    pop rax
    pop rcx
    jne .any_send_failure
    add ecx, 4
    add ecx, eax

    ; Read public_key_blob
    mov [rsp + 1536], ecx     ; blob offset
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    mov [rsp + 1540], eax     ; blob_len
    add ecx, 4

    ; Parse inside blob: skip "ssh-ed25519", read raw pubkey
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 32
    jne .any_send_failure
    add ecx, 4

    ; Copy raw pubkey
    lea rdi, [rsp + 1440]
    lea rsi, [rbp + rcx]
    push rcx
    mov ecx, 32
    rep movsb
    pop rcx
    add ecx, 32

    ; Check if key is authorized
    mov r14d, [rsp + 1552]    ; num_keys
    mov rdi, [rsp + 1544]     ; authorized_keys_ptr
    test r14d, r14d
    jz .any_send_failure

    xor eax, eax
.any_key_scan:
    cmp eax, r14d
    jge .any_send_failure
    push rax
    push rdi
    lea rsi, [rsp + 1440 + 16]
    mov ecx, 32
    repe cmpsb
    pop rdi
    pop rax
    je .any_key_found
    add rdi, 32
    inc eax
    jmp .any_key_scan

.any_key_found:
    test r15d, r15d
    jnz .any_pk_verify

    ; --- PROBE: Send PK_OK ---
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_PK_OK
    lea rdi, [rbp + 1]
    lea rsi, [rel str_ssh_ed25519]
    mov edx, str_ssh_ed25519_len
    call encode_string
    mov ebx, eax
    inc ebx

    lea rdi, [rbp + rbx]
    mov ecx, [rsp + 1536]
    lea rsi, [rsp + 512 + rcx]
    mov eax, [rsp + 1540]
    lea edx, [eax + 4]
    push rbx
    mov ecx, edx
    rep movsb
    pop rbx
    add ebx, edx

    mov edi, r12d
    lea rsi, [rsp]
    mov edx, ebx
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .any_fail

    ; Recv second USERAUTH_REQUEST
    lea rsi, [rsp + 512]
    mov edi, r12d
    mov edx, 512
    mov rcx, r13
    call ssh_recv_packet_enc
    cmp rax, 0
    jle .any_fail
    mov ebx, eax

    lea rbp, [rsp + 512]
    cmp byte [rbp], SSH_MSG_USERAUTH_REQUEST
    jne .any_fail

    ; Re-parse second request
    mov ecx, 1

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    cmp byte [rbp + rcx], 1
    jne .any_send_failure
    inc ecx

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; Save blob offset/len
    mov [rsp + 1536], ecx
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    mov [rsp + 1540], eax
    add ecx, 4
    add ecx, eax

    ; Re-extract raw pubkey from new blob
    mov r14d, [rsp + 1536]
    movzx r14, r14d
    lea rdi, [rbp + r14 + 4]
    push rcx
    call decode_uint32
    pop rcx
    mov edx, r14d
    add edx, 4
    add edx, 4
    add edx, eax
    lea rdi, [rbp + rdx]
    push rcx
    push rdx
    call decode_uint32
    pop rdx
    pop rcx
    cmp eax, 32
    jne .any_send_failure
    add edx, 4
    push rcx
    lea rdi, [rsp + 1440 + 8]
    lea rsi, [rbp + rdx]
    mov ecx, 32
    rep movsb
    pop rcx

    ; Read signature_blob
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 64
    jne .any_send_failure
    add ecx, 4

    push rcx
    lea rdi, [rsp + 1472 + 8]
    lea rsi, [rbp + rcx]
    mov ecx, 64
    rep movsb
    pop rcx

    jmp .any_do_verify

.any_pk_verify:
    ; Direct verify (boolean TRUE in first message)
    ; Read sig_blob from current packet
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [rbp + rcx]
    push rcx
    call decode_uint32
    pop rcx
    cmp eax, 64
    jne .any_send_failure
    add ecx, 4

    push rcx
    lea rdi, [rsp + 1472 + 8]
    lea rsi, [rbp + rcx]
    mov ecx, 64
    rep movsb
    pop rcx

.any_do_verify:
    ; Build signed data in rsp+1024
    lea rbp, [rsp + 1024]
    xor ebx, ebx

    ; [string session_id]
    lea rdi, [rbp]
    lea rsi, [r13 + SSH_STATE_SESSION_ID]
    mov edx, 32
    call encode_string
    add ebx, eax

    ; [byte 50]
    mov byte [rbp + rbx], SSH_MSG_USERAUTH_REQUEST
    inc ebx

    ; Copy fields from recv buffer (offset 1 to sig_blob start)
    lea r14, [rsp + 512]
    mov ecx, 1

    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    inc ecx                    ; boolean

    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    lea rdi, [r14 + rcx]
    push rcx
    call decode_uint32
    pop rcx
    add ecx, 4
    add ecx, eax

    ; ecx = offset of sig_blob
    mov edx, ecx
    dec edx
    lea rsi, [r14 + 1]
    lea rdi, [rbp + rbx]
    push rcx
    mov ecx, edx
    rep movsb
    pop rcx
    add ebx, edx

    ; ed25519_verify
    lea rdi, [rsp + 1472]
    lea rsi, [rsp + 1024]
    mov edx, ebx
    lea rcx, [rsp + 1440]
    call ed25519_verify
    test eax, eax
    jnz .any_send_failure

.any_send_success:
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_SUCCESS
    mov edi, r12d
    lea rsi, [rbp]
    mov edx, 1
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .any_fail

    xor eax, eax
    jmp .any_done

.any_send_failure:
    lea rbp, [rsp]
    mov byte [rbp], SSH_MSG_USERAUTH_FAILURE
    lea rdi, [rbp + 1]
    ; List both password and publickey as available methods
    lea rsi, [rel str_password]
    mov edx, str_password_len
    call encode_string
    lea edx, [eax + 1]
    mov byte [rbp + rdx], 0     ; partial_success = FALSE
    inc edx
    mov edi, r12d
    lea rsi, [rbp]
    mov rcx, r13
    call ssh_send_packet_enc
    test rax, rax
    jnz .any_fail

    ; Loop back to receive the next USERAUTH_REQUEST (e.g. after "none" probe)
    jmp .any_recv_userauth

.any_fail:
    mov rax, -1

.any_done:
    add rsp, 2560
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
