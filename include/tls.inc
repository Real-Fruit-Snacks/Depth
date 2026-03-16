%ifndef TLS_INC
%define TLS_INC

; Content types
%define TLS_CT_CHANGE_CIPHER  20
%define TLS_CT_ALERT          21
%define TLS_CT_HANDSHAKE      22
%define TLS_CT_APPLICATION    23

; Versions
%define TLS_VERSION_12  0x0303
%define TLS_VERSION_13  0x0304

; Handshake types
%define TLS_HS_CLIENT_HELLO     1
%define TLS_HS_SERVER_HELLO     2
%define TLS_HS_ENCRYPTED_EXTS   8
%define TLS_HS_CERTIFICATE      11
%define TLS_HS_CERT_VERIFY      15
%define TLS_HS_FINISHED         20

; Extensions
%define TLS_EXT_SUPPORTED_VERSIONS  0x002B
%define TLS_EXT_KEY_SHARE           0x0033
%define TLS_EXT_SUPPORTED_GROUPS    0x000A
%define TLS_EXT_SIGNATURE_ALGOS     0x000D

; Cipher suite
%define TLS_CHACHA20_POLY1305_SHA256  0x1303

; Named group
%define TLS_GROUP_X25519  0x001D

; Signature algorithm
%define TLS_SIG_ED25519  0x0807

; TLS connection state offsets
%define TLS_STATE_WRITE_KEY      0     ; 32 bytes
%define TLS_STATE_WRITE_IV       32    ; 12 bytes
%define TLS_STATE_WRITE_SEQ      44    ; 8 bytes
%define TLS_STATE_READ_KEY       52    ; 32 bytes
%define TLS_STATE_READ_IV        84    ; 12 bytes
%define TLS_STATE_READ_SEQ       96    ; 8 bytes
%define TLS_STATE_SIZE           104

; Max TLS record payload
%define TLS_MAX_RECORD  16640

; Linux syscall
%define SYS_GETRANDOM  318

%endif
