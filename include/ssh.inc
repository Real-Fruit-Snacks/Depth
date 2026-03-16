%ifndef SSH_INC
%define SSH_INC

; SHA-256
%define SHA256_BLOCK_SIZE   64
%define SHA256_DIGEST_SIZE  32

; SHA-512
%define SHA512_BLOCK_SIZE   128
%define SHA512_DIGEST_SIZE  64

; X25519
%define X25519_KEY_SIZE     32

; Ed25519
%define ED25519_SIG_SIZE    64
%define ED25519_KEY_SIZE    32

; SSH message types (RFC 4253/4254)
%define SSH_MSG_DISCONNECT          1
%define SSH_MSG_IGNORE              2
%define SSH_MSG_UNIMPLEMENTED       3
%define SSH_MSG_SERVICE_REQUEST     5
%define SSH_MSG_SERVICE_ACCEPT      6
%define SSH_MSG_KEXINIT             20
%define SSH_MSG_NEWKEYS             21
%define SSH_MSG_KEX_ECDH_INIT       30
%define SSH_MSG_KEX_ECDH_REPLY      31
%define SSH_MSG_USERAUTH_REQUEST    50
%define SSH_MSG_USERAUTH_FAILURE    51
%define SSH_MSG_USERAUTH_SUCCESS    52
%define SSH_MSG_USERAUTH_PK_OK     60
%define SSH_MSG_GLOBAL_REQUEST      80
%define SSH_MSG_REQUEST_SUCCESS     81
%define SSH_MSG_REQUEST_FAILURE     82
%define SSH_MSG_CHANNEL_OPEN        90
%define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
%define SSH_MSG_CHANNEL_OPEN_FAILURE 92
%define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
%define SSH_MSG_CHANNEL_DATA        94
%define SSH_MSG_CHANNEL_EOF         96
%define SSH_MSG_CHANNEL_CLOSE       97
%define SSH_MSG_CHANNEL_REQUEST     98
%define SSH_MSG_CHANNEL_SUCCESS     99
%define SSH_MSG_CHANNEL_FAILURE     100

; Channel state structure
%define CHAN_STATE_LOCAL_ID       0    ; 4 bytes
%define CHAN_STATE_REMOTE_ID      4    ; 4 bytes
%define CHAN_STATE_LOCAL_WINDOW   8    ; 4 bytes
%define CHAN_STATE_REMOTE_WINDOW  12   ; 4 bytes
%define CHAN_STATE_LOCAL_MAXPKT   16   ; 4 bytes
%define CHAN_STATE_REMOTE_MAXPKT  20   ; 4 bytes
%define CHAN_STATE_WRITE_FD       24   ; 4 bytes - write fd (PTY master or stdin pipe)
%define CHAN_STATE_CHILD_PID      28   ; 4 bytes
%define CHAN_STATE_FLAGS          32   ; 4 bytes
; Extended channel state (v2) - new fields at end for backward compat
%define CHAN_STATE_TYPE           36   ; 4 bytes (0=unused, 1=session/pty, 2=direct-tcpip)
%define CHAN_STATE_FD             40   ; 4 bytes (PTY master fd or TCP socket fd)
%define CHAN_STATE_SIZE           48   ; updated from 36 (4 bytes padding for alignment)

; Multi-channel support
%define MAX_CHANNELS              8
%define CHAN_TABLE_SIZE            (CHAN_STATE_SIZE * MAX_CHANNELS)  ; 384 bytes

; Channel types
%define CHAN_TYPE_UNUSED           0
%define CHAN_TYPE_SESSION          1   ; PTY shell session
%define CHAN_TYPE_DIRECT_TCP       2   ; direct-tcpip (port forward)
%define CHAN_TYPE_SFTP             3   ; SFTP subsystem (event-loop integrated)

; ChaCha20-Poly1305 AEAD
%define CHACHA20_KEY_SIZE      32
%define POLY1305_TAG_SIZE      16
%define SSH_AEAD_KEY_SIZE      64      ; K1(32) + K2(32) per direction

; SSH packet framing
%define SSH_MAX_PACKET_SIZE    35000
%define SSH_MIN_PADDING        4
%define SSH_BLOCK_SIZE_PLAIN   8

; SFTP packet types (draft-ietf-secsh-filexfer-02, version 3)
%define SSH_FXP_INIT        1
%define SSH_FXP_VERSION     2
%define SSH_FXP_OPEN        3
%define SSH_FXP_CLOSE       4
%define SSH_FXP_READ        5
%define SSH_FXP_WRITE       6
%define SSH_FXP_LSTAT       7
%define SSH_FXP_FSTAT       8
%define SSH_FXP_SETSTAT     9
%define SSH_FXP_OPENDIR     11
%define SSH_FXP_READDIR     12
%define SSH_FXP_REMOVE      13
%define SSH_FXP_MKDIR       14
%define SSH_FXP_RMDIR       15
%define SSH_FXP_REALPATH    16
%define SSH_FXP_STAT        17
%define SSH_FXP_RENAME      18
%define SSH_FXP_STATUS      101
%define SSH_FXP_HANDLE      102
%define SSH_FXP_DATA        103
%define SSH_FXP_NAME        104
%define SSH_FXP_ATTRS       105

; SFTP status codes
%define SSH_FX_OK                0
%define SSH_FX_EOF               1
%define SSH_FX_NO_SUCH_FILE      2
%define SSH_FX_PERMISSION_DENIED 3
%define SSH_FX_FAILURE           4
%define SSH_FX_OP_UNSUPPORTED    8

; SFTP attribute flags
%define SSH_FILEXFER_ATTR_SIZE        0x01
%define SSH_FILEXFER_ATTR_UIDGID      0x02
%define SSH_FILEXFER_ATTR_PERMISSIONS 0x04
%define SSH_FILEXFER_ATTR_ACMODTIME   0x08

; SFTP open flags
%define SSH_FXF_READ    0x01
%define SSH_FXF_WRITE   0x02
%define SSH_FXF_APPEND  0x04
%define SSH_FXF_CREAT   0x08
%define SSH_FXF_TRUNC   0x10
%define SSH_FXF_EXCL    0x20

; SFTP handle table
%define SFTP_MAX_HANDLES  16
%define SFTP_HANDLE_FD    0    ; 4 bytes
%define SFTP_HANDLE_TYPE  4    ; 1 byte (0=unused, 1=file, 2=dir)
%define SFTP_HANDLE_SIZE  8

; Linux syscalls
%define SYS_READ    0
%define SYS_WRITE   1
%define SYS_EXIT    60

%endif
