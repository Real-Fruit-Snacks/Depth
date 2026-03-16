; io_dispatch.asm — I/O function pointer table for pluggable transport
;
; Provides io_read_fn and io_write_fn function pointers that ssh_transport.asm
; calls through for all network I/O. By default these point to the raw TCP
; functions (net_read_exact / net_write_all). When TLS is enabled, main.asm
; swaps them to tls_read_exact / tls_write_all after the TLS handshake.
;
; This indirection keeps ssh_transport.asm transport-agnostic without
; modifying its call sites beyond replacing `call net_read_exact` with
; `call [rel io_read_fn]`.

extern net_read_exact
extern net_write_all

section .data
align 8

; Function pointers — default to raw TCP
global io_read_fn
io_read_fn:  dq net_read_exact

global io_write_fn
io_write_fn: dq net_write_all
