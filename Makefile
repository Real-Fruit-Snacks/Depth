NASM = nasm
LD = ld
NASM_FLAGS = -f elf64 -Ox -I include/
LD_FLAGS = -nostdlib -static

.PHONY: all test clean

all: build/test_sha256 build/test_sha512 build/test_x25519 build/test_ed25519 build/test_hmac_sha256 build/test_hkdf build/test_ssh_encode build/test_ssh_aead build/test_ssh_transport build/test_ssh_kex build/test_ssh_kex_server build/test_ssh_auth build/test_ssh_pubkey build/test_ssh_channel build/test_ssh_pty build/test_ssh_e2e build/test_ssh_multichan build/test_tls13 build/test_tls_ssh build/test_bind_mode build/depth build/test_remote_fwd build/test_sftp

build/test_sha256: tests/test_sha256.asm src/sha256.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/test_sha256_harness.o tests/test_sha256.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_sha256_harness.o build/sha256.o

build/test_sha512: tests/test_sha512.asm src/sha512.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	$(NASM) $(NASM_FLAGS) -o build/test_sha512_harness.o tests/test_sha512.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_sha512_harness.o build/sha512.o

build/test_x25519: tests/test_x25519.asm src/curve25519.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/test_x25519_harness.o tests/test_x25519.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_x25519_harness.o build/curve25519.o

build/test_ed25519: tests/test_ed25519.asm src/ed25519.asm src/sha512.asm src/curve25519.asm src/sc_reduce_c.c include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512_lib.o src/sha512.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519_lib.o src/curve25519.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ed25519_harness.o tests/test_ed25519.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ed25519_harness.o build/ed25519.o build/sha512_lib.o build/curve25519_lib.o build/sc_reduce_c.o

build/test_hmac_sha256: tests/test_hmac_sha256.asm src/hmac_sha256.asm src/sha256.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/hmac_sha256.o src/hmac_sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/test_hmac_sha256_harness.o tests/test_hmac_sha256.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_hmac_sha256_harness.o build/hmac_sha256.o build/sha256.o

build/test_hkdf: tests/test_hkdf.asm src/hkdf.asm src/hmac_sha256.asm src/sha256.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/hkdf.o src/hkdf.asm
	$(NASM) $(NASM_FLAGS) -o build/hmac_sha256.o src/hmac_sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/test_hkdf_harness.o tests/test_hkdf.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_hkdf_harness.o build/hkdf.o build/hmac_sha256.o build/sha256.o

build/test_ssh_encode: tests/test_ssh_encode.asm src/ssh_encode.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_encode_harness.o tests/test_ssh_encode.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_encode_harness.o build/ssh_encode.o

build/test_ssh_aead: tests/test_ssh_aead.asm src/ssh_aead.asm include/ssh.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_aead_harness.o tests/test_ssh_aead.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_aead_harness.o build/ssh_aead.o

build/test_ssh_kex: tests/test_ssh_kex.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_kex_harness.o tests/test_ssh_kex.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_kex_harness.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_kex_server: tests/test_ssh_kex_server.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_kex_server_harness.o tests/test_ssh_kex_server.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_kex_server_harness.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_auth: tests/test_ssh_auth.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_auth_harness.o tests/test_ssh_auth.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_auth_harness.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_pubkey: tests/test_ssh_pubkey.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_pubkey_harness.o tests/test_ssh_pubkey.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_pubkey_harness.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_channel: tests/test_ssh_channel.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_channel_harness.o tests/test_ssh_channel.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_channel_harness.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_pty: tests/test_ssh_pty.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_pty_harness.o tests/test_ssh_pty.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_pty_harness.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_transport: tests/test_ssh_transport.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_transport_harness.o tests/test_ssh_transport.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_transport_harness.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_e2e: tests/test_ssh_e2e.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_e2e_harness.o tests/test_ssh_e2e.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_e2e_harness.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_ssh_multichan: tests/test_ssh_multichan.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_ssh_multichan_harness.o tests/test_ssh_multichan.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_ssh_multichan_harness.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_bind_mode: tests/test_bind_mode.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_bind_mode_harness.o tests/test_bind_mode.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_bind_mode_harness.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/depth: src/main.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/tls_io.asm src/tls13.asm src/tls_record.asm src/hkdf.asm src/hmac_sha256.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/config.inc include/ssh.inc include/tls.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/main.o src/main.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/tls_io.o src/tls_io.asm
	$(NASM) $(NASM_FLAGS) -o build/tls13.o src/tls13.asm
	$(NASM) $(NASM_FLAGS) -o build/tls_record.o src/tls_record.asm
	$(NASM) $(NASM_FLAGS) -o build/hkdf.o src/hkdf.asm
	$(NASM) $(NASM_FLAGS) -o build/hmac_sha256.o src/hmac_sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(LD) $(LD_FLAGS) -o $@ build/main.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/tls_io.o build/tls13.o build/tls_record.o build/hkdf.o build/hmac_sha256.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_remote_fwd: tests/test_remote_fwd.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_remote_fwd_harness.o tests/test_remote_fwd.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_remote_fwd_harness.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_sftp: tests/test_bind_mode.asm src/ssh_client.asm src/ssh_sftp.asm src/ssh_forward.asm src/ssh_remote_forward.asm src/ssh_pty.asm src/ssh_channel.asm src/ssh_auth.asm src/ssh_transport.asm src/io_dispatch.asm src/net.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/sc_reduce_c.c include/ssh.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/ssh_client.o src/ssh_client.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_sftp.o src/ssh_sftp.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_forward.o src/ssh_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_remote_forward.o src/ssh_remote_forward.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_pty.o src/ssh_pty.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_channel.o src/ssh_channel.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_bind_mode_harness.o tests/test_bind_mode.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_bind_mode_harness.o build/ssh_client.o build/ssh_sftp.o build/ssh_forward.o build/ssh_remote_forward.o build/ssh_pty.o build/ssh_channel.o build/ssh_auth.o build/ssh_transport.o build/io_dispatch.o build/net.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/sc_reduce_c.o

build/test_tls13: tests/test_tls13.asm src/tls13.asm src/tls_record.asm src/hkdf.asm src/hmac_sha256.asm src/sha256.asm src/curve25519.asm src/net.asm include/ssh.inc include/tls.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/tls13.o src/tls13.asm
	$(NASM) $(NASM_FLAGS) -o build/tls_record.o src/tls_record.asm
	$(NASM) $(NASM_FLAGS) -o build/hkdf.o src/hkdf.asm
	$(NASM) $(NASM_FLAGS) -o build/hmac_sha256.o src/hmac_sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	$(NASM) $(NASM_FLAGS) -o build/test_tls13_harness.o tests/test_tls13.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_tls13_harness.o build/tls13.o build/tls_record.o build/hkdf.o build/hmac_sha256.o build/sha256.o build/curve25519.o build/net.o

build/test_tls_ssh: tests/test_tls_ssh.asm src/tls13.asm src/tls_record.asm src/tls_io.asm src/io_dispatch.asm src/hkdf.asm src/hmac_sha256.asm src/ssh_transport.asm src/ssh_auth.asm src/ssh_encode.asm src/ssh_aead.asm src/sha256.asm src/curve25519.asm src/ed25519.asm src/sha512.asm src/net.asm src/sc_reduce_c.c include/ssh.inc include/tls.inc include/syscall.inc
	$(NASM) $(NASM_FLAGS) -o build/tls13.o src/tls13.asm
	$(NASM) $(NASM_FLAGS) -o build/tls_record.o src/tls_record.asm
	$(NASM) $(NASM_FLAGS) -o build/tls_io.o src/tls_io.asm
	$(NASM) $(NASM_FLAGS) -o build/io_dispatch.o src/io_dispatch.asm
	$(NASM) $(NASM_FLAGS) -o build/hkdf.o src/hkdf.asm
	$(NASM) $(NASM_FLAGS) -o build/hmac_sha256.o src/hmac_sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_transport.o src/ssh_transport.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_auth.o src/ssh_auth.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_encode.o src/ssh_encode.asm
	$(NASM) $(NASM_FLAGS) -o build/ssh_aead.o src/ssh_aead.asm
	$(NASM) $(NASM_FLAGS) -o build/sha256.o src/sha256.asm
	$(NASM) $(NASM_FLAGS) -o build/curve25519.o src/curve25519.asm
	$(NASM) $(NASM_FLAGS) -o build/ed25519.o src/ed25519.asm
	$(NASM) $(NASM_FLAGS) -o build/sha512.o src/sha512.asm
	$(NASM) $(NASM_FLAGS) -o build/net.o src/net.asm
	gcc -c -O2 -fno-stack-protector -fno-pie -o build/sc_reduce_c.o src/sc_reduce_c.c
	$(NASM) $(NASM_FLAGS) -o build/test_tls_ssh_harness.o tests/test_tls_ssh.asm
	$(LD) $(LD_FLAGS) -o $@ build/test_tls_ssh_harness.o build/tls13.o build/tls_record.o build/tls_io.o build/io_dispatch.o build/hkdf.o build/hmac_sha256.o build/ssh_transport.o build/ssh_auth.o build/ssh_encode.o build/ssh_aead.o build/sha256.o build/curve25519.o build/ed25519.o build/sha512.o build/net.o build/sc_reduce_c.o

test: all
	python3 -m pytest tests/ -v --timeout=60

clean:
	rm -f build/*
