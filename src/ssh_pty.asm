; ssh_pty.asm - PTY allocation, shell spawning, and I/O relay
; Pure x86-64 Linux syscalls, no libc
;
; Functions:
;   ssh_pty_alloc        - Allocate PTY master/slave pair
;   ssh_pty_spawn_shell  - Fork and exec /bin/bash
;   ssh_pty_spawn_exec   - Fork and exec arbitrary command via bash -c
;   ssh_pty_relay        - I/O relay between PTY master and SSH channel

%include "ssh.inc"
%include "syscall.inc"

; External functions (ssh_channel.asm)
extern ssh_channel_send_data
extern ssh_channel_recv
extern ssh_channel_send_eof_close
extern stack_probe

; Constants
%define SIGCHLD         17
%define WNOHANG         1

section .rodata
align 8
ptmx_path:      db "/dev/ptmx", 0
pts_prefix:     db "/dev/pts/", 0
pts_prefix_len  equ $ - pts_prefix - 1  ; 9 bytes without null
bash_path:      db "/bin/bash", 0
bash_arg_c:     db "-c", 0

section .text

; ============================================================================
; ssh_pty_alloc(rdi=master_fd_out_ptr, rsi=slave_fd_out_ptr) -> rax=0 or -1
;
; Opens /dev/ptmx, unlocks slave, gets pty number, opens /dev/pts/N
; Stores master_fd at [rdi], slave_fd at [rsi]
; ============================================================================
global ssh_pty_alloc
ssh_pty_alloc:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64                 ; stack: [0..31] path buffer, [32..35] int buf

    mov r12, rdi                ; master_fd_out_ptr
    mov r13, rsi                ; slave_fd_out_ptr

    ; Step 1: openat(AT_FDCWD, "/dev/ptmx", O_RDWR | O_NOCTTY)
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel ptmx_path]
    mov edx, O_RDWR | O_NOCTTY ; 2 | 256 = 258
    xor r10d, r10d
    syscall
    test rax, rax
    js .alloc_fail
    mov r14d, eax               ; master_fd

    ; Step 2: ioctl(master_fd, TIOCSPTLCK, &zero) — unlock slave
    mov dword [rsp + 32], 0     ; zero value
    mov eax, SYS_IOCTL
    mov edi, r14d
    mov esi, TIOCSPTLCK
    lea rdx, [rsp + 32]
    syscall
    test rax, rax
    js .alloc_fail_close_master

    ; Step 3: ioctl(master_fd, TIOCGPTN, &pty_num) — get PTY number
    mov eax, SYS_IOCTL
    mov edi, r14d
    mov esi, TIOCGPTN
    lea rdx, [rsp + 32]
    syscall
    test rax, rax
    js .alloc_fail_close_master

    mov ebx, [rsp + 32]        ; pty_num

    ; Step 4: Build "/dev/pts/N" string on stack
    ; Copy prefix "/dev/pts/" to path buffer
    lea rdi, [rsp]
    lea rsi, [rel pts_prefix]
    mov ecx, pts_prefix_len
    rep movsb
    ; rdi now points to where digits go

    ; Convert pty_num (ebx) to ASCII digits
    ; Use repeated division by 10, push remainders, then pop
    mov eax, ebx
    xor ecx, ecx               ; digit count
    test eax, eax
    jnz .itoa_loop
    ; pty_num is 0
    mov byte [rdi], '0'
    inc rdi
    jmp .itoa_done

.itoa_loop:
    test eax, eax
    jz .itoa_reverse
    xor edx, edx
    mov ebx, 10
    div ebx                     ; eax = quotient, edx = remainder
    add dl, '0'
    push rdx                    ; push digit char
    inc ecx
    jmp .itoa_loop

.itoa_reverse:
    test ecx, ecx
    jz .itoa_done
    pop rdx
    mov byte [rdi], dl
    inc rdi
    dec ecx
    jmp .itoa_reverse

.itoa_done:
    mov byte [rdi], 0           ; null terminate

    ; Step 5: openat(AT_FDCWD, "/dev/pts/N", O_RDWR)
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rsp]              ; path buffer
    mov edx, O_RDWR
    xor r10d, r10d
    syscall
    test rax, rax
    js .alloc_fail_close_master

    ; Step 6: Store results
    mov [r12], r14d             ; *master_fd_out = master_fd
    mov [r13], eax              ; *slave_fd_out = slave_fd

    xor eax, eax
    jmp .alloc_done

.alloc_fail_close_master:
    ; Close master_fd
    mov eax, SYS_CLOSE
    mov edi, r14d
    syscall

.alloc_fail:
    mov rax, -1

.alloc_done:
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_pty_spawn_shell(edi=master_fd, esi=slave_fd) -> rax=child_pid or -1
;
; Fork via clone(SIGCHLD). Child: setsid, set ctty, dup2, execve /bin/bash
; Parent: close slave_fd, return child_pid
; ============================================================================
global ssh_pty_spawn_shell
ssh_pty_spawn_shell:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8                  ; align stack

    mov r12d, edi               ; master_fd
    mov r13d, esi               ; slave_fd

    ; clone(SIGCHLD, 0, 0, 0, 0)
    mov eax, SYS_CLONE
    mov edi, SIGCHLD
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    js .spawn_shell_fail
    jnz .spawn_shell_parent

    ; ---- CHILD PROCESS ----

    ; setsid()
    mov eax, SYS_SETSID
    syscall

    ; ioctl(slave_fd, TIOCSCTTY, 0) — set controlling terminal
    mov eax, SYS_IOCTL
    mov edi, r13d
    mov esi, TIOCSCTTY
    xor edx, edx
    syscall

    ; dup2(slave_fd, 0)
    mov eax, SYS_DUP2
    mov edi, r13d
    xor esi, esi
    syscall

    ; dup2(slave_fd, 1)
    mov eax, SYS_DUP2
    mov edi, r13d
    mov esi, 1
    syscall

    ; dup2(slave_fd, 2)
    mov eax, SYS_DUP2
    mov edi, r13d
    mov esi, 2
    syscall

    ; close(master_fd)
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall

    ; close(slave_fd) — already duped to 0,1,2
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; execve("/bin/bash", ["/bin/bash", NULL], [NULL])
    ; Build argv on stack
    sub rsp, 32
    lea rax, [rel bash_path]
    mov [rsp], rax              ; argv[0] = "/bin/bash"
    mov qword [rsp + 8], 0     ; argv[1] = NULL
    mov qword [rsp + 16], 0    ; envp[0] = NULL

    lea rdi, [rel bash_path]   ; filename
    lea rsi, [rsp]             ; argv
    lea rdx, [rsp + 16]       ; envp
    mov eax, SYS_EXECVE
    syscall

    ; If execve fails, exit
    mov eax, SYS_EXIT
    mov edi, 127
    syscall

    ; ---- PARENT PROCESS ----
.spawn_shell_parent:
    mov r14d, eax               ; save child_pid

    ; close(slave_fd)
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    mov eax, r14d               ; return child_pid
    jmp .spawn_shell_done

.spawn_shell_fail:
    mov rax, -1

.spawn_shell_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_pty_spawn_exec(edi=master_fd, esi=slave_fd, rdx=cmd, ecx=cmd_len)
;     -> rax=child_pid or -1
;
; Fork and exec: /bin/bash -c <cmd>
; The cmd is copied to a stack buffer and null-terminated.
; ============================================================================
global ssh_pty_spawn_exec
ssh_pty_spawn_exec:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, 4104
    call stack_probe
    sub rsp, 4104               ; 4096 cmd buf + 8 align

    mov r12d, edi               ; master_fd
    mov r13d, esi               ; slave_fd
    mov r14, rdx                ; cmd ptr
    mov r15d, ecx               ; cmd_len

    ; Copy command to stack buffer and null-terminate
    cmp r15d, 4095
    ja .spawn_exec_fail         ; cmd too long
    lea rdi, [rsp]
    mov rsi, r14
    mov ecx, r15d
    rep movsb
    mov byte [rdi], 0           ; null terminate

    ; clone(SIGCHLD, 0, 0, 0, 0)
    mov eax, SYS_CLONE
    mov edi, SIGCHLD
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    js .spawn_exec_fail
    jnz .spawn_exec_parent

    ; ---- CHILD PROCESS ----

    ; setsid()
    mov eax, SYS_SETSID
    syscall

    ; ioctl(slave_fd, TIOCSCTTY, 0)
    mov eax, SYS_IOCTL
    mov edi, r13d
    mov esi, TIOCSCTTY
    xor edx, edx
    syscall

    ; dup2(slave_fd, 0/1/2)
    mov eax, SYS_DUP2
    mov edi, r13d
    xor esi, esi
    syscall
    mov eax, SYS_DUP2
    mov edi, r13d
    mov esi, 1
    syscall
    mov eax, SYS_DUP2
    mov edi, r13d
    mov esi, 2
    syscall

    ; close(master_fd), close(slave_fd)
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; execve("/bin/bash", ["/bin/bash", "-c", cmd_str, NULL], [NULL])
    ; cmd_str is at rsp (still valid after fork — clone shares address space initially
    ; but with COW, the stack buffer we wrote is still at the same address)
    sub rsp, 64
    lea rax, [rel bash_path]
    mov [rsp], rax              ; argv[0] = "/bin/bash"
    lea rax, [rel bash_arg_c]
    mov [rsp + 8], rax          ; argv[1] = "-c"
    lea rax, [rsp + 64]        ; argv[2] = cmd_str (at old rsp)
    mov [rsp + 16], rax
    mov qword [rsp + 24], 0    ; argv[3] = NULL
    mov qword [rsp + 32], 0    ; envp[0] = NULL

    lea rdi, [rel bash_path]
    lea rsi, [rsp]             ; argv
    lea rdx, [rsp + 32]       ; envp
    mov eax, SYS_EXECVE
    syscall

    ; If execve fails, exit
    mov eax, SYS_EXIT
    mov edi, 127
    syscall

    ; ---- PARENT PROCESS ----
.spawn_exec_parent:
    mov ebp, eax                ; save child_pid

    ; close(slave_fd)
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    mov eax, ebp                ; return child_pid
    jmp .spawn_exec_done

.spawn_exec_fail:
    mov rax, -1

.spawn_exec_done:
    add rsp, 4104
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_pty_spawn_exec_pipe(rdi=cmd_ptr, esi=cmd_len)
;     -> rax=stdout_read_fd, edx=stdin_write_fd, ecx=child_pid
;     -> rax=-1 on failure
;
; Spawns a command via pipes (no PTY) for exec-without-pty support.
; Uses pipe2(2) to create stdin/stdout pipes, clone(SIGCHLD) to fork,
; then wires the child's stdio to the pipes and execve's bash -c <cmd>.
; ============================================================================
global ssh_pty_spawn_exec_pipe
ssh_pty_spawn_exec_pipe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, 4120
    call stack_probe
    sub rsp, 4120               ; 16 pipe fds + 4096 cmd buf + 8 align

    ; Stack layout:
    ;   [rsp +  0]  stdin_pipe[0]  (read  end, 4 bytes)
    ;   [rsp +  4]  stdin_pipe[1]  (write end, 4 bytes)
    ;   [rsp +  8]  stdout_pipe[0] (read  end, 4 bytes)
    ;   [rsp + 12]  stdout_pipe[1] (write end, 4 bytes)
    ;   [rsp + 16]  command buffer (4096 bytes)

    mov r14, rdi                ; cmd_ptr
    mov r15d, esi               ; cmd_len

    ; Clamp and copy command to stack buffer, null-terminate
    cmp r15d, 4095
    ja .exec_pipe_fail          ; cmd too long
    lea rdi, [rsp + 16]
    mov rsi, r14
    mov ecx, r15d
    rep movsb
    mov byte [rdi], 0           ; null terminate

    ; pipe2(stdin_pipe, 0)
    mov eax, SYS_PIPE2
    lea rdi, [rsp]              ; &stdin_pipe[0]
    xor esi, esi                ; flags = 0
    syscall
    test rax, rax
    js .exec_pipe_fail

    ; pipe2(stdout_pipe, 0)
    mov eax, SYS_PIPE2
    lea rdi, [rsp + 8]          ; &stdout_pipe[0]
    xor esi, esi
    syscall
    test rax, rax
    js .exec_pipe_fail_close_stdin

    ; clone(SIGCHLD, 0, 0, 0, 0)
    mov eax, SYS_CLONE
    mov edi, SIGCHLD
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    js .exec_pipe_fail_close_all
    jnz .exec_pipe_parent

    ; ---- CHILD PROCESS ----

    ; dup2(stdin_pipe[0], 0)  — wire stdin
    mov eax, SYS_DUP2
    mov edi, dword [rsp]        ; stdin_pipe[0]
    xor esi, esi
    syscall

    ; dup2(stdout_pipe[1], 1) — wire stdout
    mov eax, SYS_DUP2
    mov edi, dword [rsp + 12]   ; stdout_pipe[1]
    mov esi, 1
    syscall

    ; dup2(stdout_pipe[1], 2) — merge stderr into stdout
    mov eax, SYS_DUP2
    mov edi, dword [rsp + 12]   ; stdout_pipe[1]
    mov esi, 2
    syscall

    ; Close all four pipe fds
    mov eax, SYS_CLOSE
    mov edi, dword [rsp]        ; stdin_pipe[0]
    syscall
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 4]    ; stdin_pipe[1]
    syscall
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 8]    ; stdout_pipe[0]
    syscall
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 12]   ; stdout_pipe[1]
    syscall

    ; execve("/bin/bash", ["/bin/bash", "-c", cmd_str, NULL], [NULL])
    ; cmd_str is at rsp+16 (still valid after clone COW)
    sub rsp, 64
    lea rax, [rel bash_path]
    mov [rsp], rax              ; argv[0] = "/bin/bash"
    lea rax, [rel bash_arg_c]
    mov [rsp + 8], rax          ; argv[1] = "-c"
    lea rax, [rsp + 64 + 16]   ; argv[2] = cmd_str (at old rsp+16)
    mov [rsp + 16], rax
    mov qword [rsp + 24], 0    ; argv[3] = NULL
    mov qword [rsp + 32], 0    ; envp[0] = NULL

    lea rdi, [rel bash_path]
    lea rsi, [rsp]             ; argv
    lea rdx, [rsp + 32]       ; envp
    mov eax, SYS_EXECVE
    syscall

    ; execve failed — exit 127
    mov eax, SYS_EXIT
    mov edi, 127
    syscall

    ; ---- PARENT PROCESS ----
.exec_pipe_parent:
    mov ebp, eax                ; save child_pid

    ; Close stdin_pipe[0] — child's read end
    mov eax, SYS_CLOSE
    mov edi, dword [rsp]
    syscall

    ; Close stdout_pipe[1] — child's write end
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 12]
    syscall

    ; Return: rax=stdout_pipe[0], edx=stdin_pipe[1], ecx=child_pid
    mov eax, dword [rsp + 8]    ; stdout_pipe[0]
    mov edx, dword [rsp + 4]    ; stdin_pipe[1]
    mov ecx, ebp                ; child_pid
    jmp .exec_pipe_done

.exec_pipe_fail_close_all:
    ; Close stdout_pipe fds
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 8]    ; stdout_pipe[0]
    syscall
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 12]   ; stdout_pipe[1]
    syscall

.exec_pipe_fail_close_stdin:
    ; Close stdin_pipe fds
    mov eax, SYS_CLOSE
    mov edi, dword [rsp]        ; stdin_pipe[0]
    syscall
    mov eax, SYS_CLOSE
    mov edi, dword [rsp + 4]    ; stdin_pipe[1]
    syscall

.exec_pipe_fail:
    mov rax, -1

.exec_pipe_done:
    add rsp, 4120
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; ============================================================================
; ssh_pty_relay(edi=sock_fd, rsi=state_ptr, rdx=chan_state_ptr,
;               ecx=master_fd, r8d=child_pid) -> rax=0
;
; Main I/O relay loop:
;   1. poll([master_fd, sock_fd], POLLIN, 100ms)
;   2. If master_fd readable: read from PTY, ssh_channel_send_data
;   3. If sock_fd readable: ssh_channel_recv, write to PTY
;   4. Check child status with waitpid(WNOHANG)
;   5. If child exited: ssh_channel_send_eof_close, return
;   6. If channel closed (recv returns -97): kill child, return
; ============================================================================
global ssh_pty_relay
ssh_pty_relay:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rax, 4144
    call stack_probe
    sub rsp, 4144               ; pollfd(16) + status(4) + pty_buf(4096) + padding(28)

    ; Layout:
    ;   [rsp + 0]    pollfd[0] (master_fd) — 8 bytes
    ;   [rsp + 8]    pollfd[1] (sock_fd) — 8 bytes
    ;   [rsp + 16]   wait status — 4 bytes
    ;   [rsp + 32]   pty I/O buffer — 4096 bytes
    ;   [rsp + 4128] padding

    mov r12d, edi               ; sock_fd
    mov r13, rsi                ; state_ptr
    mov r14, rdx                ; chan_state_ptr
    mov r15d, ecx               ; master_fd
    mov ebp, r8d                ; child_pid

.relay_loop:
    ; Build pollfd array
    ; pollfd[0]: master_fd, POLLIN
    mov dword [rsp], r15d       ; fd = master_fd
    mov word [rsp + 4], POLLIN  ; events
    mov word [rsp + 6], 0       ; revents

    ; pollfd[1]: sock_fd, POLLIN
    mov dword [rsp + 8], r12d   ; fd = sock_fd
    mov word [rsp + 12], POLLIN ; events
    mov word [rsp + 14], 0      ; revents

    ; poll(pollfds, 2, 100)
    mov eax, SYS_POLL
    lea rdi, [rsp]
    mov esi, 2
    mov edx, 100                ; 100ms timeout
    syscall
    ; rax < 0 = error, 0 = timeout, >0 = events ready

    cmp rax, 0
    jl .relay_check_child       ; poll error, check child status
    je .relay_check_child       ; timeout, check child status

    ; Check master_fd (PTY output → SSH channel)
    test word [rsp + 6], POLLIN
    jz .relay_check_sock

    ; Read from PTY master
    mov eax, SYS_READ
    mov edi, r15d
    lea rsi, [rsp + 32]
    mov edx, 4096
    syscall
    cmp rax, 0
    jle .relay_child_exited     ; EOF or error from PTY = child likely exited

    ; Send data through SSH channel
    mov ebx, eax                ; save read count
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, r14                ; chan_state_ptr
    lea rcx, [rsp + 32]        ; data
    mov r8d, ebx                ; data_len
    call ssh_channel_send_data
    ; Ignore send errors for now (window exhaustion etc)

.relay_check_sock:
    ; Check sock_fd (SSH channel data → PTY)
    test word [rsp + 14], POLLIN
    jz .relay_check_child

    ; Receive from SSH channel
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, r14                ; chan_state_ptr
    lea rcx, [rsp + 32]        ; buffer
    mov r8d, 4096               ; max_len
    call ssh_channel_recv
    ; rax > 0: data bytes, -96: EOF, -97: CLOSE, -98: REQUEST

    cmp rax, -97
    je .relay_channel_closed    ; CHANNEL_CLOSE
    cmp rax, -96
    je .relay_channel_closed    ; CHANNEL_EOF — treat as close for v1
    cmp rax, 0
    jle .relay_check_child      ; error or control msg, continue

    ; Write received data to PTY master
    mov ebx, eax                ; data_len
    mov eax, SYS_WRITE
    mov edi, r15d               ; master_fd
    lea rsi, [rsp + 32]
    mov edx, ebx
    syscall

.relay_check_child:
    ; waitpid(child_pid, &status, WNOHANG)
    mov eax, SYS_WAIT4
    mov edi, ebp                ; child_pid
    lea rsi, [rsp + 16]        ; &status
    mov edx, WNOHANG
    xor r10d, r10d              ; rusage = NULL
    syscall
    ; rax > 0 means child exited
    cmp rax, 0
    jg .relay_child_exited

    ; Continue relay loop
    jmp .relay_loop

.relay_child_exited:
    ; Child exited — send EOF+CLOSE on SSH channel
    mov edi, r12d               ; sock_fd
    mov rsi, r13                ; state_ptr
    mov rdx, r14                ; chan_state_ptr
    call ssh_channel_send_eof_close

    ; Close master_fd
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall

    xor eax, eax
    jmp .relay_done

.relay_channel_closed:
    ; Channel closed by remote — kill child process
    mov eax, SYS_KILL
    mov edi, ebp                ; child_pid
    mov esi, 9                  ; SIGKILL
    syscall

    ; Wait for child to clean up
    mov eax, SYS_WAIT4
    mov edi, ebp
    lea rsi, [rsp + 16]
    xor edx, edx               ; flags = 0 (blocking)
    xor r10d, r10d
    syscall

    ; Close master_fd
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall

    xor eax, eax

.relay_done:
    add rsp, 4144
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
