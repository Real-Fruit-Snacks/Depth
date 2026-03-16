%ifndef SYSCALL_INC
%define SYSCALL_INC

%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_CLOSE       3
%define SYS_SOCKET      41
%define SYS_CONNECT     42
%define SYS_POLL        7
%define SYS_FORK        57
%define SYS_EXECVE      59
%define SYS_EXIT        60
%define SYS_DUP2        33
%define SYS_SETSID      112
%define SYS_IOCTL       16
%define SYS_OPENAT      257
%define SYS_GETRANDOM   318
%define SYS_PIPE2       293
%define SYS_WAIT4       61
%define SYS_CLONE       56
%define SYS_KILL        62

; Bind mode + filesystem syscalls (Plan 14)
%define SYS_BIND        49
%define SYS_LISTEN      50
%define SYS_ACCEPT      43
%define SYS_SETSOCKOPT  54
%define SYS_NEWFSTATAT  262
%define SYS_FSTAT       5
%define SYS_GETDENTS64  217
%define SYS_UNLINKAT    263
%define SYS_MKDIRAT     258
%define SYS_RENAMEAT2   316
%define SYS_FCHMODAT    268
%define SYS_UTIMENSAT   280
%define SYS_READLINKAT  267
%define SYS_GETCWD      79

; Setsockopt constants
%define SOL_SOCKET      1
%define SO_REUSEADDR    2

; Socket constants
%define AF_INET         2
%define SOCK_STREAM     1
%define IPPROTO_TCP     6

; ioctl constants
%define TIOCSCTTY       0x540E
%define TIOCGPTN        0x80045430
%define TIOCSPTLCK      0x40045431

; lseek
%define SYS_LSEEK       8
%define SEEK_SET        0

; openat constants
%define AT_FDCWD        -100
%define O_RDONLY        0
%define O_WRONLY        1
%define O_RDWR          2
%define O_CREAT         0x40
%define O_EXCL          0x80
%define O_TRUNC         0x200
%define O_APPEND        0x400
%define O_NOCTTY        256
%define O_DIRECTORY     0x10000

; unlinkat / rmdir
%define AT_REMOVEDIR    0x200
%define AT_SYMLINK_NOFOLLOW 0x100

; poll constants
%define POLLIN          1

%endif
