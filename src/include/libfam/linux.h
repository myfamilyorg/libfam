/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#ifndef _LINUX_H
#define _LINUX_H

#include <libfam/types.h>

/* FCNTL */
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETOWN 5
#define F_SETOWN 6
#define F_GETLEASE 10
#define F_SETLEASE 1024
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7

/* Open constants */
#define O_CREAT 0100
#define O_WRONLY 00000001
#define O_RDWR 02
#define O_EXCL 00000200
#define O_SYNC 04000000
#define O_RDONLY 00000000
#define O_NONBLOCK 04000
#define AT_FDCWD -100

/* FUTEX */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

/* MMAP */
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

/* MSYNC */
#define MS_ASYNC 1	/* sync memory asynchronously */
#define MS_INVALIDATE 2 /* invalidate the caches */
#define MS_SYNC 4	/* synchronous memory sync */

#define SEEK_SET 0  /* seek relative to beginning of file */
#define SEEK_CUR 1  /* seek relative to current file position */
#define SEEK_END 2  /* seek relative to end of file */
#define SEEK_DATA 3 /* seek to the next data */
#define SEEK_HOLE 4 /* seek to the next hole */
#define SEEK_MAX SEEK_HOLE

/* Clone flags for clone and clone3 */
#define CLONE_VM 0x00000100		/* Share memory */
#define CLONE_FS 0x00000200		/* Share filesystem info */
#define CLONE_FILES 0x00000400		/* Share file descriptors */
#define CLONE_SIGHAND 0x00000800	/* Share signal handlers */
#define CLONE_PIDFD 0x00001000		/* Return pidfd (clone3) */
#define CLONE_PTRACE 0x00002000		/* Continue ptrace */
#define CLONE_VFORK 0x00004000		/* vfork semantics */
#define CLONE_PARENT 0x00008000		/* Set parent to caller */
#define CLONE_THREAD 0x00010000		/* Same thread group */
#define CLONE_NEWNS 0x00020000		/* New mount namespace */
#define CLONE_SYSVSEM 0x00040000	/* Share System V semaphores */
#define CLONE_SETTLS 0x00080000		/* Set TLS */
#define CLONE_PARENT_SETTID 0x00100000	/* Store TID in parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* Clear TID on exit */
#define CLONE_DETACHED 0x00400000	/* Obsolete, ignored */
#define CLONE_UNTRACED 0x00800000	/* Don't trace child */
#define CLONE_CHILD_SETTID 0x01000000	/* Store TID in child */
#define CLONE_NEWCGROUP 0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000		/* New UTS namespace */
#define CLONE_NEWIPC 0x08000000		/* New IPC namespace */
#define CLONE_NEWUSER 0x10000000	/* New user namespace */
#define CLONE_NEWPID 0x20000000		/* New PID namespace */
#define CLONE_NEWNET 0x40000000		/* New network namespace */
#define CLONE_IO 0x80000000		/* Clone I/O context */

/* SIGNALS */
#define SIGHUP 1     /* Hangup */
#define SIGINT 2     /* Interrupt (Ctrl+C) */
#define SIGQUIT 3    /* Quit (Ctrl+\) */
#define SIGILL 4     /* Illegal instruction */
#define SIGTRAP 5    /* Trace/breakpoint trap */
#define SIGABRT 6    /* Abort */
#define SIGIOT 6     /* Alias for SIGABRT */
#define SIGBUS 7     /* Bus error */
#define SIGFPE 8     /* Floating-point exception */
#define SIGKILL 9    /* Kill (cannot be caught) */
#define SIGUSR1 10   /* User-defined signal 1 */
#define SIGSEGV 11   /* Segmentation fault */
#define SIGUSR2 12   /* User-defined signal 2 */
#define SIGPIPE 13   /* Broken pipe */
#define SIGALRM 14   /* Alarm clock */
#define SIGTERM 15   /* Termination */
#define SIGSTKFLT 16 /* Stack fault (rare) */
#define SIGCHLD 17   /* Child terminated/stopped */
#define SIGCONT 18   /* Continue */
#define SIGSTOP 19   /* Stop (cannot be caught) */
#define SIGTSTP 20   /* Terminal stop (Ctrl+Z) */
#define SIGTTIN 21   /* Background read from tty */
#define SIGTTOU 22   /* Background write to tty */
#define SIGURG 23    /* Urgent condition on socket */
#define SIGXCPU 24   /* CPU time limit exceeded */
#define SIGXFSZ 25   /* File size limit exceeded */
#define SIGVTALRM 26 /* Virtual timer expired */
#define SIGPROF 27   /* Profiling timer expired */
#define SIGWINCH 28  /* Window size changed */
#define SIGIO 29     /* I/O possible */
#define SIGPOLL 29   /* Alias for SIGIO */
#define SIGPWR 30    /* Power failure */
#define SIGSYS 31    /* Bad system call */
#define SIGUNUSED 31 /* Alias for SIGSYS */
#define SIGRTMIN 32  /* First real-time signal */
#define SIGRTMAX 64  /* Last real-time signal */

/* GETRANDOM */
#define GRND_RANDOM 0x0002

/* EPOLL */
#define EPOLLIN 0x00000001	  /* Available for reading */
#define EPOLLOUT 0x00000004	  /* Available for writing */
#define EPOLLPRI 0x00000002	  /* Urgent data available */
#define EPOLLERR 0x00000008	  /* Error condition */
#define EPOLLHUP 0x00000010	  /* Hang up */
#define EPOLLET 0x80000000	  /* Edge-triggered mode */
#define EPOLLONESHOT 0x40000000	  /* One-shot mode */
#define EPOLLRDHUP 0x00002000	  /* Peer closed connection */
#define EPOLLWAKEUP 0x20000000	  /* Prevent suspend */
#define EPOLLEXCLUSIVE 0x10000000 /* Exclusive wake-up mode */

#define EPOLL_CTL_ADD 1 /* Add a file descriptor to the epoll instance */
#define EPOLL_CTL_DEL 2 /* Add a file descriptor to the epoll instance */
#define EPOLL_CTL_MOD 3 /* Modify an existing file descriptor's settings */

/* shutdown */
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

/* socket */
#define AF_INET 2
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define SO_ERROR 4

/* SA_RESTORER - rt_sigaction */
#define SA_RESTORER 0x04000000

struct clone_args {
	u64 flags;
	u64 pidfd;
	u64 child_tid;
	u64 parent_tid;
	u64 exit_signal;
	u64 stack;
	u64 stack_size;
	u64 tls;
	u64 set_tid;
	u64 set_tid_size;
};

struct timeval {
	u64 tv_sec;
	u64 tv_usec;
};

struct rt_sigaction {
	void (*k_sa_handler)(i32);
	u64 k_sa_flags;
	void (*k_sa_restorer)(void);
	u64 k_sa_mask;
};

struct sockaddr {
	unsigned short sa_family;
	u8 sa_data[14];
};

typedef u32 socklen_t;

struct sockaddr_in {
	unsigned short sin_family;
	unsigned short sin_port;
	u32 sin_addr;
	u8 sin_zero[8];
};

struct timespec {
	u64 tv_sec;
	u64 tv_nsec;
};

typedef union epoll_data {
	void *ptr;
	i32 fd;
	u32 u32;
	u64 u64;
} epoll_data_t;

struct epoll_event {
	u32 events;
	epoll_data_t data;
} __attribute__((packed));

#ifndef _NSIG
#define _NSIG 64
#endif /* _NSIG */

typedef struct {
	u64 bits[_NSIG / (8 * sizeof(u64))];
} sigset_t;

#ifdef __x86_64__
struct stat {
	u64 st_dev;	  /* 64-bit */
	u64 st_ino;	  /* 64-bit */
	u64 st_nlink;	  /* 64-bit */
	u32 st_mode;	  /* 32-bit */
	u32 st_uid;	  /* 32-bit */
	u32 st_gid;	  /* 32-bit */
	u32 __pad0;	  /* 32-bit padding */
	u64 st_rdev;	  /* 64-bit */
	i64 st_size;	  /* 64-bit */
	i64 st_blksize;	  /* 64-bit */
	i64 st_blocks;	  /* 64-bit */
	u64 st_atime;	  /* 64-bit */
	u64 st_atimensec; /* 64-bit */
	u64 st_mtime;	  /* 64-bit */
	u64 st_mtimensec; /* 64-bit */
	u64 st_ctime;	  /* 64-bit */
	u64 st_ctimensec; /* 64-bit */
	i64 __unused[3];  /* 64-bit each */
};
#elif defined(__aarch64__)
struct stat {
	unsigned long st_dev;  /* Device.  */
	unsigned long st_ino;  /* File serial number.  */
	unsigned int st_mode;  /* File mode.  */
	unsigned int st_nlink; /* Link count.  */
	unsigned int st_uid;   /* User ID of the file's owner.  */
	unsigned int st_gid;   /* Group ID of the file's group. */
	unsigned long st_rdev; /* Device number, if device.  */
	unsigned long __pad1;
	long st_size;	/* Size of file, in bytes.  */
	int st_blksize; /* Optimal block size for I/O.  */
	int __pad2;
	long st_blocks; /* Number 512-byte blocks allocated. */
	long st_atime;	/* Time of last access.  */
	unsigned long st_atime_nsec;
	long st_mtime; /* Time of last modification.  */
	unsigned long st_mtime_nsec;
	long st_ctime; /* Time of last status change.  */
	unsigned long st_ctime_nsec;
	unsigned int __unused4;
	unsigned int __unused5;
};
#endif /* __aarch64__ */

i64 raw_syscall(i64 sysno, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5);

#endif /* _LINUX_H */
