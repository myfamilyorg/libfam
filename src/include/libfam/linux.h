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
#define O_DIRECT 00040000
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

#ifdef __x86_64__
struct stat {
	u64 st_dev;
	u64 st_ino;
	u64 st_nlink;
	u32 st_mode;
	u32 st_uid;
	u32 st_gid;
	u32 __pad0;
	u64 st_rdev;
	i64 st_size;
	i64 st_blksize;
	i64 st_blocks;
	u64 st_atime;
	u64 st_atimensec;
	u64 st_mtime;
	u64 st_mtimensec;
	u64 st_ctime;
	u64 st_ctimensec;
	i64 __unused[3];
};
#elif defined(__aarch64__)
struct stat {
	u64 st_dev;
	u64 st_ino;
	u32 st_mode;
	u32 st_nlink;
	u32 st_uid;
	u32 st_gid;
	u64 st_rdev;
	u64 __pad1;
	i64 st_size;
	i32 st_blksize;
	i32 __pad2;
	i64 st_blocks;
	i64 st_atime;
	u64 st_atime_nsec;
	i64 st_mtime;
	i64 st_mtime_nsec;
	i64 st_ctime;
	u64 st_ctime_nsec;
	u32 __unused4;
	u32 __unused5;
};
#endif /* __aarch64__ */

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* io_uring */

struct io_sqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 dropped;
	u32 array;
	u32 resv1;
	u64 user_addr;
};

struct io_cqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	u32 cqes;
	u32 flags;
	u32 resv1;
	u64 user_addr;
};

/*
 * IO submission data structure (Submission Queue Entry)
 */
struct io_uring_sqe {
	u8 opcode;  /* type of operation for this sqe */
	u8 flags;   /* IOSQE_ flags */
	u16 ioprio; /* ioprio for the request */
	i32 fd;	    /* file descriptor to do IO on */
	union {
		u64 off; /* offset into file */
		u64 addr2;
		struct {
			u32 cmd_op;
			u32 __pad1;
		};
	};
	union {
		u64 addr; /* pointer to buffer or iovecs */
		u64 splice_off_in;
		struct {
			u32 level;
			u32 optname;
		};
	};
	u32 len; /* buffer size or number of iovecs */
	union {
		i32 rw_flags;
		u32 fsync_flags;
		u16 poll_events;   /* compatibility */
		u32 poll32_events; /* word-reversed for BE */
		u32 sync_range_flags;
		u32 msg_flags;
		u32 timeout_flags;
		u32 accept_flags;
		u32 cancel_flags;
		u32 open_flags;
		u32 statx_flags;
		u32 fadvise_advice;
		u32 splice_flags;
		u32 rename_flags;
		u32 unlink_flags;
		u32 hardlink_flags;
		u32 xattr_flags;
		u32 msg_ring_flags;
		u32 uring_cmd_flags;
		u32 waitid_flags;
		u32 futex_flags;
		u32 install_fd_flags;
	};
	u64 user_data; /* data to be passed back at completion time */
	/* pack this to avoid bogus arm OABI complaints */
	union {
		/* index into fixed buffers, if used */
		u16 buf_index;
		/* for grouped buffer selection */
		u16 buf_group;
	} __attribute__((packed));
	/* personality to use, if used */
	u16 personality;
	union {
		i32 splice_fd_in;
		u32 file_index;
		u32 optlen;
		struct {
			u16 addr_len;
			u16 __pad3[1];
		};
	};
	union {
		struct {
			u64 addr3;
			u64 __pad2[1];
		};
		u64 optval;
		/*
		 * If the ring is initialized with IORING_SETUP_SQE128, then
		 * this field is used for 80 bytes of arbitrary command data
		 */
		u8 cmd[0];
	};
};

/*
 * cq_ring->flags
 */

/* disable eventfd notifications */
#define IORING_CQ_EVENTFD_DISABLED (1U << 0)

/*
 * io_uring_enter(2) flags
 */
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_SQ_WAIT (1U << 2)
#define IORING_ENTER_EXT_ARG (1U << 3)
#define IORING_ENTER_REGISTERED_RING (1U << 4)

/*
 * io_uring_register(2) opcodes and arguments
 */
enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,

	/* extended with tagging */
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,

	/* set/clear io-wq thread affinities */
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,

	/* set/get max number of io-wq workers */
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,

	/* register/unregister io_uring fd with the ring */
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,

	/* register ring based provide buffer group */
	IORING_REGISTER_PBUF_RING = 22,
	IORING_UNREGISTER_PBUF_RING = 23,

	/* sync cancelation API */
	IORING_REGISTER_SYNC_CANCEL = 24,

	/* register a range of fixed file slots for automatic slot allocation */
	IORING_REGISTER_FILE_ALLOC_RANGE = 25,

	/* return status information for a buffer group */
	IORING_REGISTER_PBUF_STATUS = 26,

	/* this goes last */
	IORING_REGISTER_LAST,

	/* flag added to the opcode to use a registered ring fd */
	IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
};

#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL
#define IORING_OFF_PBUF_RING 0x80000000ULL
#define IORING_OFF_PBUF_SHIFT 16
#define IORING_OFF_MMAP_MASK 0xf8000000ULL

/*
 * IO completion data structure (Completion Queue Entry)
 */
struct io_uring_cqe {
	u64 user_data; /* sqe->data submission passed back */
	i32 res;       /* result code for this event */
	u32 flags;

	/*
	 * If the ring is initialized with IORING_SETUP_CQE32, then this field
	 * contains 16-bytes of padding, doubling the size of the CQE.
	 */
	u64 big_cqe[];
};

struct io_uring_params {
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	u32 sq_thread_cpu;
	u32 sq_thread_idle;
	u32 features;
	u32 wq_fd;
	u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

enum io_uring_op {
	IORING_OP_NOP,
	IORING_OP_READV,
	IORING_OP_WRITEV,
	IORING_OP_FSYNC,
	IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED,
	IORING_OP_POLL_ADD,
	IORING_OP_POLL_REMOVE,
	IORING_OP_SYNC_FILE_RANGE,
	IORING_OP_SENDMSG,
	IORING_OP_RECVMSG,
	IORING_OP_TIMEOUT,
	IORING_OP_TIMEOUT_REMOVE,
	IORING_OP_ACCEPT,
	IORING_OP_ASYNC_CANCEL,
	IORING_OP_LINK_TIMEOUT,
	IORING_OP_CONNECT,
	IORING_OP_FALLOCATE,
	IORING_OP_OPENAT,
	IORING_OP_CLOSE,
	IORING_OP_FILES_UPDATE,
	IORING_OP_STATX,
	IORING_OP_READ,
	IORING_OP_WRITE,
	IORING_OP_FADVISE,
	IORING_OP_MADVISE,
	IORING_OP_SEND,
	IORING_OP_RECV,
	IORING_OP_OPENAT2,
	IORING_OP_EPOLL_CTL,
	IORING_OP_SPLICE,
	IORING_OP_PROVIDE_BUFFERS,
	IORING_OP_REMOVE_BUFFERS,
	IORING_OP_TEE,
	IORING_OP_SHUTDOWN,
	IORING_OP_RENAMEAT,
	IORING_OP_UNLINKAT,
	IORING_OP_MKDIRAT,
	IORING_OP_SYMLINKAT,
	IORING_OP_LINKAT,
	IORING_OP_MSG_RING,
	IORING_OP_FSETXATTR,
	IORING_OP_SETXATTR,
	IORING_OP_FGETXATTR,
	IORING_OP_GETXATTR,
	IORING_OP_SOCKET,
	IORING_OP_URING_CMD,
	IORING_OP_SEND_ZC,
	IORING_OP_SENDMSG_ZC,
	IORING_OP_READ_MULTISHOT,
	IORING_OP_WAITID,
	IORING_OP_FUTEX_WAIT,
	IORING_OP_FUTEX_WAKE,
	IORING_OP_FUTEX_WAITV,
	IORING_OP_FIXED_FD_INSTALL,
	IORING_OP_LAST,
};

struct iovec {
	void *iov_base; /* Pointer to data.  */
	u64 iov_len;	/* Length of data.  */
};

i64 raw_syscall(i64 sysno, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5);

#endif /* _LINUX_H */
