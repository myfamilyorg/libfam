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

#include <libfam/debug.h>
#include <libfam/errno.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

#ifdef __aarch64__
#define SYS_lstat 6
#define SYS_epoll_create1 20
#define SYS_epoll_pwait 22
#define SYS_epoll_ctl 21
#define SYS_fcntl 25
#define SYS_unlinkat 35
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_lseek 62
#define SYS_read 63
#define SYS_fdatasync 83
#define SYS_fchmod 94
#define SYS_futex 98
#define SYS_nanosleep 101
#define SYS_utimes 102
#define SYS_sched_yield 124
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_getpid 172
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_shutdown 210
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_msync 227
#define SYS_clone3 435
#elif defined(__x86_64__)
#define SYS_read 0
#define SYS_close 3
#define SYS_lstat 6
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_rt_sigaction 13
#define SYS_sched_yield 24
#define SYS_msync 26
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_shutdown 48
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_kill 62
#define SYS_fcntl 72
#define SYS_fdatasync 75
#define SYS_ftruncate 77
#define SYS_fchmod 91
#define SYS_utimes 235
#define SYS_futex 202
#define SYS_epoll_ctl 233
#define SYS_openat 257
#define SYS_futimesat 261
#define SYS_fstatat 262
#define SYS_unlinkat 263
#define SYS_epoll_pwait 281
#define SYS_epoll_create1 291
#define SYS_pipe2 293
#define SYS_clone3 435
#endif /* __x86_64__ */

i32 pipe2(i32 fds[2], i32 flags) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_pipe2) ERROR();
#endif /* TEST */
	v = (i32)raw_syscall(SYS_pipe2, (i64)fds, (i64)flags, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 getpid(void) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 kill(i32 pid, i32 signal) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_kill, (i64)pid, (i64)signal, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 unlinkat(i32 dfd, const u8 *path, i32 flags) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_unlinkat, (i64)dfd, (i64)path, (i64)flags, 0,
			     0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i64 read(i32 fd, void *buf, u64 count) {
	i64 v;
INIT:
	v = raw_syscall(SYS_read, (i64)fd, (i64)buf, (i64)count, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 sched_yield(void) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

void *mmap(void *addr, u64 length, i32 prot, i32 flags, i32 fd, i64 offset) {
	void *ret =
	    (void *)(u64)raw_syscall(SYS_mmap, (i64)addr, (i64)length,
				     (i64)prot, (i64)flags, (i64)fd, offset);
	if ((i64)ret < 0) {
		errno = -(i64)ret;
		return (void *)-1;
	} else
		return ret;
}

PUBLIC i32 munmap(void *addr, u64 len) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_munmap, (i64)addr, (i64)len, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

PUBLIC i32 close(i32 fd) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_close, (i64)fd, 0, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 fcntl(i32 fd, i32 op, ...) {
	__builtin_va_list ap;
	i64 arg;
	i32 v;
INIT:

#if TEST == 1
	if (_debug_fail_fcntl) return -1;
#endif

	__builtin_va_start(ap, op);

	switch (op) {
		case F_DUPFD:
		case F_SETFD:
		case F_SETFL:
		case F_SETOWN:
		case F_SETLEASE:
			arg = __builtin_va_arg(ap, i64);
			break;
		case F_GETFD:
		case F_GETFL:
		case F_GETOWN:
		case F_GETLEASE:
			arg = 0;
			break;
		default:
			arg = 0;
			break;
	}

	__builtin_va_end(ap);

	v = (i32)raw_syscall(SYS_fcntl, (i64)fd, (i64)op, (i64)arg, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 clone3(struct clone_args *args, u64 size) {
	i32 v;
INIT:

#if TEST == 1
	if (_debug_fail_clone3) return -1;
#endif

	v = (i32)raw_syscall(SYS_clone3, (i64)args, (i64)size, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 fdatasync(i32 fd) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_fdatasync, (i64)fd, 0, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 ftruncate(i32 fd, i64 length) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_ftruncate, (i64)fd, (i64)length, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 connect(i32 sockfd, const struct sockaddr *addr, u32 addrlen) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_connect, (i64)sockfd, (i64)addr, (i64)addrlen,
			     0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 setsockopt(i32 sockfd, i32 level, i32 optname, const void *optval,
	       u32 optlen) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_setsockopt) return -1;
#endif /* TEST */

	v = (i32)raw_syscall(SYS_setsockopt, (i64)sockfd, (i64)level,
			     (i64)optname, (i64)optval, (i64)optlen, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 getsockopt(i32 sockfd, i32 level, i32 optname, void *optval, u32 *optlen) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_setsockopt) return -1;
#endif /* TEST */

	v = (i32)raw_syscall(SYS_getsockopt, (i64)sockfd, (i64)level,
			     (i64)optname, (i64)optval, (i64)optlen, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 bind(i32 sockfd, const struct sockaddr *addr, u32 addrlen) {
	i32 v;
INIT:

	v = (i32)raw_syscall(SYS_bind, (i64)sockfd, (i64)addr, (i64)addrlen, 0,
			     0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 listen(i32 sockfd, i32 backlog) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_listen) return -1;
#endif /* TEST */

	v = (i32)raw_syscall(SYS_listen, (i64)sockfd, (i64)backlog, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 getsockname(i32 sockfd, struct sockaddr *addr, u32 *addrlen) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_getsockbyname) return -1;
#endif /* TEST */
	v = (i32)raw_syscall(SYS_getsockname, (i64)sockfd, (i64)addr,
			     (i64)addrlen, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 accept(i32 sockfd, struct sockaddr *addr, u32 *addrlen) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_accept, (i64)sockfd, (i64)addr, (i64)addrlen,
			     0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 shutdown(i32 sockfd, i32 how) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_shutdown, (i64)sockfd, (i64)how, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 socket(i32 domain, i32 type, i32 protocol) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_socket, (i64)domain, (i64)type, (i64)protocol,
			     0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 epoll_create1(i32 flags) {
	i32 v;
INIT:
#if TEST == 1
	if (_debug_fail_epoll_create1) return -1;
#endif
	v = (i32)raw_syscall(SYS_epoll_create1, (i64)flags, 0, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 epoll_pwait(i32 epfd, struct epoll_event *events, i32 maxevents,
		i32 timeout, const struct sigset_t *sigmask, u64 size) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_epoll_pwait, (i64)epfd, (i64)events,
			     (i64)maxevents, (i64)timeout, (i64)sigmask,
			     (i64)size);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 epoll_ctl(i32 epfd, i32 op, i32 fd, struct epoll_event *event) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_epoll_ctl, (i64)epfd, (i64)op, (i64)fd,
			     (i64)event, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 openat(i32 dfd, const u8 *pathname, i32 flags, u32 mode) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_openat, (i64)dfd, (i64)pathname, (i64)flags,
			     (i64)mode, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i64 lseek(i32 fd, i64 offset, i32 whence) {
	i64 v;
INIT:
	v = raw_syscall(SYS_lseek, (i64)fd, (i64)offset, (i64)whence, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i64 futex(u32 *uaddr, i32 futex_op, u32 val, const struct timespec *timeout,
	  u32 *uaddr2, u32 val3) {
	i64 v;
INIT:
	v = raw_syscall(SYS_futex, (i64)uaddr, (i64)futex_op, (i64)val,
			(i64)timeout, (i64)uaddr2, (i64)val3);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 rt_sigaction(i32 signum, const struct rt_sigaction *act,
		 struct rt_sigaction *oldact, u64 sigsetsize) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_rt_sigaction, (i64)signum, (i64)act,
			     (i64)oldact, (i64)sigsetsize, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 nanosleep(const struct timespec *req, struct timespec *rem) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_nanosleep, (i64)req, (i64)rem, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 msync(void *addr, u64 length, i32 flags) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_msync, (i64)addr, (i64)length, (i64)flags, 0,
			     0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

#include <libfam/test_base.h>
i32 lstat(const u8 *path, struct stat *buf) {
	i64 v;
INIT:
	v = raw_syscall(SYS_lstat, (i64)path, (i64)buf, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 utimes(const u8 *path, const struct timeval *times) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_utimes, (i64)path, (i64)times, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 fchmod(i32 fd, u32 mode) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_fchmod, (i64)fd, (i64)mode, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 futimesat(i32 dirfd, const u8 *pathname, const struct timeval *times,
	      i32 flags) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_futimesat, (i64)dirfd, (i64)pathname,
			     (i64)times, (i64)flags, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}
i32 fstatat(i32 dirfd, const u8 *pathname, struct stat *buf, i32 flags) {
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_fstatat, (i64)dirfd, (i64)pathname, (i64)buf,
			     (i64)flags, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

