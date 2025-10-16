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
#include <libfam/linux.h>
#include <libfam/linux_time.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#ifdef __aarch64__
#define SYS_waitid 95
#elif defined(__x86_64__)
#define SYS_waitid 247
#else
#error "Unsupported platform"
#endif /* ARCH */

#define P_PID 1
#define WEXITED 4
#define WNOHANG 1
/*#define WNOWAIT 0x01000000*/

i32 await(i32 pid) {
	i64 idtype = P_PID, options = WEXITED;
	i32 v;
INIT:
	v = (i32)raw_syscall(SYS_waitid, idtype, (i64)pid, 0, options, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 reap(i32 pid) {
	i64 idtype = P_PID, options = WNOHANG | WEXITED;
	i32 v;
INIT:
	errno = SUCCESS;
	v = (i32)raw_syscall(SYS_waitid, idtype, (i64)pid, 0, options, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

PUBLIC i32 file(const u8 *path) { return open(path, O_CREAT | O_RDWR, 0600); }

PUBLIC i32 exists(const u8 *path) {
	i32 fd = open(path, O_RDWR, 0600);
	if (fd > 0) {
		close(fd);
		return 1;
	}
	return 0;
}

PUBLIC i32 open(const u8 *path, i32 flags, u32 mode) {
	return openat(AT_FDCWD, path, flags, mode);
}

PUBLIC i32 unlink(const u8 *path) { return unlinkat(AT_FDCWD, path, 0); }
PUBLIC i32 getentropy(void *buffer, u64 length) {
	return getrandom(buffer, length, GRND_RANDOM);
}
PUBLIC i32 pipe(i32 fds[2]) { return pipe2(fds, 0); }
PUBLIC i32 yield(void) { return sched_yield(); }

PUBLIC void abort(void) { _exit(1); }

PUBLIC i32 two(void) {
	struct clone_args args = {0};
	i64 ret;
	args.flags = CLONE_FILES;
	args.pidfd = 0;
	args.child_tid = 0;
	args.parent_tid = 0;
	args.exit_signal = SIGCHLD;
	args.stack = 0;
	args.stack_size = 0;
	args.tls = 0;

	ret = clone3(&args, sizeof(args));
	return (i32)ret;
}

PUBLIC i32 fork(void) {
	struct clone_args args = {0};
	i64 ret;
	args.flags = 0;
	args.pidfd = 0;
	args.child_tid = 0;
	args.parent_tid = 0;
	args.exit_signal = SIGCHLD;
	args.stack = 0;
	args.stack_size = 0;
	args.tls = 0;

	ret = clone3(&args, sizeof(args));
	return (i32)ret;
}

PUBLIC i32 flush(i32 fd) {
	i32 ret = fdatasync(fd);
	return ret;
}

PUBLIC i32 msleep(u64 millis) {
	struct timespecfam req;
	i32 ret;
	req.tv_sec = millis / 1000;
	req.tv_nsec = (millis % 1000) * 1000000;
	ret = nanosleep(&req, &req);
	return ret;
}

PUBLIC i64 fsize(i32 fd) { return lseek(fd, 0, SEEK_END); }

PUBLIC i32 fresize(i32 fd, i64 length) { return ftruncate(fd, length); }

PUBLIC void *map(u64 length) {
	void *v = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (v == MAP_FAILED) return NULL;
	return v;
}
PUBLIC void *fmap(i32 fd, i64 size, i64 offset) {
	void *v =
	    mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if (v == MAP_FAILED) return NULL;
	return v;
}

PUBLIC void *smap(u64 length) {
	void *v = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (v == MAP_FAILED) return NULL;
	return v;
}

#ifdef __aarch64__
#define SYSCALL_RESTORER     \
	__asm__ volatile(    \
	    "mov x8, #139\n" \
	    "svc #0\n" ::    \
		: "x8", "memory");
#elif defined(__x86_64__)
#define SYSCALL_RESTORER        \
	__asm__ volatile(       \
	    "movq $15, %%rax\n" \
	    "syscall\n"         \
	    :                   \
	    :                   \
	    : "%rax", "%rcx", "%r11", "memory");
#else
#error "Unsupported platform"
#endif /* ARCH */

#ifdef __aarch64__
PUBLIC void restorer(void) { SYSCALL_RESTORER; }
#elif defined(__x86_64__)
PUBLIC __attribute__((naked)) void restorer(void) { SYSCALL_RESTORER; }
#else
#error "Unsupported platform"
#endif /* ARCH */
