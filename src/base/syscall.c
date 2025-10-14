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
#include <libfam/linux_time.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#ifdef __aarch64__
#define SYS_write 64
#define SYS_gettimeofday 169
#define SYS_getrandom 278
#elif defined(__amd64__)
#define SYS_write 1
#define SYS_gettimeofday 96
#define SYS_getrandom 318
#else
#error "Unsupported Platform"
#endif /* ARCH */

i64 raw_syscall(i64 sysno, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5) {
	i64 result;
#ifdef __aarch64__
	__asm__ volatile(
	    "mov x8, %1\n"
	    "mov x0, %2\n"
	    "mov x1, %3\n"
	    "mov x2, %4\n"
	    "mov x3, %5\n"
	    "mov x4, %6\n"
	    "mov x5, %7\n"
	    "svc #0\n"
	    "mov %0, x0\n"
	    : "=r"(result)
	    : "r"(sysno), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
	    : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory");
#elif defined(__x86_64__)
	register i64 _a3 __asm__("r10") = a3;
	register i64 _a4 __asm__("r8") = a4;
	register i64 _a5 __asm__("r9") = a5;
	__asm__ volatile("syscall"
			 : "=a"(result)
			 : "a"(sysno), "D"(a0), "S"(a1), "d"(a2), "r"(_a3),
			   "r"(_a4), "r"(_a5)
			 : "rcx", "r11", "memory");
#endif /* __x86_64__ */
	return result;
}

extern bool _debug_no_exit;

#ifdef __aarch64__
#define SYSCALL_EXIT                 \
	if (_debug_no_exit) return;  \
	__asm__ volatile(            \
	    "mov x8, #93\n"          \
	    "mov x0, %0\n"           \
	    "svc #0\n"               \
	    :                        \
	    : "r"((i64)status)       \
	    : "x8", "x0", "memory"); \
	while (true) {               \
	}
#elif defined(__x86_64__)
#define SYSCALL_EXIT                                     \
	if (_debug_no_exit) return;                      \
	__asm__ volatile(                                \
	    "movq $60, %%rax\n"                          \
	    "movq %0, %%rdi\n"                           \
	    "syscall\n"                                  \
	    :                                            \
	    : "r"((i64)status)                           \
	    : "%rax", "%rdi", "%rcx", "%r11", "memory"); \
	while (true) {                                   \
	}
#endif /* __x86_64__ */

#ifdef COVERAGE
void __gcov_dump(void);
#define SYSCALL_EXIT_COV                    \
	if (!_debug_no_exit) __gcov_dump(); \
	SYSCALL_EXIT
#endif /* COVERAGE */

PUBLIC void _exit(i32 status){
#ifdef COVERAGE
    SYSCALL_EXIT_COV
#else
    SYSCALL_EXIT
#endif
}

PUBLIC i64 write(i32 fd, const void *buf, u64 count) {
	i64 v;
INIT:
#if TEST == 1
	if ((fd == 1 || fd == 2) && _debug_no_write) return count;
#endif /* TEST */
	v = raw_syscall(SYS_write, (i64)fd, (i64)buf, (i64)count, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 gettimeofday(struct timeval *tv, void *tz) {
	i32 v;
INIT:
	if (!tv) ERROR(EINVAL);
	v = (i32)raw_syscall(SYS_gettimeofday, (i64)tv, (i64)tz, 0, 0, 0, 0);
	if (v < 0) ERROR(-v);
	OK(v);
CLEANUP:
	RETURN;
}

i32 getrandom(void *buffer, u64 length, u32 flags) {
	i64 v;
INIT:
	if (length > 256) ERROR(EIO);
	if (!buffer) ERROR(EFAULT);
	v = raw_syscall(SYS_getrandom, (i64)buffer, (i64)length, (i64)flags, 0,
			0, 0);
	if (v < 0) ERROR(-v);
	if (v < length) ERROR(EIO);
	OK(v);
CLEANUP:
	RETURN;
}
