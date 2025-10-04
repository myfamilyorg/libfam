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
#include <libfam/types.h>
#include <libfam/utils.h>

#define SYS_write 1
#define SYS_gettimeofday 96

i64 raw_syscall(i64 sysno, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5) {
	i64 result;
	register i64 _a3 __asm__("r10") = a3;
	register i64 _a4 __asm__("r8") = a4;
	register i64 _a5 __asm__("r9") = a5;
	__asm__ volatile("syscall"
			 : "=a"(result)
			 : "a"(sysno), "D"(a0), "S"(a1), "d"(a2), "r"(_a3),
			   "r"(_a4), "r"(_a5)
			 : "rcx", "r11", "memory");
	return result;
}

#if TEST == 1
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
#else
#define SYSCALL_EXIT                                     \
	__asm__ volatile(                                \
	    "movq $60, %%rax\n"                          \
	    "movq %0, %%rdi\n"                           \
	    "syscall\n"                                  \
	    :                                            \
	    : "r"((i64)status)                           \
	    : "%rax", "%rdi", "%rcx", "%r11", "memory"); \
	while (true) {                                   \
	}
#endif /* TEST */

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

