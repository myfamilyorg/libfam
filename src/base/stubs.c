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

/*#include <libfam/string.h>*/
#include <libfam/syscall.h>
#include <libfam/utils.h>

PUBLIC void __stack_chk_fail(void) {
	/*i32 __attribute__((unused)) _v;
	const u8 *msg = "STACK_CHK_FAIL\n";
	_v = write(STDERR_FD, msg, strlen(msg));*/
	_exit(-1);
}

PUBLIC void __stack_chk_guard(void) {
	/*i32 __attribute__((unused)) _v;
	const u8 *msg = "STACK_CHK_GUARD\n";
	_v = write(STDERR_FD, msg, strlen(msg));*/
	_exit(-1);
}

#ifdef __aarch64__

u32 __aarch64_cas4_acq_rel(volatile u32 *p, u32 old_val, u32 new_val) {
	u32 read, tmp;
	__asm__ __volatile__(
	    "1: ldaxr   %w0, [%2]\n"
	    "   cmp     %w0, %w3\n"
	    "   b.ne    2f\n"
	    "   stlxr   %w1, %w4, [%2]\n"
	    "   cbnz    %w1, 1b\n"
	    "2:\n"
	    : "=&r"(read), "=&r"(tmp)
	    : "r"(p), "r"(old_val), "r"(new_val)
	    : "memory", "cc");
	return read;
}

// Full acq_rel atomic fetch-add, returns old value
u32 __aarch64_ldadd4_acq_rel(volatile u32 *p, u32 val) {
	u32 old, new_val, tmp;
	__asm__ __volatile__(
	    "1: ldaxr   %w0, [%3]\n"
	    "   add     %w1, %w0, %w2\n"
	    "   stlxr   %w2, %w1, [%3]\n"
	    "   cbnz    %w2, 1b\n"
	    : "=&r"(old), "=&r"(new_val), "=&r"(tmp)
	    : "r"(p), "r"(val)
	    : "memory", "cc");
	return old;
}

#endif /* __aarch64__ */
