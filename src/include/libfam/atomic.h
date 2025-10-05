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

#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <libfam/types.h>

static __inline i32 __cas32(u32 *ptr, u32 *expected, u32 desired) {
#ifdef __x86_64__
	return __atomic_compare_exchange_n(ptr, expected, desired, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#elif defined(__aarch64__)
	u32 result;
	i32 success;
	u32 orig_expected = *expected;
	i32 retries = 5;
	while (retries--) {
		__asm__ volatile(
		    "ldaxr %w0, [%2]\n"	   /* Load-exclusive 32-bit */
		    "cmp %w0, %w3\n"	   /* Compare with *expected */
		    "b.ne 1f\n"		   /* Jump to fail if not equal */
		    "stxr w1, %w4, [%2]\n" /* Store-exclusive desired */
		    "cbz w1, 2f\n"     /* Jump to success if store succeeded */
		    "1: mov %w1, #0\n" /* Set success = 0 (fail) */
		    "b 3f\n"
		    "2: mov %w1, #1\n" /* Set success = 1 (success) */
		    "3: dmb ish\n"     /* Memory barrier */
		    : "=&r"(result), "=&r"(success)
		    : "r"(a), "r"(*expected), "r"(desired)
		    : "w1", "memory" /* Use w1 instead of x0, x1 */
		);
		if (success) break;
		*expected = result;
		if (result != orig_expected) break;
	}
	return success;
#endif /* __aarch64__ */
}

static __inline u32 __aand32(volatile u32 *ptr, u32 value) {
	return __atomic_and_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __aadd32(volatile u32 *ptr, u32 value) {
	return __atomic_add_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __asub32(volatile u32 *ptr, u32 value) {
	return __atomic_sub_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __aor32(volatile u32 *ptr, u32 value) {
	return __atomic_or_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline i32 __cas64(u64 *ptr, u64 *expected, u64 desired) {
	return __atomic_compare_exchange_n(ptr, expected, desired, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static __inline u64 __aand64(volatile u64 *ptr, u64 value) {
	return __atomic_and_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u64 __aadd64(volatile u64 *ptr, u64 value) {
	return __atomic_add_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u64 __asub64(volatile u64 *ptr, u64 value) {
	return __atomic_sub_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u64 __aor64(volatile u64 *ptr, u64 value) {
	return __atomic_or_fetch(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __aload32(const volatile u32 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static __inline u64 __aload64(const volatile u64 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static __inline void __astore32(volatile u32 *ptr, u32 value) {
	return __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline void __astore64(volatile u64 *ptr, u64 value) {
	return __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline void mfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }

#endif /* _ATOMIC_H */
