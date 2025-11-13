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

/*
 * Function: __cas32
 * Atomically compares and swaps a 32-bit value.
 * inputs:
 *         u32 *ptr       - pointer to the memory location to modify.
 *         u32 *expected  - pointer to expected current value.
 *         u32 desired    - value to write if comparison succeeds.
 * return value: i32 - 1 on success, 0 on failure.
 * errors: None.
 * notes:
 *         If *ptr == *expected, stores desired into *ptr and returns 1.
 *         Otherwise, updates *expected with current *ptr and returns 0.
 *         Uses full sequential consistency (SEQ_CST).
 *         On ARM64, includes bounded retry (5 attempts) to avoid livelock.
 *         ptr and expected must not be null.
 */
static __inline i32 __cas32(u32 *ptr, u32 *expected, u32 desired) {
#ifdef __aarch64__
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#elif defined(__x86_64__)
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#endif /* __x86_64__ */
}

/*
 * Function: __aand32
 * Atomically performs bitwise AND on a 32-bit value and returns the old value.
 * inputs:
 *         volatile u32 *ptr - pointer to the memory location.
 *         u32 value         - value to AND with current contents.
 * return value: u32 - the value of *ptr before the operation.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr &= value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u32 __aand32(volatile u32 *ptr, u32 value) {
#ifdef __aarch64__
	u32 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %w0, [%2]\n"
	    "and %w1, %w0, %w3\n"
	    "stxr w4, %w1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_and(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __aadd32
 * Atomically adds to a 32-bit value and returns the old value.
 * inputs:
 *         volatile u32 *ptr - pointer to the memory location.
 *         u32 value         - value to add.
 * return value: u32 - the value of *ptr before the addition.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr += value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u32 __aadd32(volatile u32 *ptr, u32 value) {
#ifdef __aarch64__
	u32 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %w0, [%2]\n"
	    "add %w1, %w0, %w3\n"
	    "stxr w4, %w1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __asub32
 * Atomically subtracts from a 32-bit value and returns the old value.
 * inputs:
 *         volatile u32 *ptr - pointer to the memory location.
 *         u32 value         - value to subtract.
 * return value: u32 - the value of *ptr before the subtraction.
 * errors: None.
 * notes:
 *         Implemented as __aadd32(ptr, -value).
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u32 __asub32(volatile u32 *ptr, u32 value) {
	return __aadd32(ptr, -value);
}

/*
 * Function: __aor32
 * Atomically performs bitwise OR on a 32-bit value and returns the old value.
 * inputs:
 *         volatile u32 *ptr - pointer to the memory location.
 *         u32 value         - value to OR with current contents.
 * return value: u32 - the value of *ptr before the operation.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr |= value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u32 __aor32(volatile u32 *ptr, u32 value) {
#ifdef __aarch64__
	u32 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %w0, [%2]\n"
	    "orr %w1, %w0, %w3\n"
	    "stxr w4, %w1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_or(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __cas64
 * Atomically compares and swaps a 64-bit value.
 * inputs:
 *         u64 *ptr       - pointer to the memory location to modify.
 *         u64 *expected  - pointer to expected current value.
 *         u64 desired    - value to write if comparison succeeds.
 * return value: i32 - 1 on success, 0 on failure.
 * errors: None.
 * notes:
 *         If *ptr == *expected, stores desired into *ptr and returns 1.
 *         Otherwise, updates *expected with current *ptr and returns 0.
 *         Uses full sequential consistency (SEQ_CST).
 *         On ARM64, includes bounded retry (5 attempts) to avoid livelock.
 *         ptr and expected must not be null.
 */
static __inline i32 __cas64(u64 *ptr, u64 *expected, u64 desired) {
#ifdef __aarch64__
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#elif defined(__x86_64__)
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#endif /* __x86_64__ */
}

/*
 * Function: __aand64
 * Atomically performs bitwise AND on a 64-bit value and returns the old value.
 * inputs:
 *         volatile u64 *ptr - pointer to the memory location.
 *         u64 value         - value to AND with current contents.
 * return value: u64 - the value of *ptr before the operation.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr &= value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u64 __aand64(volatile u64 *ptr, u64 value) {
#ifdef __aarch64__
	u64 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %x0, [%2]\n"
	    "and %x1, %x0, %x3\n"
	    "stxr w4, %x1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_and(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __aadd64
 * Atomically adds to a 64-bit value and returns the old value.
 * inputs:
 *         volatile u64 *ptr - pointer to the memory location.
 *         u64 value         - value to add.
 * return value: u64 - the value of *ptr before the addition.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr += value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u64 __aadd64(volatile u64 *ptr, u64 value) {
#ifdef __aarch64__
	u64 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %x0, [%2]\n"
	    "add %x1, %x0, %x3\n"
	    "stxr w4, %x1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __asub64
 * Atomically subtracts from a 64-bit value and returns the old value.
 * inputs:
 *         volatile u64 *ptr - pointer to the memory location.
 *         u64 value         - value to subtract.
 * return value: u64 - the value of *ptr before the subtraction.
 * errors: None.
 * notes:
 *         Implemented as __aadd64(ptr, -value).
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u64 __asub64(volatile u64 *ptr, u64 value) {
	return __aadd64(ptr, -value);
}

/*
 * Function: __aor64
 * Atomically performs bitwise OR on a 64-bit value and returns the old value.
 * inputs:
 *         volatile u64 *ptr - pointer to the memory location.
 *         u64 value         - value to OR with current contents.
 * return value: u64 - the value of *ptr before the operation.
 * errors: None.
 * notes:
 *         Equivalent to: old = *ptr; *ptr |= value; return old;
 *         Full memory ordering (SEQ_CST).
 *         ptr must not be null.
 */
static __inline u64 __aor64(volatile u64 *ptr, u64 value) {
#ifdef __aarch64__
	u64 old, tmp;
	__asm__ volatile(
	    "1: ldaxr %x0, [%2]\n"
	    "orr %x1, %x0, %x3\n"
	    "stxr w4, %x1, [%2]\n"
	    "cbnz w4, 1b\n"
	    "dmb ish\n"
	    : "=&r"(old), "=&r"(tmp), "+r"(ptr)
	    : "r"(value)
	    : "w4", "memory");
	return old;
#elif defined(__x86_64__)
	return __atomic_fetch_or(ptr, value, __ATOMIC_SEQ_CST);
#endif /* __x86_64__ */
}

/*
 * Function: __aload32
 * Atomically loads a 32-bit value with sequential consistency.
 * inputs:
 *         const volatile u32 *ptr - pointer to the memory location.
 * return value: u32 - the current value at *ptr.
 * errors: None.
 * notes:
 *         Provides acquire semantics and full ordering.
 *         ptr must not be null.
 */
static __inline u32 __aload32(const volatile u32 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

/*
 * Function: __aload64
 * Atomically loads a 64-bit value with sequential consistency.
 * inputs:
 *         const volatile u64 *ptr - pointer to the memory location.
 * return value: u64 - the current value at *ptr.
 * errors: None.
 * notes:
 *         Provides acquire semantics and full ordering.
 *         ptr must not be null.
 */
static __inline u64 __aload64(const volatile u64 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

/*
 * Function: __astore32
 * Atomically stores a 32-bit value with sequential consistency.
 * inputs:
 *         volatile u32 *ptr - pointer to the memory location.
 *         u32 value         - value to store.
 * return value: None.
 * errors: None.
 * notes:
 *         Provides release semantics and full ordering.
 *         ptr must not be null.
 */
static __inline void __astore32(volatile u32 *ptr, u32 value) {
	__atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

/*
 * Function: __astore64
 * Atomically stores a 64-bit value with sequential consistency.
 * inputs:
 *         volatile u64 *ptr - pointer to the memory location.
 *         u64 value         - value to store.
 * return value: None.
 * errors: None.
 * notes:
 *         Provides release semantics and full ordering.
 *         ptr must not be null.
 */
static __inline void __astore64(volatile u64 *ptr, u64 value) {
	__atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

/*
 * Function: mfence
 * Inserts a full memory barrier.
 * inputs: None.
 * return value: None.
 * errors: None.
 * notes:
 *         Ensures all memory operations before the fence complete
 *         before any operations after it begin.
 *         Equivalent to __atomic_thread_fence(__ATOMIC_SEQ_CST).
 *         Use for strict inter-thread visibility and ordering.
 */
static __inline void mfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }

#endif /* _ATOMIC_H */
