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

#ifndef _BUILTIN_H
#define _BUILTIN_H

#include <libfam/types.h>

/*
 * Constant: USE_COMPILER_BUILTINS
 * Controls whether to use GCC/Clang builtin functions or inline assembly.
 * notes:
 *         Define to use __builtin_clz, __builtin_ctz, etc.
 *         Undefine to force inline assembly on supported platforms.
 *         Default: defined (uses builtins for portability and performance).
 */
#define USE_COMPILER_BUILTINS

/*
 * Function: clz_u32
 * Counts leading zeros in a 32-bit unsigned integer.
 * inputs:
 *         u32 x - value to count leading zeros in.
 * return value: u8 - number of leading zero bits (0 to 32).
 * errors: None.
 * notes:
 *         Returns 32 if x == 0.
 *         Uses __builtin_clz if USE_COMPILER_BUILTINS is defined.
 *         On x86_64: uses lzcntl instruction.
 *         On aarch64: uses clz instruction.
 *         Always inlined.
 */
static __inline u8 clz_u32(u32 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_clz(x);
#else
#ifdef __aarch64__
	u32 result;
	__asm__("clz %w0, %w1" : "=r"(result) : "r"(x));
	return result;
#else
	u32 result;
	__asm__("lzcntl %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif
#endif /* USE_COMPILER_BUILTINS */
}

/*
 * Function: clz_u64
 * Counts leading zeros in a 64-bit unsigned integer.
 * inputs:
 *         u64 x - value to count leading zeros in.
 * return value: u8 - number of leading zero bits (0 to 64).
 * errors: None.
 * notes:
 *         Returns 64 if x == 0.
 *         Uses __builtin_clzll if USE_COMPILER_BUILTINS is defined.
 *         On x86_64: uses lzcntq instruction.
 *         On aarch64: uses clz instruction.
 *         Always inlined.
 */
static __inline u8 clz_u64(u64 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_clzll(x);
#else
#ifdef __aarch64__
	u64 result;
	__asm__("clz %x0, %x1" : "=r"(result) : "r"(x));
	return result;
#else
	u64 result;
	__asm__("lzcntq %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif
#endif /* USE_COMPILER_BUILTINS */
}

/*
 * Function: clz_u128
 * Counts leading zeros in a 128-bit unsigned integer.
 * inputs:
 *         u128 x - value to count leading zeros in.
 * return value: u8 - number of leading zero bits (0 to 128).
 * errors: None.
 * notes:
 *         Returns 128 if x == 0.
 *         Implemented by checking high 64 bits first, then low.
 *         Uses clz_u64 internally.
 *         Always inlined.
 */
static __inline u8 clz_u128(u128 x) {
	u64 high = (u64)(x >> 64);
	u64 low = (u64)x;
	if (high != 0) return clz_u64(high);
	if (low != 0) return clz_u64(low) + 64;
	return 128;
}

/*
 * Function: ctz_u32
 * Counts trailing zeros in a 32-bit unsigned integer.
 * inputs:
 *         u32 x - value to count trailing zeros in.
 * return value: u8 - number of trailing zero bits (0 to 32).
 * errors: None.
 * notes:
 *         Returns 32 if x == 0.
 *         Uses __builtin_ctz if USE_COMPILER_BUILTINS is defined.
 *         On x86_64: uses tzcntl instruction.
 *         On aarch64: uses rbit + clz sequence.
 *         Always inlined.
 */
static __inline u8 ctz_u32(u32 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_ctz(x);
#else
#ifdef __aarch64__
	u32 result;
	__asm__(
	    "rbit %w0, %w1\n\t"
	    "clz %w0, %w0"
	    : "=r"(result)
	    : "r"(x));
	return result;
#else
	u32 result;
	__asm__("tzcntl %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif
#endif /* USE_COMPILER_BUILTINS */
}

/*
 * Function: ctz_u64
 * Counts trailing zeros in a 64-bit unsigned integer.
 * inputs:
 *         u64 x - value to count trailing zeros in.
 * return value: u8 - number of trailing zero bits (0 to 64).
 * errors: None.
 * notes:
 *         Returns 64 if x == 0.
 *         Uses __builtin_ctzll if USE_COMPILER_BUILTINS is defined.
 *         On x86_64: uses tzcntq instruction.
 *         On aarch64: uses rbit + clz sequence.
 *         Always inlined.
 */
static __inline u8 ctz_u64(u64 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_ctzll(x);
#else
#ifdef __aarch64__
	u64 result;
	__asm__(
	    "rbit %x0, %x1\n\t"
	    "clz %x0, %x0"
	    : "=r"(result)
	    : "r"(x));
	return result;
#else
	u64 result;
	__asm__("tzcntq %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif
#endif /* USE_COMPILER_BUILTINS */
}

/*
 * Function: trap
 * Triggers an undefined instruction trap.
 * inputs: None.
 * return value: None.
 * errors: None.
 * notes:
 *         On x86_64: emits ud2 (undefined instruction).
 *         On aarch64: emits udf #0 (permanent undefined).
 *         Marked __attribute__((unused)) to avoid warnings.
 *         Use for panic, assert failure, or unreachable code.
 *         Does not return.
 */
static __inline void __attribute__((unused)) trap(void) {
#ifdef __aarch64__
	__asm__ volatile("udf #0" ::: "memory");
#else
	__asm__ volatile("ud2" ::: "memory");
#endif
}

#endif /* _BUILTIN_H */
