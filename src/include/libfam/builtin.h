/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of u8ge, to any person obtaining a copy
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

#define USE_COMPILER_BUILTINS

static __inline u8 clz_u32(u32 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_clz(x);
#else
	u32 result;
	__asm__("lzcntl %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif /* USE_COMPILER_BUILTINS */
}

static __inline u8 clz_u64(u64 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_clzll(x);
#else
	u64 result;
	__asm__("lzcntq %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif /* USE_COMPILER_BUILTINS */
}

static __inline u8 clz_u128(u128 x) {
	u64 high = (u64)(x >> 64);
	u64 low = (u64)x;
	if (high != 0) return clz_u64(high);
	if (low != 0) return clz_u64(low) + 64;
	return 128;
}

static __inline u8 ctz_u32(u32 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_ctz(x);
#else
	u32 result;
	__asm__("tzcntl %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif /* USE_COMPILER_BUILTINS */
}

static __inline u8 ctz_u64(u64 x) {
#ifdef USE_COMPILER_BUILTINS
	return __builtin_ctzll(x);
#else
	u64 result;
	__asm__("tzcntq %1, %0" : "=r"(result) : "r"(x) :);
	return result;
#endif /* USE_COMPILER_BUILTINS */
}

static __inline void __attribute__((unused)) trap(void) {
	__asm__ volatile("ud2" ::: "memory");
}

#endif /* _BUILTIN_H */
