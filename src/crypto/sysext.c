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

#include <libfam/atomic.h>
#include <libfam/sha3.h>
#include <libfam/string.h>

static inline u64 read_cycle_counter(void) {
#if defined(__x86_64__)
	u32 lo, hi;
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((u64)hi << 32) | lo;

#elif defined(__aarch64__)
	u64 cnt;
	__asm__ __volatile__("isb" : : : "memory");
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
	return cnt;
#else
#error "Unsupported architecture"
#endif
}

static u64 global_entropy_counter = 1;

void random32(u8 out[32]) {
	Sha3Context ctx;
	u64 x[4];
	x[0] = read_cycle_counter();
	x[1] = (u64)__builtin_return_address(0);
	x[2] = (u64)__builtin_frame_address(0);
	x[3] = __aadd64(&global_entropy_counter, 1);
	sha3_init256(&ctx);
	sha3_update(&ctx, x, sizeof(x));
	fastmemcpy(out, sha3_finalize(&ctx), 32);
}

void random_stir(u8 current[32], const u8 stir_in[32]) {
	Sha3Context ctx;
	sha3_init256(&ctx);
	sha3_update(&ctx, current, 32);
	sha3_update(&ctx, stir_in, 32);
	fastmemcpy(current, sha3_finalize(&ctx), 32);
}

