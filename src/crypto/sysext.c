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

#include <libfam/aighthash.h>
#include <libfam/atomic.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/storm.h>
#include <libfam/string.h>

PUBLIC u64 read_cycle_counter(void) {
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

static u64 global_entropy_counter = U64_MAX / 2;

void random32(u8 out[32]) {
	__attribute__((aligned(32))) u8 tmp[32] = {0};
	u64 *x = (u64 *)tmp;

	x[0] = read_cycle_counter();
	x[1] = (u64)__builtin_return_address(0);
	x[2] = (u64)__builtin_frame_address(0);
	x[3] = __aadd64(&global_entropy_counter, 1);

	StormContext ctx;
	storm_init(&ctx, tmp);
	storm_next_block(&ctx, tmp);

	fastmemcpy(out, tmp, 32);
	memset(tmp, 0, 32);
}

void random_stir(u8 current[32], const u8 stir_in[32]) {
	__attribute__((aligned(32))) u8 block[32];
	fastmemcpy(block, current, 32);

	StormContext ctx;
	storm_init(&ctx, block);
	storm_next_block(&ctx, block);

	fastmemcpy(current, block, 32);
	memset(block, 0, 32);
}
