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
#include <libfam/env.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

static u64 global_entropy_counter = U64_MAX / 2;

u64 read_cycle_counter(void) {
#if defined(__x86_64__)
	u32 lo, hi;
	mfence();
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

STATIC void random32(u8 out[32]) {
	__attribute__((aligned(32))) u8 tmp[32];
	u64 *x = (u64 *)tmp;
	StormContext ctx;
	struct timespec ts;
	u64 pid = getpid();
	i32 res;

	res = clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	if (res != 0) clock_gettime(CLOCK_MONOTONIC, &ts);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
	x[0] = (u64)__builtin_return_address(1) ^ (u64)&tmp;
#pragma GCC diagnostic pop
	x[1] = (u64)ts.tv_nsec;
	x[2] = __aadd64(&global_entropy_counter, 1) ^ (u64)&ts;
	x[3] = read_cycle_counter() ^ pid;

	storm_init(&ctx, tmp);
	storm_next_block(&ctx, out);

	secure_zero32(tmp);
	secure_zero(&ctx, sizeof(ctx));
}

STATIC void random_stir(u8 current[32], const u8 stir_in[32]) {
	StormContext ctx;

	storm_init(&ctx, current);
	fastmemcpy(current, stir_in, 32);
	storm_next_block(&ctx, current);

	secure_zero(&ctx, sizeof(ctx));
}

void rng_init(Rng *rng, const void *opt_entropy) {
	__attribute__((aligned(32))) u8 key[32];

#if TEST == 1
	if (IS_VALGRIND()) fastmemset(key, 0, 32);
#endif /* TEST */

	random32(key);
	if (opt_entropy) random_stir(key, opt_entropy);
	storm_init(&rng->ctx, key);
	secure_zero32(key);
}

void rng_reseed(Rng *rng, const void *opt_entropy) {
	rng_init(rng, opt_entropy);
}

void rng_gen(Rng *rng, void *v, u64 size) {
	u8 *out = v;
	u64 off = 0;
	while (off + 32 < size) {
		storm_next_block(&rng->ctx, out + off);
		off += 32;
	}

	if (off < size) {
		__attribute__((aligned(32))) u8 buf[32];
#if TEST == 1
		if (IS_VALGRIND()) fastmemset(buf, 0, 32);
#endif /* TEST */

		storm_next_block(&rng->ctx, buf);
		fastmemcpy(out + off, buf, size - off);
		secure_zero32(buf);
	}
}

#if TEST == 1
void rng_test_seed(Rng *rng, u8 key[32]) { storm_init(&rng->ctx, key); }
#endif /* TEST */

