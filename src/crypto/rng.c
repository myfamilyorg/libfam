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

#include <libfam/format.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

void rng_init(Rng *rng, const void *opt_entropy) {
	__attribute__((aligned(32))) u8 key[32];
	random32(key);
	if (opt_entropy) random_stir(key, opt_entropy);
	storm_init(&rng->ctx, key);
	memset(key, 0, sizeof(key));
}

void rng_reseed(Rng *rng, const void *opt_entropy) {
	rng_init(rng, opt_entropy);
}

void rng_gen(Rng *rng, void *v, u64 size) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u64 off = 0;
	while (size >= 32) {
		storm_next_block(&rng->ctx, (u8 *)(v + off));
		size -= 32;
		off += 32;
	}

	if (size) {
		storm_next_block(&rng->ctx, buf);
		fastmemcpy(((u8 *)v) + off, buf, size);
	}
}

#if TEST == 1
void rng_test_seed(Rng *rng, u8 key[32]) { storm_init(&rng->ctx, key); }
#endif /* TEST */

