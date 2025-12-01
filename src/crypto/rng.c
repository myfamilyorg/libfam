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

#include <libfam/errno.h>
#include <libfam/linux.h>
#include <libfam/rng.h>
#include <libfam/string.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

void rng_init(Rng *rng, const void *opt_entropy) {
	u8 iv[32], key[32];
	random32(key);
	if (opt_entropy) random_stir(key, opt_entropy);
	random32(iv);
	if (opt_entropy) random_stir(iv, opt_entropy);
	aes_init(&rng->ctx, key, iv);
	memset(iv, 0, sizeof(iv));
	memset(key, 0, sizeof(key));
}

void rng_reseed(Rng *rng, const void *opt_entropy) {
	rng_init(rng, opt_entropy);
}

void rng_gen(Rng *rng, void *v, u64 size) {
	aes_ctr_xcrypt_buffer(&rng->ctx, (u8 *)v, size);
}

#if TEST == 1
void rng_test_seed(Rng *rng, u8 key[32], u8 iv[16]) {
	u8 v0[1] = {0};
	aes_init(&rng->ctx, key, iv);
	rng_gen(rng, &v0, 1);
}
#endif /* TEST */

