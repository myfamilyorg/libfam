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

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __ARM_FEATURE_CRYPTO */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#include <libfam/dilithium_const.h>
#include <libfam/utils.h>

void ntt_avx(void *a, const void *qdata);
void nttunpack_avx(void *packed);

void ntt(i32 a[N]) {
#ifdef USE_AVX2
	__m256i packed[32] __attribute__((aligned(32)));
	for (int i = 0; i < 32; ++i) {
		packed[i] = _mm256_load_si256((__m256i *)&a[i * 8]);
	}

	ntt_avx(packed, (void *)qdata.vec);
	nttunpack_avx(packed);

	for (int i = 0; i < 32; ++i) {
		_mm256_store_si256((__m256i *)&a[i * 8], packed[i]);
	}
#else
	u32 len, start, j, k = 0;
	i32 zeta;

	for (len = 128; len > 0; len >>= 1) {
		for (start = 0; start < N; start = j + len) {
			zeta = zetas[++k];
			for (j = start; j < start + len; ++j) {
				i32 aj, ajlen, v;
				i64 w, x, y, z;

				aj = a[j];
				w = zeta;
				x = a[j + len];

				y = x * w;
				i32 y_low = (i32)y;

				z = y_low * QINV;
				z = z * Q;
				z = y - z;
				v = z >> 32;
				ajlen = aj - v;
				aj = aj + v;

				a[j + len] = ajlen;
				a[j] = aj;
			}
		}
	}
#endif /* !USE_AVX2 */
}

void invntt_tomont(i32 a[N]) {
	u32 start, len, j, k;
	i32 t, zeta;
	const i32 f = 41978;

	k = 256;
	for (len = 1; len < N; len <<= 1) {
		for (start = 0; start < N; start = j + len) {
			zeta = -zetas[--k];
			for (j = start; j < start + len; ++j) {
				t = a[j];
				a[j] = t + a[j + len];
				a[j + len] = t - a[j + len];
				i64 ain = (i64)zeta * a[j + len];
				t = (i64)ain * QINV;

				a[j + len] = (ain - (i64)t * Q) >> 32;
			}
		}
	}

	for (j = 0; j < N; ++j) {
		i64 ain = (i64)f * a[j];
		i32 t;
		t = (i64)ain * QINV;
		a[j] = (ain - (i64)t * Q) >> 32;
	}
}

i32 power2round(i32 *a0, i32 a) {
	i32 a1;

	a1 = (a + (1 << (D - 1)) - 1) >> D;
	*a0 = a - (a1 << D);
	return a1;
}

i32 decompose(i32 *a0, i32 a) {
	i32 a1;

	a1 = (a + 127) >> 7;
	a1 = (a1 * 11275 + (1 << 23)) >> 24;
	a1 ^= ((43 - a1) >> 31) & a1;

	*a0 = a - a1 * 2 * GAMMA2;
	*a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
	return a1;
}

u32 make_hint(i32 a0, i32 a1) {
	if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) return 1;

	return 0;
}

i32 use_hint(i32 a, u32 hint) {
	i32 a0, a1;

	a1 = decompose(&a0, a);
	if (hint == 0) return a1;

	if (a0 > 0)
		return (a1 == 43) ? 0 : a1 + 1;
	else
		return (a1 == 0) ? 43 : a1 - 1;
}

i32 montgomery_reduce(i64 a) {
	i32 t;

	t = (i64)(i32)a * QINV;
	t = (a - (i64)t * Q) >> 32;
	return t;
}

i32 reduce32(i32 a) {
	i32 t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * Q;
	return t;
}

i32 caddq(i32 a) {
	a += (a >> 31) & Q;
	return a;
}
