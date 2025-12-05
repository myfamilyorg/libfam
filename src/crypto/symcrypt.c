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

#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */
#include <libfam/aes.h>
#include <libfam/aighthash.h>
#include <libfam/format.h>
#include <libfam/string.h>
#include <libfam/symcrypt.h>
#include <libfam/utils.h>

#define P1 0x9e3779b97f4a7c15ULL
#define P2 0x517cc1b727220a95ULL

typedef struct {
#ifdef USE_AVX2
	__m256i state;
	__m128i rk_lo[4];
	__m128i rk_hi[4];
#else
	u8 state[32];
	u8 rk_lo[4][16];
	u8 rk_hi[4][16];
#endif /* !USE_AVX2 */
} SymCryptContextImpl;

STATIC void sym_crypt_mix(SymCryptContextImpl *st, const u8 mkey[32]) {
	u64 h, seed = ((u64 *)mkey)[0] ^ ((u64 *)mkey)[1] ^ ((u64 *)mkey)[2] ^
		      ((u64 *)mkey)[3];
	h = aighthash64(&((u64 *)&st->state)[0], 8, seed);
	((u64 *)&st->state)[0] ^= h;
	h = aighthash64(&((u64 *)&st->state)[1], 8, seed ^ P1);
	((u64 *)&st->state)[1] ^= h;
	h = aighthash64(&((u64 *)&st->state)[2], 8, seed ^ P2);
	((u64 *)&st->state)[2] ^= h;
	h = aighthash64(&((u64 *)&st->state)[3], 8, seed);
	((u64 *)&st->state)[3] ^= h;
}

#ifdef USE_AVX2
STATIC void sym_crypt_init_avx2(SymCryptContext *ctx, const u8 mkey[32],
				const u8 iv[16]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;
	__m256i key = _mm256_loadu_si256((const __m256i_u *)mkey);
	__m256i iv256 =
	    _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i_u *)iv));

	st->state = _mm256_xor_si256(iv256, key);

	__m256i k = key;
	const __m256i ONE4 = _mm256_set_epi64x(0, 1, 0, 1);

	for (int i = 0; i < 4; i++) {
		st->rk_lo[i] = _mm256_castsi256_si128(k);
		st->rk_hi[i] = _mm256_extracti128_si256(k, 1);
		k = _mm256_add_epi64(k, ONE4);
	}

	sym_crypt_mix(st, mkey);
}

STATIC void sym_crypt_xcrypt_buffer_avx2(SymCryptContext *ctx, u8 buf[32]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;

	__m256i x = st->state;
	__m128i kl0 = st->rk_lo[0];
	__m128i kh1 = st->rk_hi[1];
	__m128i kl2 = st->rk_lo[2];
	__m128i kh3 = st->rk_hi[3];
	__m256i p = _mm256_load_si256((const __m256i *)(void *)buf);

	x = _mm256_xor_si256(x, p);
	__m128i lo = _mm256_castsi256_si128(x);
	__m128i hi = _mm256_extracti128_si256(x, 1);

	lo = _mm_aesenc_si128(lo, kl0);
	hi = _mm_aesenc_si128(hi, kh1);
	x = _mm256_set_m128i(hi, lo);

	lo = _mm_aesenc_si128(lo, kl2);
	hi = _mm_aesenc_si128(hi, kh3);
	x = _mm256_set_m128i(hi, lo);

	st->state = x;
	_mm256_store_si256((__m256i *)(void *)buf, _mm256_xor_si256(p, x));
}
#else
STATIC void sym_crypt_init_scalar(SymCryptContext *ctx, const u8 mkey[32],
				  const u8 iv[16]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;

	for (int i = 0; i < 16; ++i) {
		st->state[i] = iv[i] ^ mkey[i];
		st->state[i + 16] = iv[i] ^ mkey[i + 16];
	}

	fastmemcpy(st->rk_lo[0], mkey, 16);
	fastmemcpy(st->rk_hi[0], mkey + 16, 16);

	for (int i = 1; i < 4; ++i) {
		fastmemcpy(st->rk_lo[i], st->rk_lo[i - 1], 16);
		fastmemcpy(st->rk_hi[i], st->rk_hi[i - 1], 16);

		*(u64 *)st->rk_lo[i] += 1;
		*(u64 *)st->rk_hi[i] += 1;
	}

	sym_crypt_mix(st, mkey);
}
STATIC void sym_crypt_xcrypt_buffer_scalar(SymCryptContext *ctx, u8 buf[32]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;

	u8 x_lo[16], x_hi[16];
	for (int i = 0; i < 16; ++i) {
		x_lo[i] = st->state[i] ^ buf[i];
		x_hi[i] = st->state[i + 16] ^ buf[i + 16];
	}

	AesSingleRound(x_lo, st->rk_lo[0]);
	AesSingleRound(x_hi, st->rk_hi[1]);
	AesSingleRound(x_lo, st->rk_lo[2]);
	AesSingleRound(x_hi, st->rk_hi[3]);

	fastmemcpy(st->state, x_lo, 16);
	fastmemcpy(st->state + 16, x_hi, 16);

	for (int i = 0; i < 16; ++i) {
		buf[i] ^= x_lo[i];
		buf[i + 16] ^= x_hi[i];
	}
}
#endif /* !USE_AVX2 */

PUBLIC void sym_crypt_init(SymCryptContext *ctx, const u8 key[32],
			   const u8 iv[16]) {
#ifdef USE_AVX2
	sym_crypt_init_avx2(ctx, key, iv);
#else
	sym_crypt_init_scalar(ctx, key, iv);
#endif /* !USE_AVX2 */
}

PUBLIC void sym_crypt_xcrypt_buffer(SymCryptContext *ctx, u8 buf[32]) {
#ifdef USE_AVX2
	sym_crypt_xcrypt_buffer_avx2(ctx, buf);
#else
	sym_crypt_xcrypt_buffer_scalar(ctx, buf);

#endif /* !USE_AVX2 */
}
