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
#include <immintrin.h>
#endif /* __AVX2__ */
#include <libfam/string.h>
#include <libfam/symcrypt.h>
#include <libfam/utils.h>

typedef struct {
	u8 key[4][32];
	u8 state[32];
	__m256i keys[4];
} SymCryptContextImpl;

void sym_crypt_init(SymCryptContext *ctx, const u8 key[32], const u8 iv[16]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;
	*(__m256i *)st->key[0] = _mm256_loadu_si256((const __m256i *)key);

	__m128i iv128 = _mm_loadu_si128((const __m128i *)iv);
	__m256i iv256 = _mm256_broadcastsi128_si256(iv128);

	*(__m256i *)st->state = iv256;

	*(__m256i *)st->state =
	    _mm256_xor_si256(*(__m256i *)st->state, *(__m256i *)st->key[0]);
	*(__m256i *)st->key[1] =
	    _mm256_add_epi64(*(__m256i *)st->key[0], _mm256_set1_epi64x(1));
	*(__m256i *)st->key[2] =
	    _mm256_add_epi64(*(__m256i *)st->key[1], _mm256_set1_epi64x(1));
	*(__m256i *)st->key[3] =
	    _mm256_add_epi64(*(__m256i *)st->key[2], _mm256_set1_epi64x(1));
}

inline void sym_crypt_xcrypt_buffer(SymCryptContext *ctx, u8 buf[32]) {
	SymCryptContextImpl *st = (SymCryptContextImpl *)ctx;

	__m256i s = _mm256_load_si256((const __m256i *)(void *)st->state);
	__m256i p = _mm256_load_si256((const __m256i *)(void *)buf);
	__m256i x = _mm256_xor_si256(s, p);

	__m128i rk0 = _mm_load_si128((const __m128i *)(void *)st->key[0]);
	__m128i rk1 = _mm_load_si128((const __m128i *)(void *)st->key[1] + 1);
	__m128i rk2 = _mm_load_si128((const __m128i *)(void *)st->key[2]);
	__m128i rk3 = _mm_load_si128((const __m128i *)(void *)st->key[3] + 1);

	__m128i lo = _mm256_castsi256_si128(x);
	__m128i hi = _mm256_extracti128_si256(x, 1);

	x = _mm256_shuffle_epi32(x, 0x4E);
	lo = _mm_aesenc_si128(lo, rk0);
	hi = _mm_aesenc_si128(hi, rk1);
	x = _mm256_set_m128i(hi, lo);

	x = _mm256_shuffle_epi32(x, 0x4E);
	lo = _mm_aesenc_si128(lo, rk2);
	hi = _mm_aesenc_si128(hi, rk3);
	x = _mm256_set_m128i(hi, lo);

	_mm256_store_si256((__m256i *)(void *)st->state, x);
	_mm256_store_si256((__m256i *)(void *)buf, _mm256_xor_si256(p, x));
}
