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
#ifdef __aarch64__
#include <arm_neon.h>
#endif /* __aarch64__ */
#include <libfam/string.h>
#include <libfam/symcrypt.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#ifdef __AVX2__
typedef struct {
	__m256i rk[15];
	__m256i ctr[2];
} symcrypt_internal;
#elif defined(__aarch64__)
typedef struct {
	uint8x16_t rk[15];
	uint8x16_t ctr[8];
} symcrypt_internal;
#else
#error Unsupported Platform
#endif

STATIC_ASSERT(sizeof(symcrypt_internal) == sizeof(SymCryptContext),
	      sym_crypt_sizes);

void sym_crypt_init(SymCryptContext *ctx, const u8 key[32],
		    const u8 nonce[16]) {
	symcrypt_internal *s = (symcrypt_internal *)ctx->_data;

#ifdef __AVX2__
	__m128i k = _mm_loadu_si128((const __m128i *)key);
	s->rk[0] = _mm256_broadcastsi128_si256(k);

	for (int i = 1; i < 15; ++i) {
		__m128i temp = _mm_aeskeygenassist_si128(k, 0);
		k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
		k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
		k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
		k = _mm_xor_si128(k, _mm_shuffle_epi32(temp, 0xff));
		if (i % 2 == 1) {
			temp = _mm_aeskeygenassist_si128(k, 0);
			k = _mm_xor_si128(k, _mm_shuffle_epi32(temp, 0xaa));
		}
		s->rk[i] = _mm256_broadcastsi128_si256(k);
	}

	__m128i n = _mm_loadu_si128((const __m128i *)nonce);
	__m256i base = _mm256_broadcastsi128_si256(n);
	__m256i inc_lo = _mm256_set_epi64x(3, 2, 1, 0);
	__m256i inc_hi = _mm256_set_epi64x(7, 6, 5, 4);
	s->ctr[0] = _mm256_add_epi64(base, inc_lo);
	s->ctr[1] = _mm256_add_epi64(base, inc_hi);

#elif defined(__aarch64__)
#else
#error Unsupported platform
#endif
}

void sym_crypt_xcrypt_buffer(SymCryptContext *ctx, u8 block[128]) {
	symcrypt_internal *s = (symcrypt_internal *)ctx->_data;

#ifdef __AVX2__
	__m256i c0 = s->ctr[0];
	__m256i c1 = s->ctr[1];
	__m256i ks0 = c0;
	__m256i ks1 = c1;

#define AESENC(round)                                  \
	ks0 = _mm256_aesenc_epi128(ks0, s->rk[round]); \
	ks1 = _mm256_aesenc_epi128(ks1, s->rk[round]);

	AESENC(0);
	AESENC(1);
	AESENC(2);
	AESENC(3);
	AESENC(4);
	AESENC(5);
	AESENC(6);
	AESENC(7);
	AESENC(8);
	AESENC(9);
	AESENC(10);
	AESENC(11);
	AESENC(12);
	AESENC(13);

	ks0 = _mm256_aesenclast_epi128(ks0, s->rk[14]);
	ks1 = _mm256_aesenclast_epi128(ks1, s->rk[14]);

	__m256i p0 = _mm256_loadu_si256((const __m256i *)block);
	__m256i p1 = _mm256_loadu_si256((const __m256i *)(block + 32));
	__m256i p2 = _mm256_loadu_si256((const __m256i *)(block + 64));
	__m256i p3 = _mm256_loadu_si256((const __m256i *)(block + 96));

	_mm256_storeu_si256((__m256i *)block, _mm256_xor_si256(p0, ks0));
	_mm256_storeu_si256((__m256i *)(block + 32), _mm256_xor_si256(p1, ks0));
	_mm256_storeu_si256((__m256i *)(block + 64), _mm256_xor_si256(p2, ks1));
	_mm256_storeu_si256((__m256i *)(block + 96), _mm256_xor_si256(p3, ks1));

	s->ctr[0] = _mm256_add_epi64(c0, _mm256_set1_epi64x(8));
	s->ctr[1] = _mm256_add_epi64(c1, _mm256_set1_epi64x(8));

#elif defined(__aarch64__)
#else
#error Unsupported platform
#endif
}
