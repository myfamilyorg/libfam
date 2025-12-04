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
	uint8x16_t k = vld1q_u8(key);
	s->rk[0] = k;

	for (int i = 1; i < 15; ++i) {
		uint8x16_t temp = vaeskeygenassistq_u8(k, 0);
		k = veorq_u8(k, vshlq_n_u8(k, 4));
		k = veorq_u8(k, vshlq_n_u8(k, 4));
		k = veorq_u8(k, vshlq_n_u8(k, 4));
		k = veorq_u8(k, vextq_u8(temp, temp, 12));
		if (i % 2 == 1) {
			temp = vaeskeygenassistq_u8(k, 0);
			k = veorq_u8(k, vextq_u8(temp, temp, 11));
		}
		s->rk[i] = k;
	}

	uint8x16_t n = vld1q_u8(nonce);
	for (int i = 0; i < 8; ++i) {
		s->ctr[i] = vaddq_u32(n, vdupq_n_u32(i));
	}
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
	uint8x16_t c[8];
	for (int i = 0; i < 8; ++i) c[i] = s->ctr[i];

#define AESENC(round)                           \
	c[0] = vaesencq_u8(c[0], s->rk[round]); \
	c[1] = vaesencq_u8(c[1], s->rk[round]); \
	c[2] = vaesencq_u8(c[2], s->rk[round]); \
	c[3] = vaesencq_u8(c[3], s->rk[round]); \
	c[4] = vaesencq_u8(c[4], s->rk[round]); \
	c[5] = vaesencq_u8(c[5], s->rk[round]); \
	c[6] = vaesencq_u8(c[6], s->rk[round]); \
	c[7] = vaesencq_u8(c[7], s->rk[round]);

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

#undef AESENC

	c[0] = vaesenclastq_u8(c[0], s->rk[14]);
	c[1] = vaesenclastq_u8(c[1], s->rk[14]);
	c[2] = vaesenclastq_u8(c[2], s->rk[14]);
	c[3] = vaesenclastq_u8(c[3], s->rk[14]);
	c[4] = vaesenclastq_u8(c[4], s->rk[14]);
	c[5] = vaesenclastq_u8(c[5], s->rk[14]);
	c[6] = vaesenclastq_u8(c[6], s->rk[14]);
	c[7] = vaesenclastq_u8(c[7], s->rk[14]);

	for (int i = 0; i < 8; ++i) {
		uint8x16_t p = vld1q_u8(block + i * 16);
		uint8x16_t out = veorq_u8(p, c[i]);
		vst1q_u8(block + i * 16, out);
	}

	for (int i = 0; i < 8; ++i) {
		s->ctr[i] = vaddq_u64(s->ctr[i], vdupq_n_u64(8));
	}
#else
#error Unsupported platform
#endif
}
