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
#include <arm_acle.h>
#include <arm_neon.h>
#endif /* __aarch64__ */
#include <libfam/symcrypt.h>
#include <libfam/utils.h>

#ifdef __AVX2__
typedef __m256i snow_vec_t;

static inline snow_vec_t snow_zero(void) { return _mm256_setzero_si256(); }
static inline snow_vec_t snow_load(const u8 *p) {
	return _mm256_loadu_si256((const __m256i *)p);
}
static inline void snow_store(u8 *p, snow_vec_t v) {
	_mm256_storeu_si256((__m256i *)p, v);
}

static inline snow_vec_t aes_enc_round(snow_vec_t x, snow_vec_t rk) {
	return _mm256_aesenc_epi128(x, rk);
}

static inline snow_vec_t aes_dec_round(snow_vec_t x, snow_vec_t rk) {
	return _mm256_aesdec_epi128(x, rk);
}

#elif defined(__aarch64__)
typedef uint8x16x4_t snow_vec_t;
#define SNOW_LANES 4

static inline snow_vec_t snow_zero(void) {
	return vld1q_u8_x4((const uint8_t[64]){0});
}
static inline snow_vec_t snow_load(const uint8_t *p) { return vld1q_u8_x4(p); }
static inline void snow_store(uint8_t *p, snow_vec_t v) { vst1q_u8_x4(p, v); }
static inline snow_vec_t snow_xor(snow_vec_t a, snow_vec_t b) {
	return veorq_u8_x4(a, b);
}

static inline snow_vec_t aes_enc_round(snow_vec_t x, snow_vec_t rk) {
	return vaesencq_u8_x4(x, rk);
}
static inline snow_vec_t aes_dec_round(snow_vec_t x, snow_vec_t rk) {
	return vaesdecq_u8_x4(x, rk);
}

#else
#error "No Supported SIMD backend"
#endif

#include <libfam/format.h>

void sym_crypt_init(SymCryptContext *ctx, const u8 key[32], const u8 iv[16]) {
	snow_vec_t v, x;
	v = snow_load((u8[32]){0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
			       11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
			       22, 23, 24, 25, 26, 27, 28, 29, 30, 31});
	x = snow_load((u8[32]){0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
			       11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
			       22, 23, 24, 25, 26, 27, 28, 29, 30, 31});

	v = aes_enc_round(v, x);
	x = aes_dec_round(v, x);
	u8 *b = (void *)&v;
	println("{}", sizeof(snow_vec_t));
	for (u32 i = 0; i < 32; i++) {
		println("b[{}]={}", i, b[i]);
	}

	(void)snow_zero;
	(void)snow_store;
}

void sym_crypt_xcrypt_buffer(SymCryptContext *ctx, u8 buf[128]) {}
