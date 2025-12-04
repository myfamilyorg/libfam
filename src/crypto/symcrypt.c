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
typedef struct {
	uint8x16_t lane[4];
} snow_vec_t;

static inline snow_vec_t snow_zero(void) {
	snow_vec_t v;
	v.lane[0] = v.lane[1] = v.lane[2] = v.lane[3] = vdupq_n_u8(0);
	return v;
}

static inline snow_vec_t snow_load(const u8 *p) {
	snow_vec_t v;
	v.lane[0] = vld1q_u8(p + 0);
	v.lane[1] = vld1q_u8(p + 16);
	v.lane[2] = vld1q_u8(p + 32);
	v.lane[3] = vld1q_u8(p + 48);
	return v;
}

static inline void snow_store(u8 *p, snow_vec_t v) {
	vst1q_u8(p + 0, v.lane[0]);
	vst1q_u8(p + 16, v.lane[1]);
	vst1q_u8(p + 32, v.lane[2]);
	vst1q_u8(p + 48, v.lane[3]);
}

static inline snow_vec_t aes_enc_round(snow_vec_t x, snow_vec_t rk) {
	snow_vec_t out;
	out.lane[0] = vaesmcq_u8(vaeseq_u8(x.lane[0], rk.lane[0]));
	out.lane[1] = vaesmcq_u8(vaeseq_u8(x.lane[1], rk.lane[1]));
	out.lane[2] = vaesmcq_u8(vaeseq_u8(x.lane[2], rk.lane[2]));
	out.lane[3] = vaesmcq_u8(vaeseq_u8(x.lane[3], rk.lane[3]));
	return out;
}

static inline snow_vec_t aes_dec_round(snow_vec_t x, snow_vec_t rk) {
	snow_vec_t out;
	out.lane[0] = vaesdq_u8(x.lane[0], rk.lane[0]);
	out.lane[1] = vaesdq_u8(x.lane[1], rk.lane[1]);
	out.lane[2] = vaesdq_u8(x.lane[2], rk.lane[2]);
	out.lane[3] = vaesdq_u8(x.lane[3], rk.lane[3]);
	return out;
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
