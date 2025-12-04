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
#include <libfam/symcrypt.h>
#include <libfam/utils.h>

#if defined(__AVX512F__) && defined(__VAES__) && defined(__AVX512VL__)
typedef __m512i snow_vec_t;
#define SNOW_LANES 8

static inline snow_vec_t aes_round(snow_vec_t x, snow_vec_t rk) {
	return _mm512_aesenc_epi128(x, rk);
}

static inline snow_vec_t aes_dec_round(now_vec_t x, snow_vec_t rk) {
	return _mm512_aesdec_epi128(x, rk);
}

#elif defined(__AVX2__)
typedef __m256i snow_vec_t;
#define SNOW_LANES 4

static inline snow_vec_t aes_round(snow_vec_t x, snow_vec_t rk) {
	return _mm256_aesenc_epi128(x, rk);
}

static inline snow_vec_t aes_dec_round(snow_vec_t x, snow_vec_t rk) {
	return _mm256_aesdec_epi128(x, rk);
}

#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
typedef uint8x16x4_t snow_vec_t;
#define SNOW_LANES 4

static inline snow_vec_t aes_round(snow_vec_t x, snow_vec_t rk) {
	return vaesencq_u8(x, rk);
}

static inline snow_vec_t aes_dec_round(snow_vec_t x, snow_vec_t rk) {
	return vaesdecq_u8(x, rk);
}
#else
#error "No Supported SIMD backend"
#endif

void sym_crypt_init(SymCryptContext *ctx, const u8 key[32], const u8 iv[16]) {
	snow_vec_t v = {0}, x = {0};
	v = aes_round(v, x);
	x = aes_dec_round(v, x);
}
