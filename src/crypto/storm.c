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
#elif defined(__ARM_FEATURE_CRYPTO)
#define USE_NEON
#endif /* __ARM_FEATURE_CRYPTO */
#endif /* NO_VECTOR */

#ifdef USE_NEON
#include <arm_neon.h>
#endif /* USE_NEON */
#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/utils.h>

#define P1 0x9e3779b97f4a7c15ULL
#define P2 0x517cc1b727220a95ULL
#define Nb 4

static const __attribute__((aligned(32))) u8 STORM_KEY_MIX[64] = {
    0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37, 0x9e, 0x95, 0x0a, 0x22,
    0x27, 0xb7, 0xc1, 0x7c, 0x51, 0x6b, 0x8f, 0x1d, 0x2e, 0x4a, 0x9f,
    0xc3, 0x88, 0x11, 0x9a, 0x5f, 0x6d, 0x8e, 0x2b, 0x99, 0x01, 0x33,
    0x41, 0x95, 0x1f, 0xa7, 0xb3, 0x29, 0x6e, 0x5d, 0x8c, 0x77, 0x13,
    0x9f, 0x04, 0xab, 0xcd, 0xc9, 0x11, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22};

static const __attribute__((aligned(32))) u8 ZERO256[32] = {0};

typedef struct {
#ifdef USE_AVX2
	__m256i state;
	__m256i key;
	__m256i counter;
#elif defined(USE_NEON)
	uint8x16_t state_lo;
	uint8x16_t state_hi;
	uint8x16_t key_lo;
	uint8x16_t key_hi;
	uint8x16_t counter_lo;
	uint8x16_t counter_hi;
#else
	u8 state[32];
	u8 key[32];
	u8 counter[32];
#endif /* !USE_AVX2 */
} Storm256ContextImpl;

typedef struct {
#ifdef USE_AVX2
	__m128i state;
	__m128i key;
	__m128i counter;
#elif defined(USE_NEON)
	uint8x16_t state;
	uint8x16_t key;
	uint8x16_t counter;
#else
	u8 state[16];
	u8 key[16];
	u8 counter[16];
#endif /* !USE_AVX2 */
} Storm128ContextImpl;

typedef struct {
	Storm256Context ctx;
	u64 counter;
} StormCtrImpl;

typedef u8 state_t[4][4];

STATIC_ASSERT(sizeof(Storm256Context) == sizeof(Storm256ContextImpl),
	      storm_context_size);

#if !defined(USE_AVX2) && !defined(USE_NEON)
static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

STATIC void storm_sub_bytes(state_t *state) {
	u8 i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			(*state)[j][i] = sbox[(*state)[j][i]];
		}
	}
}

STATIC void storm_shift_rows(state_t *state) {
	u8 temp;

	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

STATIC u8 storm_xtime(u8 x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

STATIC void storm_mix_columns(state_t *state) {
	u8 i;
	u8 Tmp, Tm, t;
	for (i = 0; i < 4; ++i) {
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^
		      (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1];
		Tm = storm_xtime(Tm);
		(*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2];
		Tm = storm_xtime(Tm);
		(*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3];
		Tm = storm_xtime(Tm);
		(*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;
		Tm = storm_xtime(Tm);
		(*state)[i][3] ^= Tm ^ Tmp;
	}
}

STATIC void storm_add_round_key(u8 round, state_t *state, const u8 *key) {
	u8 i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			(*state)[i][j] ^= key[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

STATIC __attribute__((unused)) void aesenc128(u8 state[16],
					      const u8 *RoundKey) {
	state_t *s = (void *)state;
	storm_sub_bytes(s);
	storm_shift_rows(s);
	storm_mix_columns(s);
	storm_add_round_key(0, s, RoundKey);
}

#endif /* USE_AVX2 */

#ifdef USE_AVX2
STATIC void storm256_init_avx2(Storm256Context *ctx, const u8 key[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	__m256i key256 = _mm256_load_si256((const __m256i *)key);
	__m256i domain = _mm256_load_si256((const __m256i *)STORM_KEY_MIX);
	st->state = _mm256_xor_si256(key256, domain);
	__m256i domain_key =
	    _mm256_load_si256((const __m256i *)(STORM_KEY_MIX + 32));
	st->key = _mm256_xor_si256(key256, domain_key);
	st->counter = _mm256_load_si256((const __m256i *)ZERO256);
}
STATIC void storm256_next_block_avx2(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	__m256i p = _mm256_load_si256((const __m256i *)buf);
	__m256i x = _mm256_xor_si256(st->state, p);
	__m256i key = st->key;
	x = _mm256_aesenc_epi128(x, key);
	__m128i lo = _mm256_castsi256_si128(x);
	__m128i hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	__m256i y = _mm256_set_m128i(lo, hi);
	x = _mm256_aesenc_epi128(x, key);
	x = _mm256_xor_si256(y, x);
	x = _mm256_aesenc_epi128(x, key);
	lo = _mm256_castsi256_si128(x);
	hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	st->state = _mm256_set_m128i(lo, hi);
	x = _mm256_aesenc_epi128(x, key);
	_mm256_store_si256((__m256i *)buf, x);
}
STATIC void storm256_xcrypt_buffer_avx2(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	__m256i ctr = st->counter;
	storm256_next_block(ctx, (u8 *)&ctr);
	_mm256_store_si256(
	    (__m256i *)buf,
	    _mm256_xor_si256(_mm256_load_si256((__m256i *)buf), ctr));
	st->counter = _mm256_add_epi64(st->counter, _mm256_set1_epi64x(1));
}
#elif defined(USE_NEON)
STATIC void storm256_init_neon(Storm256Context *ctx, const u8 key[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	uint8x16_t key_lo = vld1q_u8(key);
	uint8x16_t key_hi = vld1q_u8(key + 16);
	uint8x16_t domain_lo = vld1q_u8(STORM_KEY_MIX);
	uint8x16_t domain_hi = vld1q_u8(STORM_KEY_MIX + 16);
	st->state_lo = veorq_u8(key_lo, domain_lo);
	st->state_hi = veorq_u8(key_hi, domain_hi);
	uint8x16_t domain_key_lo = vld1q_u8(STORM_KEY_MIX + 32);
	uint8x16_t domain_key_hi = vld1q_u8(STORM_KEY_MIX + 32 + 16);
	st->key_lo = veorq_u8(key_lo, domain_key_lo);
	st->key_hi = veorq_u8(key_hi, domain_key_hi);
	st->counter_lo = vdupq_n_u8(0);
	st->counter_hi = vdupq_n_u8(0);
	(void)ZERO256;
}

STATIC uint8x16_t aesenc_intel_match(uint8x16_t data, uint8x16_t rkey) {
	uint8x16_t zero = vdupq_n_u8(0);
	data = vaeseq_u8(data, zero);
	data = vaesmcq_u8(data);
	return veorq_u8(data, rkey);
}

STATIC void storm256_next_block_neon(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	uint8x16_t p_lo = vld1q_u8(buf);
	uint8x16_t p_hi = vld1q_u8(buf + 16);
	uint8x16_t x_lo = veorq_u8(st->state_lo, p_lo);
	uint8x16_t x_hi = veorq_u8(st->state_hi, p_hi);
	uint8x16_t temp_lo = aesenc_intel_match(x_lo, st->key_lo);
	uint8x16_t temp_hi = aesenc_intel_match(x_hi, st->key_hi);
	uint8x16_t reduced = veorq_u8(temp_lo, temp_hi);
	st->state_lo = temp_hi;
	st->state_hi = reduced;
	uint8x16_t out_lo = aesenc_intel_match(temp_lo, st->key_lo);
	uint8x16_t out_hi = aesenc_intel_match(temp_hi, st->key_hi);
	vst1q_u8(buf, out_lo);
	vst1q_u8(buf + 16, out_hi);
}

STATIC void storm256_xcrypt_buffer_neon(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	uint8x16_t ctr_lo = st->counter_lo;
	uint8x16_t ctr_hi = st->counter_hi;

	u8 ctr_block[32] __attribute__((aligned(16)));
	vst1q_u8(ctr_block, ctr_lo);
	vst1q_u8(ctr_block + 16, ctr_hi);

	storm256_next_block_neon(ctx, ctr_block);

	uint8x16_t keystream_lo = vld1q_u8(ctr_block);
	uint8x16_t keystream_hi = vld1q_u8(ctr_block + 16);

	uint8x16_t data_lo = vld1q_u8(buf);
	uint8x16_t data_hi = vld1q_u8(buf + 16);

	uint8x16_t out_lo = veorq_u8(data_lo, keystream_lo);
	uint8x16_t out_hi = veorq_u8(data_hi, keystream_hi);

	vst1q_u8(buf, out_lo);
	vst1q_u8(buf + 16, out_hi);

	uint64x2_t lo64 = vreinterpretq_u64_u8(ctr_lo);
	uint64x2_t hi64 = vreinterpretq_u64_u8(ctr_hi);

	uint64x2_t inc = vdupq_n_u64(1);

	st->counter_lo = vreinterpretq_u8_u64(vaddq_u64(lo64, inc));
	st->counter_hi = vreinterpretq_u8_u64(vaddq_u64(hi64, inc));
}

#else
STATIC void storm256_init_scalar(Storm256Context *ctx, const u8 key[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;

	for (int i = 0; i < 32; ++i) {
		st->state[i] = key[i] ^ STORM_KEY_MIX[i];
		st->key[i] = key[i] ^ STORM_KEY_MIX[32 + i];
	}
	fastmemcpy(st->counter, ZERO256, 32);
}

STATIC void storm256_next_block_scalar(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;

	u8 lo[16], hi[16];

	for (int i = 0; i < 16; ++i) {
		lo[i] = st->state[i] ^ buf[i];
		hi[i] = st->state[i + 16] ^ buf[i + 16];
	}

	aesenc128(lo, st->key);
	aesenc128(hi, st->key + 16);

	u8 orig_lo[16], orig_hi[16];
	fastmemcpy(orig_lo, lo, 16);
	fastmemcpy(orig_hi, hi, 16);

	for (int i = 0; i < 16; ++i) {
		lo[i] ^= hi[i];
	}

	for (int i = 0; i < 16; ++i) {
		st->state[i] = orig_hi[i];
		st->state[i + 16] = lo[i];
	}

	aesenc128(orig_lo, st->key);
	aesenc128(orig_hi, st->key + 16);

	for (int i = 0; i < 16; ++i) {
		buf[i] = orig_lo[i];
		buf[i + 16] = orig_hi[i];
	}
}
STATIC void storm256_xcrypt_buffer_scalar(Storm256Context *ctx, u8 buf[32]) {
	Storm256ContextImpl *st = (Storm256ContextImpl *)ctx;
	u8 block[32];
	fastmemcpy(block, st->counter, 32);

	storm256_next_block(ctx, block);

	for (int i = 0; i < 32; i++) {
		buf[i] ^= block[i];
	}

	u64 *counter = (u64 *)st->counter;
	++counter[0];
	++counter[1];
	++counter[2];
	++counter[3];
}

#endif /* !USE_AVX2 */

PUBLIC void storm256_init(Storm256Context *ctx, const u8 key[32]) {
#ifdef USE_AVX2
	storm256_init_avx2(ctx, key);
#elif defined(USE_NEON)
	storm256_init_neon(ctx, key);
#else
	storm256_init_scalar(ctx, key);
#endif /* !USE_AVX2 */
}

PUBLIC void storm256_next_block(Storm256Context *ctx, u8 buf[32]) {
#ifdef USE_AVX2
	storm256_next_block_avx2(ctx, buf);
#elif defined(USE_NEON)
	storm256_next_block_neon(ctx, buf);
	storm256_next_block_neon(ctx, buf);
#else
	storm256_next_block_scalar(ctx, buf);
	storm256_next_block_scalar(ctx, buf);
#endif /* !USE_AVX2 */
}

PUBLIC void storm256_xcrypt_buffer(Storm256Context *ctx, u8 buf[32]) {
#ifdef USE_AVX2
	storm256_xcrypt_buffer_avx2(ctx, buf);
#elif defined(USE_NEON)
	storm256_xcrypt_buffer_neon(ctx, buf);
#else
	storm256_xcrypt_buffer_scalar(ctx, buf);
#endif /* !USE_AVX2 */
}

