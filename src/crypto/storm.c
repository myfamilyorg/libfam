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

#include <libfam/aesenc.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/utils.h>

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

static const __attribute__((aligned(32))) u128 PRIMES[] = {
    ((u128)0xa70413383f55618fULL << 64) | 0x376d0932e21de58fULL,
    ((u128)0xf95524bf9f2fdfa8ULL << 64) | 0xf3fb6d8bd7643b1dULL,
    ((u128)0xdcdca803f6e7c96cULL << 64) | 0x39851fc1badcb0dbULL,
    ((u128)0x868825605fa0d9dfULL << 64) | 0xacb47fb23b6206dbULL,

    ((u128)0xf95524bf9f2fdfa8ULL << 64) | 0xf3fb6d8bd7643b1dULL,
    ((u128)0xdcdca803f6e7c96cULL << 64) | 0x39851fc1badcb0dbULL,
    ((u128)0x868825605fa0d9dfULL << 64) | 0xacb47fb23b6206dbULL,
    ((u128)0xa70413383f55618fULL << 64) | 0x376d0932e21de58fULL,

    ((u128)0xdcdca803f6e7c96cULL << 64) | 0x39851fc1badcb0dbULL,
    ((u128)0x868825605fa0d9dfULL << 64) | 0xacb47fb23b6206dbULL,
    ((u128)0xa70413383f55618fULL << 64) | 0x376d0932e21de58fULL,
    ((u128)0xf95524bf9f2fdfa8ULL << 64) | 0xf3fb6d8bd7643b1dULL,

    ((u128)0x868825605fa0d9dfULL << 64) | 0xacb47fb23b6206dbULL,
    ((u128)0xa70413383f55618fULL << 64) | 0x376d0932e21de58fULL,
    ((u128)0xf95524bf9f2fdfa8ULL << 64) | 0xf3fb6d8bd7643b1dULL,
    ((u128)0xdcdca803f6e7c96cULL << 64) | 0x39851fc1badcb0dbULL,
};
static const u8 *STORM_KEY_MIX = (void *)PRIMES;

typedef struct {
	__attribute__((aligned)) u8 state[32];
	__attribute__((aligned)) u8 key0[32];
	__attribute__((aligned)) u8 key1[32];
	__attribute__((aligned)) u8 key2[32];
	__attribute__((aligned)) u8 key3[32];
	__attribute__((aligned)) u8 counter[32];
} StormContextImpl;

#ifdef USE_AVX2
STATIC void storm_init_avx2(StormContext *ctx, const u8 key[32]) {
	static const __attribute__((aligned(32))) u8 ZERO256[32] = {0};
	StormContextImpl *st = (StormContextImpl *)ctx;
	__m256i key256 = _mm256_load_si256((const __m256i *)key);
	__m256i domain = _mm256_load_si256((const __m256i *)STORM_KEY_MIX);
	*(__m256i *)st->state = _mm256_xor_si256(key256, domain);
	__m256i domain_key =
	    _mm256_load_si256((const __m256i *)(STORM_KEY_MIX + 32));
	*(__m256i *)st->key0 = _mm256_xor_si256(key256, domain_key);
	domain_key = _mm256_load_si256((const __m256i *)(STORM_KEY_MIX + 64));
	*(__m256i *)st->key1 = _mm256_xor_si256(key256, domain_key);
	domain_key = _mm256_load_si256((const __m256i *)(STORM_KEY_MIX + 96));
	*(__m256i *)st->key2 = _mm256_xor_si256(key256, domain_key);
	domain_key = _mm256_load_si256((const __m256i *)(STORM_KEY_MIX + 128));
	*(__m256i *)st->key3 = _mm256_xor_si256(key256, domain_key);
	*(__m256i *)st->counter = _mm256_load_si256((const __m256i *)ZERO256);
}
STATIC void storm_next_block_avx2(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	__m256i p = _mm256_load_si256((const __m256i *)buf);
	__m256i x = _mm256_xor_si256(*(const __m256i *)st->state, p);
	__m256i key0 = *(__m256i *)st->key0;
	__m256i key1 = *(__m256i *)st->key1;
	__m256i key2 = *(__m256i *)st->key2;
	__m256i key3 = *(__m256i *)st->key3;
	x = _mm256_aesenc_epi128(x, key0);
	__m128i lo = _mm256_castsi256_si128(x);
	__m128i hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	__m256i y = _mm256_set_m128i(lo, hi);
	x = _mm256_aesenc_epi128(x, key1);
	x = _mm256_xor_si256(y, x);
	x = _mm256_aesenc_epi128(x, key2);
	lo = _mm256_castsi256_si128(x);
	hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	*(__m256i *)st->state = _mm256_set_m128i(lo, hi);
	x = _mm256_aesenc_epi128(x, key3);
	_mm256_store_si256((__m256i *)buf, x);
}

STATIC void storm_xcrypt_buffer_avx2(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	__m256i ctr = *(__m256i *)st->counter;
	storm_next_block(ctx, (u8 *)&ctr);
	_mm256_store_si256(
	    (__m256i *)buf,
	    _mm256_xor_si256(_mm256_load_si256((__m256i *)buf), ctr));
	*(__m256i *)st->counter =
	    _mm256_add_epi64(*(__m256i *)st->counter, _mm256_set1_epi64x(1));
}
#elif defined(USE_NEON)
STATIC void storm_init_neon(StormContext *ctx, const u8 key[32]) {
	static const __attribute__((aligned(32))) u8 ZERO256[32] = {0};
	StormContextImpl *st = (StormContextImpl *)ctx;

	for (int i = 0; i < 32; ++i) {
		st->state[i] = key[i] ^ STORM_KEY_MIX[i];
		st->key0[i] = key[i] ^ STORM_KEY_MIX[32 + i];
		st->key1[i] = key[i] ^ STORM_KEY_MIX[64 + i];
		st->key2[i] = key[i] ^ STORM_KEY_MIX[96 + i];
		st->key3[i] = key[i] ^ STORM_KEY_MIX[128 + i];
	}
	fastmemcpy(st->counter, ZERO256, 32);
}
STATIC void storm_next_block_neon(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	uint8x16_t state_lo = vld1q_u8(st->state);
	uint8x16_t state_hi = vld1q_u8(st->state + 16);
	uint8x16_t buf_lo = vld1q_u8(buf);
	uint8x16_t buf_hi = vld1q_u8(buf + 16);
	uint8x16_t x_lo = veorq_u8(state_lo, buf_lo);
	uint8x16_t x_hi = veorq_u8(state_hi, buf_hi);
	vst1q_u8(buf, x_lo);
	vst1q_u8(buf + 16, x_hi);
	aesenc256(buf, st->key0);
	uint8x16_t orig_lo = vld1q_u8(buf);
	uint8x16_t orig_hi = vld1q_u8(buf + 16);
	vst1q_u8(st->state, orig_hi);
	vst1q_u8(st->state + 16, veorq_u8(orig_lo, orig_hi));
	vst1q_u8(buf, orig_lo);
	vst1q_u8(buf + 16, orig_hi);
	aesenc256(buf, st->key1);
	state_lo = vld1q_u8(st->state);
	state_hi = vld1q_u8(st->state + 16);
	buf_lo = vld1q_u8(buf);
	buf_hi = vld1q_u8(buf + 16);
	x_lo = veorq_u8(state_lo, buf_lo);
	x_hi = veorq_u8(state_hi, buf_hi);
	vst1q_u8(buf, x_lo);
	vst1q_u8(buf + 16, x_hi);
	aesenc256(buf, st->key2);
	orig_lo = vld1q_u8(buf);
	orig_hi = vld1q_u8(buf + 16);
	vst1q_u8(st->state, orig_hi);
	vst1q_u8(st->state + 16, veorq_u8(orig_lo, orig_hi));
	vst1q_u8(buf, orig_lo);
	vst1q_u8(buf + 16, orig_hi);
	aesenc256(buf, st->key3);
}
STATIC void storm_xcrypt_buffer_neon(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	uint8x16_t ctr_lo = *(uint8x16_t *)st->counter;
	uint8x16_t ctr_hi = *(uint8x16_t *)((u8 *)st->counter + 16);

	u8 ctr_block[32] __attribute__((aligned(16)));
	vst1q_u8(ctr_block, ctr_lo);
	vst1q_u8(ctr_block + 16, ctr_hi);

	storm_next_block(ctx, ctr_block);

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

	*(uint8x16_t *)st->counter = vreinterpretq_u8_u64(vaddq_u64(lo64, inc));
	*(uint8x16_t *)((u8 *)st->counter + 16) =
	    vreinterpretq_u8_u64(vaddq_u64(hi64, inc));
}
#else
STATIC void storm_init_scalar(StormContext *ctx, const u8 key[32]) {
	static const __attribute__((aligned(32))) u8 ZERO256[32] = {0};
	StormContextImpl *st = (StormContextImpl *)ctx;

	for (int i = 0; i < 32; ++i) {
		st->state[i] = key[i] ^ STORM_KEY_MIX[i];
		st->key0[i] = key[i] ^ STORM_KEY_MIX[32 + i];
		st->key1[i] = key[i] ^ STORM_KEY_MIX[64 + i];
		st->key2[i] = key[i] ^ STORM_KEY_MIX[96 + i];
		st->key3[i] = key[i] ^ STORM_KEY_MIX[128 + i];
	}
	fastmemcpy(st->counter, ZERO256, 32);
}

STATIC void storm_next_block_scalar(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;

	u8 x[32], orig[32];

	for (int i = 0; i < 32; i++) x[i] = st->state[i] ^ buf[i];
	aesenc256(x, st->key0);
	fastmemcpy(orig, x, 32);
	for (int i = 0; i < 16; ++i) {
		st->state[i] = orig[i + 16];
		st->state[i + 16] = orig[i] ^ orig[i + 16];
	}

	aesenc256(orig, st->key1);
	fastmemcpy(buf, orig, 32);
	for (int i = 0; i < 32; i++) x[i] = st->state[i] ^ buf[i];
	aesenc256(x, st->key2);

	fastmemcpy(orig, x, 32);

	for (int i = 0; i < 16; ++i) {
		st->state[i] = orig[i + 16];
		st->state[i + 16] = orig[i] ^ orig[i + 16];
	}

	aesenc256(orig, st->key3);
	fastmemcpy(buf, orig, 32);
}
STATIC void storm_xcrypt_buffer_scalar(StormContext *ctx, u8 buf[32]) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	u8 block[32];
	fastmemcpy(block, st->counter, 32);

	storm_next_block(ctx, block);

	for (int i = 0; i < 32; i++) {
		buf[i] ^= block[i];
	}

	u64 *counter = (u64 *)st->counter;
	++counter[0];
	++counter[1];
	++counter[2];
	++counter[3];
}
#endif /* !USE_AVX2 && !USE_NEON */

PUBLIC void storm_init(StormContext *ctx, const u8 key[32]) {
#ifdef USE_AVX2
	storm_init_avx2(ctx, key);
#elif defined(USE_NEON)
	storm_init_neon(ctx, key);
#else
	storm_init_scalar(ctx, key);
#endif
}

PUBLIC void storm_next_block(StormContext *ctx, u8 block[32]) {
#ifdef USE_AVX2
	storm_next_block_avx2(ctx, block);
#elif defined(USE_NEON)
	storm_next_block_neon(ctx, block);
#else
	storm_next_block_scalar(ctx, block);
#endif
}

PUBLIC void storm_xcrypt_buffer(StormContext *ctx, u8 buf[32]) {
#ifdef USE_AVX2
	storm_xcrypt_buffer_avx2(ctx, buf);
#elif defined(USE_NEON)
	storm_xcrypt_buffer_neon(ctx, buf);
#else
	storm_xcrypt_buffer_scalar(ctx, buf);
#endif /* !USE_AVX2 */
}

