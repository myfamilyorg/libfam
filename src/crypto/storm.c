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
	__m256i x = _mm256_xor_si256(*(__m256i *)st->state, p);
	__m256i key0 = *(__m256i *)st->key0;
	__m256i key1 = *(__m256i *)st->key1;
	__m256i key2 = *(__m256i *)st->key2;
	__m256i key3 = *(__m256i *)st->key3;
	aesenc256(&x, &key0);
	__m128i lo = _mm256_castsi256_si128(x);
	__m128i hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	__m256i y = _mm256_set_m128i(lo, hi);
	aesenc256(&x, &key1);
	x = _mm256_xor_si256(y, x);
	aesenc256(&x, &key2);
	lo = _mm256_castsi256_si128(x);
	hi = _mm256_extracti128_si256(x, 1);
	lo = _mm_xor_si128(lo, hi);
	*(__m256i *)st->state = _mm256_set_m128i(lo, hi);
	aesenc256(&x, &key3);
	_mm256_store_si256((__m256i *)buf, x);
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
STATIC void storm_next_block_neon(StormContext *ctx, u8 buf[32], i32 index) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	u8 x[32], orig[32];
	for (int i = 0; i < 32; i++) x[i] = st->state[i] ^ buf[i];
	aesenc256(x, index == 0 ? st->key0 : st->key2);
	fastmemcpy(orig, x, 32);
	for (int i = 0; i < 16; ++i) {
		st->state[i] = orig[i + 16];
		st->state[i + 16] = orig[i] ^ orig[i + 16];
	}
	aesenc256(orig, index == 0 ? st->key1 : st->key3);
	fastmemcpy(buf, orig, 32);
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

STATIC void storm_next_block_scalar(StormContext *ctx, u8 buf[32], i32 index) {
	StormContextImpl *st = (StormContextImpl *)ctx;
	u8 x[32], orig[32];
	for (int i = 0; i < 32; i++) x[i] = st->state[i] ^ buf[i];
	aesenc256(x, index == 0 ? st->key0 : st->key2);
	fastmemcpy(orig, x, 32);
	for (int i = 0; i < 16; ++i) {
		st->state[i] = orig[i + 16];
		st->state[i + 16] = orig[i] ^ orig[i + 16];
	}
	aesenc256(orig, index == 0 ? st->key1 : st->key3);
	fastmemcpy(buf, orig, 32);
}
#endif /* !USE_AVX2 */

void storm_init(StormContext *ctx, const u8 key[32]) {
#ifdef USE_AVX2
	storm_init_avx2(ctx, key);
#elif defined(USE_NEON)
	storm_init_neon(ctx, key);
#else
	storm_init_scalar(ctx, key);
#endif
}

void storm_next_block(StormContext *ctx, u8 block[32]) {
#ifdef USE_AVX2
	storm_next_block_avx2(ctx, block);
#elif defined(USE_NEON)
	storm_next_block_neon(ctx, block, 0);
	storm_next_block_neon(ctx, block, 1);

#else
	storm_next_block_scalar(ctx, block, 0);
	storm_next_block_scalar(ctx, block, 1);
#endif
}
