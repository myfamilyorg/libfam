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
#include <libfam/aighthash.h>
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
};
static const u8* AIGHT_DOMAIN = (void*)PRIMES;

#define AIGHT64_INIT 0x9E3779B97F4A7C15ULL
#define AIGHT_P1 0xc2b2ae35u
#define AIGHT_P2 0x85ebca6bu

PUBLIC u64 aighthash64(const void* data, u64 len, u64 seed) {
	const u8* p = (const u8*)data;
	u64 h = seed ^ AIGHT64_INIT;
#ifdef USE_AVX2
	__m256i key = _mm256_load_si256((const __m256i*)AIGHT_DOMAIN);
#else
	const u8* key = AIGHT_DOMAIN;
#endif
	u64 tail = 0;

	// while ((u64)p & 31) tail ^= (u64)*p++ << (8 * (len & 7)), len--;

	while (len >= 256) {
		for (int i = 0; i < 8; i++) {
#ifdef USE_AVX2
			__m256i x =
			    _mm256_loadu_si256((const __m256i*)(p + i * 32));
			x = _mm256_aesenc_epi128(x, key);
			h ^= *(u64*)&x ^ *(u64*)((u8*)(&x) + 8) ^
			     *(u64*)((u8*)(&x) + 16) ^ *(u64*)((u8*)(&x) + 24);
#else
			u8 x[32];
			fastmemcpy(x, p + i * 32, 32);
			aesenc256(x, key);
			h ^= *(u64*)x ^ *(u64*)((u8*)x + 8) ^
			     *(u64*)((u8*)x + 16) ^ *(u64*)((u8*)x + 24);
#endif
		}

		p += 256;
		len -= 256;
	}

	while (len >= 32) {
#ifdef USE_AVX2
		__m256i x = _mm256_loadu_si256((const __m256i*)p);
		x = _mm256_aesenc_epi128(x, key);
		h ^= *(u64*)&x ^ *(u64*)((u8*)(&x) + 8) ^
		     *(u64*)((u8*)(&x) + 16) ^ *(u64*)((u8*)(&x) + 24);
#else
		u8 x[32];
		fastmemcpy(x, p, 32);
		aesenc256(x, key);
		h ^= *(u64*)x ^ *(u64*)((u8*)x + 8) ^ *(u64*)((u8*)x + 16) ^
		     *(u64*)((u8*)x + 24);
#endif
		p += 32;
		len -= 32;
	}

	while (len--) tail ^= (u64)*p++ << (8 * (len & 7));

	h ^= tail;
	h *= AIGHT_P2;
	h ^= h >> 29;
	h *= AIGHT_P1;
	h ^= h >> 33;

	return h;
}

