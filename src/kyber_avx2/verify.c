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
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#ifdef USE_AVX2

#include <kyber_avx2/verify.h>

/*************************************************
 * Name:        verify
 *
 * Description: Compare two arrays for equality in constant time.
 *
 * Arguments:   const u8 *a: pointer to first byte array
 *              const u8 *b: pointer to second byte array
 *              u64 len: length of the byte arrays
 *
 * Returns 0 if the byte arrays are equal, 1 otherwise
 **************************************************/
int verify(const u8 *a, const u8 *b, u64 len) {
	u64 i;
	u64 r;
	__m256i f, g, h;

	h = _mm256_setzero_si256();
	for (i = 0; i < len / 32; i++) {
		f = _mm256_loadu_si256((__m256i *)&a[32 * i]);
		g = _mm256_loadu_si256((__m256i *)&b[32 * i]);
		f = _mm256_xor_si256(f, g);
		h = _mm256_or_si256(h, f);
	}
	r = 1 - _mm256_testz_si256(h, h);

	a += 32 * i;
	b += 32 * i;
	len -= 32 * i;
	for (i = 0; i < len; i++) r |= a[i] ^ b[i];

	r = (-r) >> 63;
	return r;
}

/*************************************************
 * Name:        cmov
 *
 * Description: Copy len bytes from x to r if b is 1;
 *              don't modify x if b is 0. Requires b to be in {0,1};
 *              assumes two's complement representation of negative integers.
 *              Runs in constant time.
 *
 * Arguments:   u8 *r: pointer to output byte array
 *              const u8 *x: pointer to input byte array
 *              u64 len: Amount of bytes to be copied
 *              u8 b: Condition bit; has to be in {0,1}
 **************************************************/
void cmov(u8 *restrict r, const u8 *x, u64 len, u8 b) {
	u64 i;
	__m256i xvec, rvec, bvec;

#if defined(__GNUC__) || defined(__clang__)
	// Prevent the compiler from
	//    1) inferring that b is 0/1-valued, and
	//    2) handling the two cases with a branch.
	// This is not necessary when verify.c and kem.c are separate
	// translation units, but we expect that downstream consumers will copy
	// this code and/or change how it is built.
	__asm__("" : "+r"(b) : /* no inputs */);
#endif

	bvec = _mm256_set1_epi64x(-(u64)b);
	for (i = 0; i < len / 32; i++) {
		rvec = _mm256_loadu_si256((__m256i *)&r[32 * i]);
		xvec = _mm256_loadu_si256((__m256i *)&x[32 * i]);
		rvec = _mm256_blendv_epi8(rvec, xvec, bvec);
		_mm256_storeu_si256((__m256i *)&r[32 * i], rvec);
	}

	r += 32 * i;
	x += 32 * i;
	len -= 32 * i;
	for (i = 0; i < len; i++) r[i] ^= -b & (x[i] ^ r[i]);
}

#endif /* !USE_AVX2 */
