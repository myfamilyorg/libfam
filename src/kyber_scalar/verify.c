/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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

#ifndef USE_AVX2

#include <kyber_scalar/verify.h>

int verify(const u8 *a, const u8 *b, u64 len) {
	u64 i;
	u8 r = 0;

	for (i = 0; i < len; i++) r |= a[i] ^ b[i];

	return (-(u64)r) >> 63;
}

void cmov(u8 *r, const u8 *x, u64 len, u8 b) {
	u64 i;

	// Prevent the compiler from
	//    1) inferring that b is 0/1-valued, and
	//    2) handling the two cases with a branch.
	// This is not necessary when verify.c and kem.c are separate
	// translation units, but we expect that downstream consumers will copy
	// this code and/or change how it is built.
	__asm__("" : "+r"(b) : /* no inputs */);

	b = -b;
	for (i = 0; i < len; i++) r[i] ^= b & (r[i] ^ x[i]);
}

void cmov_int16(i16 *r, i16 v, u16 b) {
	b = -b;
	*r ^= b & ((*r) ^ v);
}

#endif /* !USE_AVX2 */
