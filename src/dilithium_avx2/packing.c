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

#include <dilithium_avx2/packing.h>
#include <dilithium_avx2/params.h>
#include <dilithium_avx2/poly.h>
#include <dilithium_avx2/polyvec.h>

void unpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
	       polyveck *t0, polyvecl *s1, polyveck *s2,
	       const u8 sk[CRYPTO_SECRETKEYBYTES]) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) key[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) tr[i] = sk[i];
	sk += TRBYTES;

	for (i = 0; i < L; ++i)
		polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += L * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}

#endif /* USE_AVX2 */
