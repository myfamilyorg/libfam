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

void pack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	     const polyveck *t1) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) pk[i] = rho[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}

void unpack_pk(u8 rho[SEEDBYTES], polyveck *t1,
	       const u8 pk[CRYPTO_PUBLICKEYBYTES]) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = pk[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}

void pack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	     const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyveck *t0,
	     const polyvecl *s1, const polyveck *s2) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = rho[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = key[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) sk[i] = tr[i];
	sk += TRBYTES;

	for (i = 0; i < L; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
	sk += L * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}

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

void pack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvecl *z,
	      const polyveck *h) {
	unsigned int i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) sig[i] = c[i];
	sig += CTILDEBYTES;

	for (i = 0; i < L; ++i)
		polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
	sig += L * POLYZ_PACKEDBYTES;

	/* Encode h */
	for (i = 0; i < OMEGA + K; ++i) sig[i] = 0;

	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j)
			if (h->vec[i].coeffs[j] != 0) sig[k++] = j;

		sig[OMEGA + i] = k;
	}
}

int unpack_sig(u8 c[CTILDEBYTES], polyvecl *z, polyveck *h,
	       const u8 sig[CRYPTO_BYTES]) {
	unsigned int i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) c[i] = sig[i];
	sig += CTILDEBYTES;

	for (i = 0; i < L; ++i)
		polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
	sig += L * POLYZ_PACKEDBYTES;

	/* Decode h */
	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j) h->vec[i].coeffs[j] = 0;

		if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) return 1;

		for (j = k; j < sig[OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > k && sig[j] <= sig[j - 1]) return 1;
			h->vec[i].coeffs[sig[j]] = 1;
		}

		k = sig[OMEGA + i];
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = k; j < OMEGA; ++j)
		if (sig[j]) return 1;

	return 0;
}

#endif /* USE_AVX2 */
