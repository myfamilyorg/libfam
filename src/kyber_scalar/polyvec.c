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

#ifndef USE_AVX2

#include <kyber_common/params.h>
#include <kyber_scalar/poly.h>
#include <kyber_scalar/polyvec.h>
#include <libfam/format.h>

void polyvec_compress(u8 r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a) {
	unsigned int i, j, k;
	u64 d0;

	u16 t[4];
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_N / 4; j++) {
			for (k = 0; k < 4; k++) {
				t[k] = a->vec[i].coeffs[4 * j + k];
				t[k] += ((i16)t[k] >> 15) & KYBER_Q;
				d0 = t[k];
				d0 <<= 10;
				d0 += 1665;
				d0 *= 1290167;
				d0 >>= 32;
				t[k] = d0 & 0x3ff;
			}

			r[0] = (t[0] >> 0);
			r[1] = (t[0] >> 8) | (t[1] << 2);
			r[2] = (t[1] >> 6) | (t[2] << 4);
			r[3] = (t[2] >> 4) | (t[3] << 6);
			r[4] = (t[3] >> 2);
			r += 5;
		}
	}
}

void polyvec_decompress(polyvec *r, const u8 a[KYBER_POLYVECCOMPRESSEDBYTES]) {
	unsigned int i, j, k;
	u16 t[4];

	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_N / 4; j++) {
			t[0] = (a[0] >> 0) | ((u16)a[1] << 8);
			t[1] = (a[1] >> 2) | ((u16)a[2] << 6);
			t[2] = (a[2] >> 4) | ((u16)a[3] << 4);
			t[3] = (a[3] >> 6) | ((u16)a[4] << 2);
			a += 5;

			for (k = 0; k < 4; k++)
				r->vec[i].coeffs[4 * j + k] =
				    ((u32)(t[k] & 0x3FF) * KYBER_Q + 512) >> 10;
		}
	}
}

void polyvec_tobytes(u8 r[KYBER_POLYVECBYTES], const polyvec *a) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

void polyvec_frombytes(polyvec *r, const u8 a[KYBER_POLYVECBYTES]) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

void polyvec_ntt(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_ntt(&r->vec[i]);
}

void polyvec_invntt_tomont(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_invntt_tomont(&r->vec[i]);
}

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
				    const polyvec *b) {
	unsigned int i;
	poly t;

	poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
	for (i = 1; i < KYBER_K; i++) {
		poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
		poly_add(r, r, &t);
	}

	poly_reduce(r);
}

void polyvec_reduce(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_reduce(&r->vec[i]);
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

#endif /* !USE_AVX2 */
