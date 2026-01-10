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

#include <libfam/kem_impl.h>
#include <kyber_scalar/cbd.h>
#include <kyber_scalar/ntt.h>
#include <kyber_scalar/poly.h>
#include <kyber_scalar/reduce.h>
#include <kyber_scalar/verify.h>
#include <libfam/format.h>
#include <libfam/kem_impl.h>
#include <libfam/storm.h>

static void storm_init_nonce2(StormContext *ctx, u16 nonce) {
	__attribute__((aligned(32))) u8 key[32];
	fastmemcpy(key, NOISE_ETA2_DOMAIN, 32);
	for (u32 i = 0; i < 16; i++) ((u16 *)key)[i] ^= nonce;
	storm_init(ctx, key);
}

static void storm_init_nonce1(StormContext *ctx, u16 nonce) {
	__attribute__((aligned(32))) u8 key[32];
	fastmemcpy(key, NOISE_ETA1_DOMAIN, 32);
	for (u32 i = 0; i < 16; i++) ((u16 *)key)[i] ^= nonce;
	storm_init(ctx, key);
}

void poly_compress(u8 r[KYBER_POLYCOMPRESSEDBYTES], const poly *a) {
	unsigned int i, j;
	i16 u;
	u32 d0;
	u8 t[8];

	for (i = 0; i < KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			u = a->coeffs[8 * i + j];
			u += (u >> 15) & KYBER_Q;
			d0 = u << 4;
			d0 += 1665;
			d0 *= 80635;
			d0 >>= 28;
			t[j] = d0 & 0xf;
		}

		r[0] = t[0] | (t[1] << 4);
		r[1] = t[2] | (t[3] << 4);
		r[2] = t[4] | (t[5] << 4);
		r[3] = t[6] | (t[7] << 4);
		r += 4;
	}
}

void poly_decompress(poly *r, const u8 a[KYBER_POLYCOMPRESSEDBYTES]) {
	unsigned int i;

	for (i = 0; i < KYBER_N / 2; i++) {
		r->coeffs[2 * i + 0] = (((u16)(a[0] & 15) * KYBER_Q) + 8) >> 4;
		r->coeffs[2 * i + 1] = (((u16)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
		a += 1;
	}
}

void poly_tobytes(u8 r[KYBER_POLYBYTES], const poly *a) {
	unsigned int i;
	u16 t0, t1;

	for (i = 0; i < KYBER_N / 2; i++) {
		t0 = a->coeffs[2 * i];
		t0 += ((i16)t0 >> 15) & KYBER_Q;
		t1 = a->coeffs[2 * i + 1];
		t1 += ((i16)t1 >> 15) & KYBER_Q;
		r[3 * i + 0] = (t0 >> 0);
		r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
		r[3 * i + 2] = (t1 >> 4);
	}
}

void poly_frombytes(poly *r, const u8 a[KYBER_POLYBYTES]) {
	unsigned int i;
	for (i = 0; i < KYBER_N / 2; i++) {
		r->coeffs[2 * i] =
		    ((a[3 * i + 0] >> 0) | ((u16)a[3 * i + 1] << 8)) & 0xFFF;
		r->coeffs[2 * i + 1] =
		    ((a[3 * i + 1] >> 4) | ((u16)a[3 * i + 2] << 4)) & 0xFFF;
	}
}

void poly_frommsg(poly *r, const u8 msg[KYBER_INDCPA_MSGBYTES]) {
	unsigned int i, j;

	for (i = 0; i < KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			r->coeffs[8 * i + j] = 0;
			cmov_int16(r->coeffs + 8 * i + j, ((KYBER_Q + 1) / 2),
				   (msg[i] >> j) & 1);
		}
	}
}

void poly_tomsg(u8 msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
	unsigned int i, j;
	u32 t;

	for (i = 0; i < KYBER_N / 8; i++) {
		msg[i] = 0;
		for (j = 0; j < 8; j++) {
			t = a->coeffs[8 * i + j];
			t <<= 1;
			t += 1665;
			t *= 80635;
			t >>= 28;
			t &= 1;
			msg[i] |= t << j;
		}
	}
}

void poly_getnoise_eta1(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce) {
	__attribute__((aligned(32))) u8 buf[KYBER_ETA1 * KYBER_N / 4] = {0};
	StormContext ctx;

	storm_init_nonce1(&ctx, nonce);
	// storm_init(&ctx, NOISE_ETA1_DOMAIN);
	fastmemcpy(buf, seed, KYBER_SYMBYTES);
	buf[KYBER_SYMBYTES] = nonce;
	storm_next_block(&ctx, buf);
	storm_next_block(&ctx, buf + 32);

	for (u32 i = 0; i < sizeof(buf); i += 32)
		storm_next_block(&ctx, buf + i);

	poly_cbd_eta1(r, buf);
}

void poly_getnoise_eta2(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce) {
	__attribute__((aligned(32))) u8 buf[KYBER_ETA2 * KYBER_N / 4] = {0};
	StormContext ctx;

	// storm_init(&ctx, NOISE_ETA2_DOMAIN);
	storm_init_nonce2(&ctx, nonce);
	fastmemcpy(buf, seed, KYBER_SYMBYTES);
	buf[KYBER_SYMBYTES] = nonce;
	storm_next_block(&ctx, buf);
	storm_next_block(&ctx, buf + 32);

	for (u32 i = 0; i < sizeof(buf); i += 32)
		storm_next_block(&ctx, buf + i);

	poly_cbd_eta2(r, buf);
}

void poly_ntt(poly *r) {
	ntt(r->coeffs);
	poly_reduce(r);
}

void poly_invntt_tomont(poly *r) { invntt(r->coeffs); }

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
	unsigned int i;
	for (i = 0; i < KYBER_N / 4; i++) {
		basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i],
			zetas[64 + i]);
		basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2],
			&b->coeffs[4 * i + 2], -zetas[64 + i]);
	}
}

void poly_tomont(poly *r) {
	unsigned int i;
	const i16 f = (1ULL << 32) % KYBER_Q;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = montgomery_reduce((i32)r->coeffs[i] * f);
}

void poly_reduce(poly *r) {
	unsigned int i;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

void poly_add(poly *r, const poly *a, const poly *b) {
	unsigned int i;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *r, const poly *a, const poly *b) {
	unsigned int i;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

#endif /* !USE_AVX2 */
