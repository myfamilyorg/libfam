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

#include <kyber_avx2/align.h>
#include <kyber_avx2/cbd.h>
#include <kyber_avx2/indcpa.h>
#include <kyber_avx2/ntt.h>
#include <kyber_avx2/poly.h>
#include <kyber_avx2/polyvec.h>
#include <kyber_avx2/rejsample.h>
#include <libfam/kem_impl.h>
#include <libfam/kem_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>

static void pack_pk(u8 r[KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk,
		    const u8 seed[KYBER_SYMBYTES]) {
	polyvec_tobytes(r, pk);
	fastmemcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void unpack_pk(polyvec *pk, u8 seed[KYBER_SYMBYTES],
		      const u8 packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
	polyvec_frombytes(pk, packedpk);
	fastmemcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void pack_sk(u8 r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
	polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk,
		      const u8 packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
	polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(u8 r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
	polyvec_compress(r, b);
	poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v,
			      const u8 c[KYBER_INDCPA_BYTES]) {
	polyvec_decompress(b, c);
	poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static unsigned int rej_uniform(i16 *r, unsigned int len, const u8 *buf,
				unsigned int buflen) {
	unsigned int ctr, pos;
	u16 val0, val1;

	ctr = pos = 0;
	while (ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
		val0 = ((buf[pos + 0] >> 0) | ((u16)buf[pos + 1] << 8)) & 0xFFF;
		val1 = ((buf[pos + 1] >> 4) | ((u16)buf[pos + 2] << 4)) & 0xFFF;
		pos += 3;

		if (val0 < KYBER_Q) r[ctr++] = val0;
		if (ctr < len && val1 < KYBER_Q) r[ctr++] = val1;
	}

	return ctr;
}

#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)

#include <libfam/format.h>
void gen_matrix(polyvec *a, const u8 seed[32], int transposed) {
	StormContext ctx0, ctx1, ctx2, ctx3;
	unsigned int i, ctr0, ctr1, ctr2, ctr3;
	ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS * SHAKE128_RATE + 8) buf[4] = {0};
	__m256i f;

	f = _mm256_loadu_si256((__m256i *)seed);
	_mm256_store_si256(buf[0].vec + 1, f);
	_mm256_store_si256(buf[1].vec + 1, f);
	_mm256_store_si256(buf[2].vec + 1, f);
	_mm256_store_si256(buf[3].vec + 1, f);

	if (transposed) {
		for (i = 0; i < 16; i++) {
			buf[0].coeffs[2 * i + 0] = 0;
			buf[0].coeffs[2 * i + 1] = 0;
			buf[1].coeffs[2 * i + 0] = 0;
			buf[1].coeffs[2 * i + 1] = 1;
			buf[2].coeffs[2 * i + 0] = 1;
			buf[2].coeffs[2 * i + 1] = 0;
			buf[3].coeffs[2 * i + 0] = 1;
			buf[3].coeffs[2 * i + 1] = 1;
		}

	} else {
		for (i = 0; i < 16; i++) {
			buf[0].coeffs[2 * i + 0] = 0;
			buf[0].coeffs[2 * i + 1] = 0;
			buf[1].coeffs[2 * i + 0] = 1;
			buf[1].coeffs[2 * i + 1] = 0;
			buf[2].coeffs[2 * i + 0] = 0;
			buf[2].coeffs[2 * i + 1] = 1;
			buf[3].coeffs[2 * i + 0] = 1;
			buf[3].coeffs[2 * i + 1] = 1;
		}
	}

	storm_init(&ctx0, GEN_MAT_DOMAIN);
	storm_init(&ctx1, GEN_MAT_DOMAIN);
	storm_init(&ctx2, GEN_MAT_DOMAIN);
	storm_init(&ctx3, GEN_MAT_DOMAIN);

	for (u32 i = 0; i < sizeof(buf[0].coeffs); i += 32) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i);
	}

	ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
	ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
	ctr2 = rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
	ctr3 = rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

	while (ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N ||
	       ctr3 < KYBER_N) {
		fastmemset(buf[0].coeffs, 0, SHAKE256_RATE);
		fastmemset(buf[1].coeffs, 0, SHAKE256_RATE);
		fastmemset(buf[2].coeffs, 0, SHAKE256_RATE);
		fastmemset(buf[3].coeffs, 0, SHAKE256_RATE);
		for (u32 i = 0; i < 5; i++) {
			storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i * 32);
			storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i * 32);
			storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i * 32);
			storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i * 32);
		}

		ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0,
				    buf[0].coeffs, SHAKE128_RATE);
		ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1,
				    buf[1].coeffs, SHAKE128_RATE);
		ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, KYBER_N - ctr2,
				    buf[2].coeffs, SHAKE128_RATE);
		ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, KYBER_N - ctr3,
				    buf[3].coeffs, SHAKE128_RATE);
	}

	poly_nttunpack(&a[0].vec[0]);
	poly_nttunpack(&a[0].vec[1]);
	poly_nttunpack(&a[1].vec[0]);
	poly_nttunpack(&a[1].vec[1]);
}

void indcpa_keypair_derand(u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
			   u8 sk[KYBER_INDCPA_SECRETKEYBYTES],
			   const u8 coins[KYBER_SYMBYTES]) {
	StormContext ctx;
	unsigned int i;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES] = {0};
	const u8 *publicseed = buf;
	const u8 *noiseseed = buf + KYBER_SYMBYTES;
	polyvec a[KYBER_K], e, pkpv, skpv;

	fastmemcpy(buf, coins, KYBER_SYMBYTES);
	buf[KYBER_SYMBYTES] = KYBER_K;

	storm_init(&ctx, INDCPA_HASH_DOMAIN);
	storm_next_block(&ctx, buf);
	storm_next_block(&ctx, buf + 32);

	gen_a(a, publicseed);

	poly_getnoise_eta1_4x(skpv.vec + 0, skpv.vec + 1, e.vec + 0, e.vec + 1,
			      noiseseed, 0, 1, 2, 3);

	polyvec_ntt(&skpv);
	polyvec_reduce(&skpv);
	polyvec_ntt(&e);

	for (i = 0; i < KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
		poly_tomont(&pkpv.vec[i]);
	}

	polyvec_add(&pkpv, &pkpv, &e);
	polyvec_reduce(&pkpv);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);
}

void indcpa_enc(u8 c[KYBER_INDCPA_BYTES], const u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
		const u8 coins[KYBER_SYMBYTES]) {
	unsigned int i;
	u8 seed[KYBER_SYMBYTES];
	polyvec sp, pkpv, ep, at[KYBER_K], b;
	poly v, k, epp;

	unpack_pk(&pkpv, seed, pk);
	poly_frommsg(&k, m);
	gen_at(at, seed);

	poly_getnoise_eta1122_4x(sp.vec + 0, sp.vec + 1, ep.vec + 0, ep.vec + 1,
				 coins, 0, 1, 2, 3);
	poly_getnoise_eta2(&epp, coins, 4);

	polyvec_ntt(&sp);

	for (i = 0; i < KYBER_K; i++)
		polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
	polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

	polyvec_invntt_tomont(&b);
	poly_invntt_tomont(&v);

	polyvec_add(&b, &b, &ep);
	poly_add(&v, &v, &epp);
	poly_add(&v, &v, &k);
	polyvec_reduce(&b);
	poly_reduce(&v);

	pack_ciphertext(c, &b, &v);
}

void indcpa_dec(u8 m[KYBER_INDCPA_MSGBYTES], const u8 c[KYBER_INDCPA_BYTES],
		const u8 sk[KYBER_INDCPA_SECRETKEYBYTES]) {
	polyvec b, skpv;
	poly v, mp;

	unpack_ciphertext(&b, &v, c);
	unpack_sk(&skpv, sk);

	polyvec_ntt(&b);
	polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
	poly_invntt_tomont(&mp);

	poly_sub(&mp, &v, &mp);
	poly_reduce(&mp);

	poly_tomsg(m, &mp);
}

#endif /* !USE_AVX2 */
