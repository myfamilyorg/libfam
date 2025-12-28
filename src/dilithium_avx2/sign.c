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

#include <dilithium_avx2/align.h>
#include <dilithium_avx2/packing.h>
#include <dilithium_avx2/params.h>
#include <dilithium_avx2/poly.h>
#include <dilithium_avx2/polyvec.h>
#include <dilithium_avx2/sign.h>
#include <libfam/rng.h>
#include <libfam/sign_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>

static inline void polyvec_matrix_expand_row(polyvecl **row, polyvecl buf[2],
					     const u8 rho[SEEDBYTES],
					     unsigned int i) {
	switch (i) {
		case 0:
			polyvec_matrix_expand_row0(buf, buf + 1, rho);
			*row = buf;
			break;
		case 1:
			polyvec_matrix_expand_row1(buf + 1, buf, rho);
			*row = buf + 1;
			break;
		case 2:
			polyvec_matrix_expand_row2(buf, buf + 1, rho);
			*row = buf;
			break;
		case 3:
			polyvec_matrix_expand_row3(buf + 1, buf, rho);
			*row = buf + 1;
			break;
	}
}

int crypto_sign_keypair(u8 *pk, u8 *sk, const u8 seed[32]) {
	StormContext ctx;
	unsigned int i;
	__attribute__((aligned(32))) u8 seedbuf[2 * SEEDBYTES + CRHBYTES] = {0};
	const u8 *rho, *rhoprime, *key;
	polyvecl rowbuf[2];
	polyvecl s1, *row = rowbuf;
	polyveck s2;
	poly t1, t0;

	/* Get randomness for rho, rhoprime and key */
	fastmemcpy(seedbuf, seed, 32);
	seedbuf[SEEDBYTES + 0] = K;
	seedbuf[SEEDBYTES + 1] = L;

	storm_init(&ctx, HASH_DOMAIN);
	for (u32 i = 0; i < 2 * SEEDBYTES + CRHBYTES; i += 32)
		storm_next_block(&ctx, seedbuf + i);
	fastmemset(seedbuf, 0, 2 * SEEDBYTES);
	storm_next_block(&ctx, seedbuf);
	storm_next_block(&ctx, seedbuf + 32);

	rho = seedbuf;
	rhoprime = rho + SEEDBYTES;
	key = rhoprime + CRHBYTES;

	/* Store rho, key */
	memcpy(pk, rho, SEEDBYTES);
	memcpy(sk, rho, SEEDBYTES);
	memcpy(sk + SEEDBYTES, key, SEEDBYTES);

	/* Sample short vectors s1 and s2 */
	poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3],
			    rhoprime, 0, 1, 2, 3);
	poly_uniform_eta_4x(&s2.vec[0], &s2.vec[1], &s2.vec[2], &s2.vec[3],
			    rhoprime, 4, 5, 6, 7);

	/* Pack secret vectors */
	for (i = 0; i < L; i++)
		polyeta_pack(
		    sk + 2 * SEEDBYTES + TRBYTES + i * POLYETA_PACKEDBYTES,
		    &s1.vec[i]);
	for (i = 0; i < K; i++)
		polyeta_pack(sk + 2 * SEEDBYTES + TRBYTES +
				 (L + i) * POLYETA_PACKEDBYTES,
			     &s2.vec[i]);

	/* Transform s1 */
	polyvecl_ntt(&s1);

	for (i = 0; i < K; i++) {
		/* Expand matrix row */
		polyvec_matrix_expand_row(&row, rowbuf, rho, i);

		/* Compute inner-product */
		polyvecl_pointwise_acc_montgomery(&t1, row, &s1);
		poly_invntt_tomont(&t1);

		/* Add error polynomial */
		poly_add(&t1, &t1, &s2.vec[i]);

		/* Round t and pack t1, t0 */
		poly_caddq(&t1);
		poly_power2round(&t1, &t0, &t1);
		polyt1_pack(pk + SEEDBYTES + i * POLYT1_PACKEDBYTES, &t1);
		polyt0_pack(sk + 2 * SEEDBYTES + TRBYTES +
				(L + K) * POLYETA_PACKEDBYTES +
				i * POLYT0_PACKEDBYTES,
			    &t0);
	}

	/* Compute H(rho, t1) and store in secret key */

	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((aligned(32))) u8 pk_copy[CRYPTO_PUBLICKEYBYTES];
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);
	for (u32 i = 0; i < CRYPTO_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	fastmemset(sk + 2 * SEEDBYTES, 0, 64);
	storm_next_block(&ctx, sk + 2 * SEEDBYTES);
	storm_next_block(&ctx, sk + 2 * SEEDBYTES + 32);

	return 0;
}

int crypto_sign_signature_internal(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
				   const u8 *pre, u64 prelen,
				   const u8 rnd[RNDBYTES], const u8 *sk) {
	StormContext ctx;
	unsigned int i, n, pos;
	__attribute__((
	    aligned(32))) u8 seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
	u8 *rho, *tr, *key, *mu, *rhoprime;
	u8 hintbuf[N];
	u8 *hint = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
	u64 nonce = 0;
	polyvecl mat[K], s1, z;
	polyveck t0, s2, w1;
	poly c, tmp;
	union {
		polyvecl y;
		polyveck w0;
	} tmpv;

	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + TRBYTES;
	mu = key + SEEDBYTES;
	rhoprime = mu + CRHBYTES;
	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

	/* Compute mu = CRH(tr, pre, msg) */

	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((aligned(32))) u8 buffer[TRBYTES + 32];
	fastmemcpy(buffer, tr, TRBYTES);
	fastmemcpy(buffer + TRBYTES, m, 32);
	storm_next_block(&ctx, buffer);
	storm_next_block(&ctx, buffer + 32);
	storm_next_block(&ctx, buffer + 64);
	fastmemset(mu, 0, 64);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((aligned(32))) u8 rho_prime_buffer[128];
	fastmemcpy(rho_prime_buffer, key, 32);
	fastmemcpy(rho_prime_buffer + 32, rnd, 32);
	fastmemcpy(rho_prime_buffer + 64, mu, 64);
	storm_next_block(&ctx, rho_prime_buffer);
	storm_next_block(&ctx, rho_prime_buffer + 32);
	storm_next_block(&ctx, rho_prime_buffer + 64);
	storm_next_block(&ctx, rho_prime_buffer + 96);
	fastmemset(rhoprime, 0, 64);
	storm_next_block(&ctx, rhoprime);
	storm_next_block(&ctx, rhoprime + 32);

	/* Expand matrix and transform vectors */
	polyvec_matrix_expand(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);

rej:
	/* Sample intermediate vector y */
	poly_uniform_gamma1_4x(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
			       rhoprime, nonce, nonce + 1, nonce + 2,
			       nonce + 3);
	nonce += 4;

	/* Matrix-vector product */
	tmpv.y = z;
	polyvecl_ntt(&tmpv.y);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &tmpv.y);
	polyveck_invntt_tomont(&w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq(&w1);
	polyveck_decompose(&w1, &tmpv.w0, &w1);
	polyveck_pack_w1(sig, &w1);

	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((
	    aligned(32))) u8 sig_buffer[K * POLYW1_PACKEDBYTES + CRHBYTES];
	fastmemcpy(sig_buffer, mu, CRHBYTES);
	fastmemcpy(sig_buffer + CRHBYTES, sig, K * POLYW1_PACKEDBYTES);
	for (u32 i = 0; i < sizeof(sig_buffer); i += 32)
		storm_next_block(&ctx, sig_buffer + i);
	fastmemset(sig, 0, 32);
	storm_next_block(&ctx, sig);

	poly_challenge(&c, sig);
	poly_ntt(&c);

	/* Compute z, reject if it reveals secret */
	for (i = 0; i < L; i++) {
		poly_pointwise_montgomery(&tmp, &c, &s1.vec[i]);
		poly_invntt_tomont(&tmp);
		poly_add(&z.vec[i], &z.vec[i], &tmp);
		poly_reduce(&z.vec[i]);
		if (poly_chknorm(&z.vec[i], GAMMA1 - BETA)) goto rej;
	}

	/* Zero hint vector in signature */
	pos = 0;
	memset(hint, 0, OMEGA);

	for (i = 0; i < K; i++) {
		/* Check that subtracting cs2 does not change high bits of w and
		 * low bits do not reveal secret information */
		poly_pointwise_montgomery(&tmp, &c, &s2.vec[i]);
		poly_invntt_tomont(&tmp);
		poly_sub(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
		poly_reduce(&tmpv.w0.vec[i]);
		if (poly_chknorm(&tmpv.w0.vec[i], GAMMA2 - BETA)) goto rej;

		/* Compute hints */
		poly_pointwise_montgomery(&tmp, &c, &t0.vec[i]);
		poly_invntt_tomont(&tmp);
		poly_reduce(&tmp);
		if (poly_chknorm(&tmp, GAMMA2)) goto rej;

		poly_add(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
		n = poly_make_hint(hintbuf, &tmpv.w0.vec[i], &w1.vec[i]);
		if (pos + n > OMEGA) goto rej;

		/* Store hints in signature */
		memcpy(&hint[pos], hintbuf, n);
		hint[OMEGA + i] = pos = pos + n;
	}

	/* Pack z into signature */
	for (i = 0; i < L; i++)
		polyz_pack(sig + CTILDEBYTES + i * POLYZ_PACKEDBYTES,
			   &z.vec[i]);

	*siglen = CRYPTO_BYTES;
	return 0;
}

int crypto_sign_signature(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
			  const u8 *ctx, u64 ctxlen, const u8 *sk, Rng *rng) {
	u8 pre[257];
	__attribute__((aligned(32))) u8 rnd[RNDBYTES] = {0};

	if (ctxlen > 255) return -1;

	/* Prepare pre = (0, ctxlen, ctx) */
	pre[0] = 0;
	pre[1] = ctxlen;
	memcpy(&pre[2], ctx, ctxlen);
	rng_gen(rng, rnd, RNDBYTES);

	crypto_sign_signature_internal(sig, siglen, m, mlen, pre, 2 + ctxlen,
				       rnd, sk);
	return 0;
}

int crypto_sign_verify_internal(const u8 *sig, u64 siglen, const u8 *m,
				u64 mlen, const u8 *pre, u64 prelen,
				const u8 *pk) {
	StormContext ctx;
	unsigned int i, j, pos = 0;
	/* polyw1_pack writes additional 14 bytes */
	ALIGNED_UINT8(K * POLYW1_PACKEDBYTES + 14) buf;
	__attribute__((aligned(32))) u8 mu[CRHBYTES] = {0};
	const u8 *hint = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
	polyvecl rowbuf[2];
	polyvecl *row = rowbuf;
	polyvecl z;
	poly c, w1, h;

	if (siglen != CRYPTO_BYTES) return -1;

	/* Compute CRH(H(rho, t1), pre, msg) */
	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((aligned(32))) u8 pk_copy[CRYPTO_PUBLICKEYBYTES];
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);
	for (u32 i = 0; i < CRYPTO_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((aligned(32))) u8 buffer[TRBYTES + 32];
	fastmemcpy(buffer, mu, TRBYTES);
	fastmemcpy(buffer + TRBYTES, m, 32);
	storm_next_block(&ctx, buffer);
	storm_next_block(&ctx, buffer + 32);
	storm_next_block(&ctx, buffer + 64);
	fastmemset(mu, 0, 64);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	/* Expand challenge */
	poly_challenge(&c, sig);
	poly_ntt(&c);

	/* Unpack z; shortness follows from unpacking */
	for (i = 0; i < L; i++) {
		polyz_unpack(&z.vec[i],
			     sig + CTILDEBYTES + i * POLYZ_PACKEDBYTES);
		poly_ntt(&z.vec[i]);
	}

	for (i = 0; i < K; i++) {
		/* Expand matrix row */
		polyvec_matrix_expand_row(&row, rowbuf, pk, i);

		/* Compute i-th row of Az - c2^Dt1 */
		polyvecl_pointwise_acc_montgomery(&w1, row, &z);

		polyt1_unpack(&h, pk + SEEDBYTES + i * POLYT1_PACKEDBYTES);
		poly_shiftl(&h);
		poly_ntt(&h);
		poly_pointwise_montgomery(&h, &c, &h);

		poly_sub(&w1, &w1, &h);
		poly_reduce(&w1);
		poly_invntt_tomont(&w1);

		/* Get hint polynomial and reconstruct w1 */
		memset(h.vec, 0, sizeof(poly));
		if (hint[OMEGA + i] < pos || hint[OMEGA + i] > OMEGA) return -1;

		for (j = pos; j < hint[OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > pos && hint[j] <= hint[j - 1]) return -1;
			h.coeffs[hint[j]] = 1;
		}
		pos = hint[OMEGA + i];

		poly_caddq(&w1);
		poly_use_hint(&w1, &w1, &h);
		polyw1_pack(buf.coeffs + i * POLYW1_PACKEDBYTES, &w1);
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = pos; j < OMEGA; ++j)
		if (hint[j]) return -1;

	/* Call random oracle and verify challenge */
	storm_init(&ctx, HASH_DOMAIN);
	__attribute__((
	    aligned(32))) u8 sig_buffer[K * POLYW1_PACKEDBYTES + CRHBYTES];
	fastmemcpy(sig_buffer, mu, CRHBYTES);
	fastmemcpy(sig_buffer + CRHBYTES, buf.coeffs, K * POLYW1_PACKEDBYTES);
	for (u32 i = 0; i < sizeof(sig_buffer); i += 32)
		storm_next_block(&ctx, sig_buffer + i);
	fastmemset(buf.coeffs, 0, 32);
	storm_next_block(&ctx, buf.coeffs);

	for (i = 0; i < CTILDEBYTES; ++i)
		if (buf.coeffs[i] != sig[i]) {
			return -1;
		}

	return 0;
}

int crypto_sign_verify(const u8 *sig, u64 siglen, const u8 *m, u64 mlen,
		       const u8 *ctx, u64 ctxlen, const u8 *pk) {
	u8 pre[257];

	if (ctxlen > 255) return -1;

	pre[0] = 0;
	pre[1] = ctxlen;
	memcpy(&pre[2], ctx, ctxlen);
	return crypto_sign_verify_internal(sig, siglen, m, mlen, pre,
					   2 + ctxlen, pk);
}

#endif /* USE_AVX2 */
