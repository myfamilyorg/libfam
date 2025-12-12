#include <dilithium/fips202.h>
#include <dilithium/packing.h>
#include <dilithium/params.h>
#include <dilithium/poly.h>
#include <dilithium/polyvec.h>
#include <dilithium/randombytes.h>
#include <dilithium/sign.h>
#include <dilithium/symmetric.h>
#include <libfam/format.h>
#include <libfam/string.h>
#include <libfam/sysext.h>

void dilithium_keyfrom(u8 *sk, u8 *pk, u8 seed[32]) {
	u8 seedbuf[2 * SEEDBYTES + CRHBYTES] = {0};
	u8 tr[TRBYTES];
	const u8 *rho, *rhoprime, *key;
	polyvecl mat[K];
	polyvecl s1, s1hat;
	polyveck s2, t1, t0;

	fastmemcpy(seedbuf, seed, 32);

	seedbuf[SEEDBYTES + 0] = K;
	seedbuf[SEEDBYTES + 1] = L;
	shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
	rho = seedbuf;
	rhoprime = rho + SEEDBYTES;
	key = rhoprime + CRHBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvecl_uniform_eta(&s1, rhoprime, 0);
	polyveck_uniform_eta(&s2, rhoprime, L);

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);
	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyveck_reduce(&t1);
	polyveck_invntt_tomont(&t1);

	/* Add error vector s2 */
	polyveck_add(&t1, &t1, &s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);

	/* Compute H(rho, t1) and write secret key */
	shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
	pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
}

void dilithium_keypair(u8 *pk, u8 *sk) {
	u8 seedbuf[2 * SEEDBYTES + CRHBYTES] = {0};
	u8 tr[TRBYTES];
	const u8 *rho, *rhoprime, *key;
	polyvecl mat[K];
	polyvecl s1, s1hat;
	polyveck s2, t1, t0;

	/* Get randomness for rho, rhoprime and key */
	random32(seedbuf);

	seedbuf[SEEDBYTES + 0] = K;
	seedbuf[SEEDBYTES + 1] = L;
	shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
	rho = seedbuf;
	rhoprime = rho + SEEDBYTES;
	key = rhoprime + CRHBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvecl_uniform_eta(&s1, rhoprime, 0);
	polyveck_uniform_eta(&s2, rhoprime, L);

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);
	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyveck_reduce(&t1);
	polyveck_invntt_tomont(&t1);

	/* Add error vector s2 */
	polyveck_add(&t1, &t1, &s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);

	/* Compute H(rho, t1) and write secret key */
	shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
	pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
}

/*************************************************
 * Name:        crypto_sign_signature_internal
 *
 * Description: Computes signature. Internal API.
 *
 * Arguments:   - u8 *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - u64 *siglen: pointer to output length of signature
 *              - u8 *m:     pointer to message to be signed
 *              - u64 mlen:    length of message
 *              - u8 *pre:   pointer to prefix string
 *              - u64 prelen:  length of prefix string
 *              - u8 *rnd:   pointer to random seed
 *              - u8 *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
void crypto_sign_signature_internal(u8 *sig, u64 *siglen, const u8 *m,
				    u64 mlen, const u8 *pre, u64 prelen,
				    const u8 rnd[RNDBYTES], const u8 *sk) {
	u32 n;
	u8 seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
	u8 *rho, *tr, *key, *mu, *rhoprime;
	u16 nonce = 0;
	polyvecl mat[K], s1, y, z;
	polyveck t0, s2, w1, w0, h;
	poly cp;
	keccak_state state;

	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + TRBYTES;
	mu = key + SEEDBYTES;
	rhoprime = mu + CRHBYTES;
	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

	/* Compute mu = CRH(tr, pre, msg) */
	shake256_init(&state);
	shake256_absorb(&state, tr, TRBYTES);
	shake256_absorb(&state, pre, prelen);
	shake256_absorb(&state, m, mlen);
	shake256_finalize(&state);
	shake256_squeeze(mu, CRHBYTES, &state);

	/* Compute rhoprime = CRH(key, rnd, mu) */
	shake256_init(&state);
	shake256_absorb(&state, key, SEEDBYTES);
	shake256_absorb(&state, rnd, RNDBYTES);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_finalize(&state);
	shake256_squeeze(rhoprime, CRHBYTES, &state);

	/* Expand matrix and transform vectors */
	polyvec_matrix_expand(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

	/* Matrix-vector multiplication */
	z = y;
	polyvecl_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq(&w1);
	polyveck_decompose(&w1, &w0, &w1);
	polyveck_pack_w1(sig, &w1);

	shake256_init(&state);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
	shake256_finalize(&state);
	shake256_squeeze(sig, CTILDEBYTES, &state);
	poly_challenge(&cp, sig);
	poly_ntt(&cp);

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
	polyvecl_invntt_tomont(&z);
	polyvecl_add(&z, &z, &y);
	polyvecl_reduce(&z);
	if (polyvecl_chknorm(&z, GAMMA1 - BETA)) goto rej;

	/* Check that subtracting cs2 does not change high bits of w and low
	 * bits do not reveal secret information */
	polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
	polyveck_invntt_tomont(&h);
	polyveck_sub(&w0, &w0, &h);
	polyveck_reduce(&w0);
	if (polyveck_chknorm(&w0, GAMMA2 - BETA)) goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
	polyveck_invntt_tomont(&h);
	polyveck_reduce(&h);
	if (polyveck_chknorm(&h, GAMMA2)) goto rej;

	polyveck_add(&w0, &w0, &h);
	n = polyveck_make_hint(&h, &w0, &w1);
	if (n > OMEGA) goto rej;

	/* Write signature */
	pack_sig(sig, sig, &z, &h);
	*siglen = CRYPTO_BYTES;
}

/*************************************************
 * Name:        crypto_sign_signature
 *
 * Description: Computes signature.
 *
 * Arguments:   - u8 *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - u64 *siglen: pointer to output length of signature
 *              - u8 *m:     pointer to message to be signed
 *              - u64 mlen:    length of message
 *              - u8 *ctx:   pointer to contex string
 *              - u64 ctxlen:  length of contex string
 *              - u8 *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success) or -1 (context string too long)
 **************************************************/
int crypto_sign_signature(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
			  const u8 *ctx, u64 ctxlen, const u8 *sk) {
	u64 i;
	u8 pre[257];
	u8 rnd[RNDBYTES];

	if (ctxlen > 255) return -1;

	/* Prepare pre = (0, ctxlen, ctx) */
	pre[0] = 0;
	pre[1] = ctxlen;
	for (i = 0; i < ctxlen; i++) pre[2 + i] = ctx[i];

#ifdef DILITHIUM_RANDOMIZED_SIGNING
	random32(rnd);
#else
	for (i = 0; i < RNDBYTES; i++) rnd[i] = 0;
#endif

	crypto_sign_signature_internal(sig, siglen, m, mlen, pre, 2 + ctxlen,
				       rnd, sk);
	return 0;
}

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Compute signed message.
 *
 * Arguments:   - u8 *sm: pointer to output signed message (allocated
 *                             array with CRYPTO_BYTES + mlen bytes),
 *                             can be equal to m
 *              - u64 *smlen: pointer to output length of signed
 *                               message
 *              - const u8 *m: pointer to message to be signed
 *              - u64 mlen: length of message
 *              - const u8 *ctx: pointer to context string
 *              - u64 ctxlen: length of context string
 *              - const u8 *sk: pointer to bit-packed secret key
 *
 * Returns 0 (success) or -1 (context string too long)
 **************************************************/
int dilithium_sign(u8 *sm, u64 *smlen, const u8 *m, u64 mlen,
		   const u8 *ctx, u64 ctxlen, const u8 *sk) {
	int ret;
	u64 i;

	for (i = 0; i < mlen; ++i)
		sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
	ret = crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, ctx,
				    ctxlen, sk);
	*smlen += mlen;
	return ret;
}

/*************************************************
 * Name:        crypto_sign_verify_internal
 *
 * Description: Verifies signature. Internal API.
 *
 * Arguments:   - u8 *m: pointer to input signature
 *              - u64 siglen: length of signature
 *              - const u8 *m: pointer to message
 *              - u64 mlen: length of message
 *              - const u8 *pre: pointer to prefix string
 *              - u64 prelen: length of prefix string
 *              - const u8 *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_verify_internal(const u8 *sig, u64 siglen, const u8 *m,
				u64 mlen, const u8 *pre, u64 prelen,
				const u8 *pk) {
	u32 i;
	u8 buf[K * POLYW1_PACKEDBYTES];
	u8 rho[SEEDBYTES];
	u8 mu[CRHBYTES];
	u8 c[CTILDEBYTES];
	u8 c2[CTILDEBYTES];
	poly cp;
	polyvecl mat[K], z;
	polyveck t1, w1, h;
	keccak_state state;

	if (siglen != CRYPTO_BYTES) {
		return -1;
	}

	unpack_pk(rho, &t1, pk);
	if (unpack_sig(c, &z, &h, sig)) {
		return -1;
	}
	if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {
		return -1;
	}

	/* Compute CRH(H(rho, t1), pre, msg) */
	shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
	shake256_init(&state);
	shake256_absorb(&state, mu, TRBYTES);
	shake256_absorb(&state, pre, prelen);
	shake256_absorb(&state, m, mlen);
	shake256_finalize(&state);
	shake256_squeeze(mu, CRHBYTES, &state);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&cp, c);
	polyvec_matrix_expand(mat, rho);

	polyvecl_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

	poly_ntt(&cp);
	polyveck_shiftl(&t1);
	polyveck_ntt(&t1);
	polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

	polyveck_sub(&w1, &w1, &t1);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Reconstruct w1 */
	polyveck_caddq(&w1);
	polyveck_use_hint(&w1, &w1, &h);
	polyveck_pack_w1(buf, &w1);

	/* Call random oracle and verify challenge */
	shake256_init(&state);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
	shake256_finalize(&state);
	shake256_squeeze(c2, CTILDEBYTES, &state);
	for (i = 0; i < CTILDEBYTES; ++i)
		if (c[i] != c2[i]) {
			return -1;
		}

	return 0;
}

/*************************************************
 * Name:        crypto_sign_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:   - u8 *m: pointer to input signature
 *              - u64 siglen: length of signature
 *              - const u8 *m: pointer to message
 *              - u64 mlen: length of message
 *              - const u8 *ctx: pointer to context string
 *              - u64 ctxlen: length of context string
 *              - const u8 *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_verify(const u8 *sig, u64 siglen, const u8 *m, u64 mlen,
		       const u8 *ctx, u64 ctxlen, const u8 *pk) {
	u64 i;
	u8 pre[257];

	if (ctxlen > 255) return -1;

	pre[0] = 0;
	pre[1] = ctxlen;
	for (i = 0; i < ctxlen; i++) pre[2 + i] = ctx[i];

	return crypto_sign_verify_internal(sig, siglen, m, mlen, pre,
					   2 + ctxlen, pk);
}

/*************************************************
 * Name:        crypto_verify
 *
 * Description: Verify signed message.
 *
 * Arguments:   - u8 *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - u64 *mlen: pointer to output length of message
 *              - const u8 *sm: pointer to signed message
 *              - u64 smlen: length of signed message
 *              - const u8 *ctx: pointer to context tring
 *              - u64 ctxlen: length of context string
 *              - const u8 *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int dilithium_verify(u8 *m, u64 *mlen, const u8 *sm, u64 smlen,
		     const u8 *ctx, u64 ctxlen, const u8 *pk) {
	u64 i;

	if (smlen < CRYPTO_BYTES) goto badsig;

	*mlen = smlen - CRYPTO_BYTES;
	if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx,
			       ctxlen, pk))
		goto badsig;
	else {
		/* All good, copy msg, return 0 */
		for (i = 0; i < *mlen; ++i) m[i] = sm[CRYPTO_BYTES + i];
		return 0;
	}

badsig:
	/* Signature verification failed */
	*mlen = 0;
	for (i = 0; i < smlen; ++i) m[i] = 0;

	return -1;
}
