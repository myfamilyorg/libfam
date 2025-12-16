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

#include <libfam/dilithium_const.h>
#include <libfam/dilithium_impl.h>
#include <libfam/format.h>
#include <libfam/sign.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/sysext.h>

__attribute__((aligned(32))) static const u8 DILITHIUM_KEYGEN_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x35, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x95, 0x00, 0x00, 0x00, 0x01};

__attribute__((aligned(32))) static const u8 DILITHIUM_TR_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x16, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x36, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x96, 0x00, 0x00, 0x00, 0x02};

__attribute__((aligned(32))) static const u8 DILITHIUM_RHO_PRIME_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x17, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x37, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x97, 0x00, 0x00, 0x00, 0x03};

__attribute__((aligned(32))) static const u8 DILITHIUM_MU_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x17, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x37, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x97, 0x00, 0x00, 0x00, 0x04};

__attribute__((aligned(32))) static const u8 DILITHIUM_CTILDE_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x17, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x37, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x97, 0x00, 0x00, 0x00, 0x05};

void keyfrom(SecretKey *sk_in, PublicKey *pk_in, u8 seed[32]) {
	u8 *pk = (void *)pk_in;
	u8 *sk = (void *)sk_in;
	__attribute__((aligned(32))) u8 seedbuf[2 * SEEDBYTES + CRHBYTES] = {0};
	u8 tr[TRBYTES] = {0};
	const u8 *rho, *rhoprime, *key;
	polyvec mat[K];
	polyvec s1, s1hat;
	polyvec s2, t1, t0;
	StormContext ctx;
	__attribute__((aligned(32))) u8 pk_copy[CRYPTO_PUBLICKEYBYTES] = {0};

	fastmemcpy(seedbuf, seed, 32);

	seedbuf[SEEDBYTES + 0] = K;
	seedbuf[SEEDBYTES + 1] = K;

	storm_init(&ctx, DILITHIUM_KEYGEN_DOMAIN);
	storm_next_block(&ctx, seedbuf);
	storm_next_block(&ctx, seedbuf + 32);
	storm_next_block(&ctx, seedbuf + 64);
	storm_next_block(&ctx, seedbuf + 96);

	rho = seedbuf;
	rhoprime = rho + SEEDBYTES;
	key = rhoprime + CRHBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvec_uniform_eta(&s1, rhoprime, 0);
	polyvec_uniform_eta(&s2, rhoprime, K);

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

	storm_init(&ctx, DILITHIUM_TR_DOMAIN);
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);

	for (u32 i = 0; i < 41; i++) storm_next_block(&ctx, pk_copy + i * 32);
	storm_next_block(&ctx, tr);
	storm_next_block(&ctx, tr + 32);

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
void crypto_sign_signature_internal(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
				    const u8 *pre, u64 prelen,
				    const u8 rnd[RNDBYTES], const u8 *sk) {
	u32 n;
	__attribute__((aligned(
	    32))) u8 seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES] = {0};
	u8 *rho, *tr, *key, *mu, *rhoprime;
	u64 nonce = 0;
	polyvec mat[K], s1, y, z;
	polyvec t0, s2, w1, w0, h;
	poly cp;
	StormContext ctx;

	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + TRBYTES;
	mu = key + SEEDBYTES;
	rhoprime = mu + CRHBYTES;
	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

	storm_init(&ctx, DILITHIUM_MU_DOMAIN);
	__attribute__((aligned(32))) u8 mu_copy[TRBYTES + MLEN] = {0};
	fastmemcpy(mu_copy, tr, TRBYTES);
	fastmemcpy(mu_copy + TRBYTES, m, MLEN);
	for (u32 i = 0; i < TRBYTES + MLEN; i += 32)
		storm_next_block(&ctx, mu_copy + i);
	fastmemset(mu, 0, CRHBYTES);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	storm_init(&ctx, DILITHIUM_RHO_PRIME_DOMAIN);
	__attribute__((aligned(
	    32))) u8 rho_prime_buf[SEEDBYTES + SEEDBYTES + CRHBYTES] = {0};

	fastmemcpy(rho_prime_buf, key, SEEDBYTES);
	fastmemcpy(rho_prime_buf + SEEDBYTES, rnd, RNDBYTES);
	fastmemcpy(rho_prime_buf + SEEDBYTES + RNDBYTES, mu, CRHBYTES);
	storm_next_block(&ctx, rho_prime_buf);
	storm_next_block(&ctx, rho_prime_buf + 32);
	storm_next_block(&ctx, rho_prime_buf + 64);
	storm_next_block(&ctx, rho_prime_buf + 96);
	storm_next_block(&ctx, rhoprime);
	storm_next_block(&ctx, rhoprime + 32);

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

	storm_init(&ctx, DILITHIUM_CTILDE_DOMAIN);
	__attribute__((
	    aligned(32))) u8 ctilde_buffer[CRHBYTES + K * POLYW1_PACKEDBYTES];
	fastmemcpy(ctilde_buffer, mu, CRHBYTES);
	fastmemcpy(ctilde_buffer + CRHBYTES, sig, K * POLYW1_PACKEDBYTES);
	for (u32 i = 0; i < CRHBYTES + K * POLYW1_PACKEDBYTES; i += 32)
		storm_next_block(&ctx, ctilde_buffer + i);
	fastmemset(sig, 0, 64);
	storm_next_block(&ctx, sig);

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
	fastmemset(rnd, 0, RNDBYTES);
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
void sign(Signature *sm_in, const Message *msg, const SecretKey *sk_in) {
	u8 *sm = (void *)sm_in;
	const u8 *sk = (void *)sk_in;
	const u8 *m = (void *)msg;
	u64 i, smlen;

	for (i = 0; i < MLEN; ++i) sm[CRYPTO_BYTES + i] = m[i];
	crypto_sign_signature(sm, &smlen, sm + CRYPTO_BYTES, MLEN, NULL, 0, sk);
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
	__attribute__((aligned(32))) u8 rho[SEEDBYTES];
	u8 mu[CRHBYTES] = {0};
	u8 c[CTILDEBYTES];
	__attribute__((aligned(32))) u8 c2[CTILDEBYTES] = {0};
	__attribute__((aligned(32))) u8 pk_copy[CRYPTO_PUBLICKEYBYTES] = {0};
	poly cp;
	polyvec mat[K], z;
	polyvec t1, w1, h;
	StormContext ctx;

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

	storm_init(&ctx, DILITHIUM_TR_DOMAIN);
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);
	for (u32 i = 0; i < 41; i++) storm_next_block(&ctx, pk_copy + i * 32);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	storm_init(&ctx, DILITHIUM_MU_DOMAIN);
	__attribute__((aligned(32))) u8 mu_copy[TRBYTES + MLEN] = {0};
	fastmemcpy(mu_copy, mu, TRBYTES);
	fastmemcpy(mu_copy + TRBYTES, m, mlen);
	for (u32 i = 0; i < TRBYTES + MLEN; i += 32)
		storm_next_block(&ctx, mu_copy + i);
	fastmemset(mu, 0, CRHBYTES);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

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

	storm_init(&ctx, DILITHIUM_CTILDE_DOMAIN);
	__attribute__((
	    aligned(32))) u8 ctilde_buffer[CRHBYTES + K * POLYW1_PACKEDBYTES];
	fastmemcpy(ctilde_buffer, mu, CRHBYTES);
	fastmemcpy(ctilde_buffer + CRHBYTES, buf, K * POLYW1_PACKEDBYTES);
	for (u32 i = 0; i < CRHBYTES + K * POLYW1_PACKEDBYTES; i += 32)
		storm_next_block(&ctx, ctilde_buffer + i);
	storm_next_block(&ctx, c2);

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
i32 verify(const Signature *sm_in, const PublicKey *pk_in) {
	const u8 *sm = (void *)sm_in;
	const u8 *pk = (void *)pk_in;
	i32 res = crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, MLEN,
				     NULL, 0, pk);
	return res == 0 ? 0 : -1;
}
