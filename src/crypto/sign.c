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
#include <libfam/rng.h>
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

	polyvec_matrix_expand(mat, rho);

	polyvec_uniform_eta(&s1, rhoprime, 0);
	polyvec_uniform_eta(&s2, rhoprime, K);

	s1hat = s1;
	polyvec_ntt(&s1hat);
	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyvec_reduce(&t1);
	polyvec_invntt_tomont(&t1);

	polyvec_add(&t1, &t1, &s2);

	polyvec_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);

	storm_init(&ctx, DILITHIUM_TR_DOMAIN);
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);

	for (u32 i = 0; i < 41; i++) storm_next_block(&ctx, pk_copy + i * 32);
	storm_next_block(&ctx, tr);
	storm_next_block(&ctx, tr + 32);

	pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
}

void signature_internal(u8 *sig, const u8 *m, const u8 rnd[RNDBYTES],
			const u8 *sk) {
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

	polyvec_matrix_expand(mat, rho);
	polyvec_ntt(&s1);
	polyvec_ntt(&s2);
	polyvec_ntt(&t0);

rej:
	polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

	z = y;
	polyvec_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
	polyvec_reduce(&w1);
	polyvec_invntt_tomont(&w1);

	polyvec_caddq(&w1);
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
	ntt(cp.coeffs);

	polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
	polyvec_invntt_tomont(&z);
	polyvec_add(&z, &z, &y);
	polyvec_reduce(&z);
	if (polyvecl_chknorm(&z, GAMMA1 - BETA)) goto rej;

	polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
	polyvec_invntt_tomont(&h);
	polyvec_sub(&w0, &w0, &h);
	polyvec_reduce(&w0);
	if (polyveck_chknorm(&w0, GAMMA2 - BETA)) goto rej;

	polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
	polyvec_invntt_tomont(&h);
	polyvec_reduce(&h);
	if (polyveck_chknorm(&h, GAMMA2)) goto rej;

	polyvec_add(&w0, &w0, &h);
	n = polyveck_make_hint(&h, &w0, &w1);
	if (n > OMEGA) goto rej;

	pack_sig(sig, sig, &z, &h);
}

void sign(Signature *sm_in, const Message *msg, const SecretKey *sk_in) {
	u8 *sm = (void *)sm_in;
	const u8 *sk = (void *)sk_in;
	const u8 *m = (void *)msg;
	u8 rnd[RNDBYTES];
	Rng rng;

	rng_init(&rng, NULL);
	rng_gen(&rng, rnd, RNDBYTES);

	fastmemcpy(sm + CRYPTO_BYTES, m, MLEN);
	signature_internal(sm, sm + CRYPTO_BYTES, rnd, sk);
}

i32 crypto_sign_verify_internal(const u8 *sig, const u8 *pk) {
	const u8 *m = sig + CRYPTO_BYTES;
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

	unpack_pk(rho, &t1, pk);
	if (unpack_sig(c, &z, &h, sig)) return -1;

	if (polyvecl_chknorm(&z, GAMMA1 - BETA)) return -1;

	storm_init(&ctx, DILITHIUM_TR_DOMAIN);
	fastmemcpy(pk_copy, pk, CRYPTO_PUBLICKEYBYTES);
	for (u32 i = 0; i < 41; i++) storm_next_block(&ctx, pk_copy + i * 32);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	storm_init(&ctx, DILITHIUM_MU_DOMAIN);
	__attribute__((aligned(32))) u8 mu_copy[TRBYTES + MLEN] = {0};
	fastmemcpy(mu_copy, mu, TRBYTES);
	fastmemcpy(mu_copy + TRBYTES, m, MLEN);
	for (u32 i = 0; i < TRBYTES + MLEN; i += 32)
		storm_next_block(&ctx, mu_copy + i);
	fastmemset(mu, 0, CRHBYTES);
	storm_next_block(&ctx, mu);
	storm_next_block(&ctx, mu + 32);

	poly_challenge(&cp, c);
	polyvec_matrix_expand(mat, rho);

	polyvec_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

	ntt(cp.coeffs);
	polyvec_shiftl(&t1);
	polyvec_ntt(&t1);
	polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

	polyvec_sub(&w1, &w1, &t1);
	polyvec_reduce(&w1);
	polyvec_invntt_tomont(&w1);

	polyvec_caddq(&w1);
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

	return fastmemcmp(c, c2, CTILDEBYTES) == 0 ? 0 : -1;
}

i32 verify(const Signature *sm_in, const PublicKey *pk_in) {
	const u8 *sm = (void *)sm_in;
	const u8 *pk = (void *)pk_in;
	return crypto_sign_verify_internal(sm, pk);
}
