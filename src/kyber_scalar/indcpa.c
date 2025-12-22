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

#ifndef __AVX2__
#include <kyber_common/params.h>
#include <kyber_scalar/indcpa.h>
#include <kyber_scalar/ntt.h>
#include <kyber_scalar/poly.h>
#include <kyber_scalar/polyvec.h>
#include <libfam/kem_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>

/*************************************************
 * Name:        pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   u8 *r: pointer to the output serialized public key
 *              polyvec *pk: pointer to the input public-key polyvec
 *              const u8 *seed: pointer to the input public seed
 **************************************************/
static void pack_pk(u8 r[KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk,
		    const u8 seed[KYBER_SYMBYTES]) {
	polyvec_tobytes(r, pk);
	fastmemcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of pack_pk
 *
 * Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
 *              - u8 *seed: pointer to output seed to generate matrix A
 *              - const u8 *packedpk: pointer to input serialized public
 *key
 **************************************************/
static void unpack_pk(polyvec *pk, u8 seed[KYBER_SYMBYTES],
		      const u8 packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
	polyvec_frombytes(pk, packedpk);
	fastmemcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - u8 *r: pointer to output serialized secret key
 *              - polyvec *sk: pointer to input vector of polynomials (secret
 *key)
 **************************************************/
static void pack_sk(u8 r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
	polyvec_tobytes(r, sk);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: De-serialize the secret key; inverse of pack_sk
 *
 * Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret
 *key)
 *              - const u8 *packedsk: pointer to input serialized secret
 *key
 **************************************************/
static void unpack_sk(polyvec *sk,
		      const u8 packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
	polyvec_frombytes(sk, packedsk);
}

/*************************************************
 * Name:        pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v
 *
 * Arguments:   u8 *r: pointer to the output serialized ciphertext
 *              poly *pk: pointer to the input vector of polynomials b
 *              poly *v: pointer to the input polynomial v
 **************************************************/
static void pack_ciphertext(u8 r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
	polyvec_compress(r, b);
	poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
 * Name:        unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of pack_ciphertext
 *
 * Arguments:   - polyvec *b: pointer to the output vector of polynomials b
 *              - poly *v: pointer to the output polynomial v
 *              - const u8 *c: pointer to the input serialized ciphertext
 **************************************************/
static void unpack_ciphertext(polyvec *b, poly *v,
			      const u8 c[KYBER_INDCPA_BYTES]) {
	polyvec_decompress(b, c);
	poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - i16 *r: pointer to output buffer
 *              - unsigned int len: requested number of 16-bit integers (uniform
 *mod q)
 *              - const u8 *buf: pointer to input buffer (assumed to be
 *uniformly random bytes)
 *              - unsigned int buflen: length of input buffer in bytes
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
static unsigned int rej_uniform(i16 *r, unsigned int len, const u8 *buf,
				unsigned int buflen) {
	unsigned int ctr, pos;
	u16 val0, val1;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
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

/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - polyvec *a: pointer to ouptput matrix A
 *              - const u8 *seed: pointer to input seed
 *              - int transposed: boolean deciding whether A or A^T is generated
 **************************************************/
#if (XOF_BLOCKBYTES % 3)
#error \
    "Implementation of gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3"
#endif

#define GEN_MATRIX_NBLOCKS                                           \
	((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / \
	 XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const u8 seed[KYBER_SYMBYTES], int transposed) {
	u32 ctr, i, j;
	__attribute__((aligned(32))) u8 buf[32] = {0};
	StormContext state;

	fastmemcpy(buf, seed, 32);

	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			fastmemcpy(buf, seed, 32);
			if (transposed)
				buf[0] = i, buf[1] = j;
			else
				buf[1] = i, buf[0] = j;

			storm_init(&state, buf);
			storm_next_block(&state, buf);
			ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, 32);

			while (ctr < KYBER_N) {
				storm_next_block(&state, buf);
				ctr += rej_uniform(a[i].vec[j].coeffs + ctr,
						   KYBER_N - ctr, buf, 32);
			}
		}
	}
}

/*************************************************
 * Name:        indcpa_keypair_derand
 *
 * Description: Generates public and private key for the CPA-secure
 *              public-key encryption scheme underlying Kyber
 *
 * Arguments:   - u8 *pk: pointer to output public key
 *                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
 *              - u8 *sk: pointer to output private key
 *                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
 *              - const u8 *coins: pointer to input randomness
 *                             (of length KYBER_SYMBYTES bytes)
 **************************************************/
void indcpa_keypair_derand(u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
			   u8 sk[KYBER_INDCPA_SECRETKEYBYTES],
			   const u8 coins[KYBER_SYMBYTES]) {
	unsigned int i;
	StormContext ctx;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES] = {0};
	const u8 *publicseed = buf;
	const u8 *noiseseed = buf + KYBER_SYMBYTES;
	u8 nonce = 0;
	polyvec a[KYBER_K], e, pkpv, skpv;

	fastmemcpy(buf, coins, KYBER_SYMBYTES);
	buf[KYBER_SYMBYTES] = KYBER_K;

	storm_init(&ctx, HASH_DOMAIN);
	storm_next_block(&ctx, buf);
	storm_next_block(&ctx, buf + 32);

	gen_a(a, publicseed);

	for (i = 0; i < KYBER_K; i++)
		poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
	for (i = 0; i < KYBER_K; i++)
		poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

	polyvec_ntt(&skpv);
	polyvec_ntt(&e);

	// matrix-vector multiplication
	for (i = 0; i < KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
		poly_tomont(&pkpv.vec[i]);
	}

	polyvec_add(&pkpv, &pkpv, &e);
	polyvec_reduce(&pkpv);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - u8 *c: pointer to output ciphertext
 *                            (of length KYBER_INDCPA_BYTES bytes)
 *              - const u8 *m: pointer to input message
 *                                  (of length KYBER_INDCPA_MSGBYTES bytes)
 *              - const u8 *pk: pointer to input public key
 *                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
 *              - const u8 *coins: pointer to input random coins used as
 *seed (of length KYBER_SYMBYTES) to deterministically generate all randomness
 **************************************************/
void indcpa_enc(u8 c[KYBER_INDCPA_BYTES], const u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
		const u8 coins[KYBER_SYMBYTES]) {
	unsigned int i;
	u8 seed[KYBER_SYMBYTES];
	u8 nonce = 0;
	polyvec sp, pkpv, ep, at[KYBER_K], b;
	poly v, k, epp;

	unpack_pk(&pkpv, seed, pk);
	poly_frommsg(&k, m);
	gen_at(at, seed);

	for (i = 0; i < KYBER_K; i++)
		poly_getnoise_eta1(sp.vec + i, coins, nonce++);
	for (i = 0; i < KYBER_K; i++)
		poly_getnoise_eta2(ep.vec + i, coins, nonce++);
	poly_getnoise_eta2(&epp, coins, nonce++);

	polyvec_ntt(&sp);

	// matrix-vector multiplication
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

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - u8 *m: pointer to output decrypted message
 *                            (of length KYBER_INDCPA_MSGBYTES)
 *              - const u8 *c: pointer to input ciphertext
 *                                  (of length KYBER_INDCPA_BYTES)
 *              - const u8 *sk: pointer to input secret key
 *                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
 **************************************************/
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

#endif /* __AVX2__ */
