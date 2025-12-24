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
#include <kyber_scalar/indcpa.h>
#include <kyber_scalar/kem.h>
#include <kyber_scalar/verify.h>
#include <libfam/kem_impl.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>

/*************************************************
 * Name:        crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - u8 *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - u8 *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *              - u8 *coins: pointer to input randomness
 *                (an already allocated array filled with 2*KYBER_SYMBYTES
 *random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair_derand(u8 *pk, u8 *sk, const u8 *coins) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES] = {0};

	indcpa_keypair_derand(pk, sk, coins);
	fastmemcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);

	storm_init(&ctx, PUBKEY_HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	fastmemset(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, 0, 32);
	storm_next_block(&ctx, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES);

	fastmemcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
		   coins + KYBER_SYMBYTES, KYBER_SYMBYTES);

	return 0;
}

/*************************************************
 * Name:        crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - u8 *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - u8 *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair(u8 *pk, u8 *sk, Rng *rng) {
	__attribute__((aligned(32))) u8 coins[2 * KYBER_SYMBYTES] = {0};
	rng_gen(rng, coins, 2 * KYBER_SYMBYTES);
	crypto_kem_keypair_derand(pk, sk, coins);
	return 0;
}

/*************************************************
 * Name:        crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - u8 *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - u8 *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const u8 *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - const u8 *coins: pointer to input randomness
 *                (an already allocated array filled with KYBER_SYMBYTES random
 *bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc_derand(u8 *ct, u8 *ss, const u8 *pk, const u8 *coins) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES] = {0};

	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES] = {0};

	fastmemcpy(buf, coins, KYBER_SYMBYTES);

	storm_init(&ctx, PUBKEY_HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	storm_next_block(&ctx, buf + KYBER_SYMBYTES);

	storm_init(&ctx, KR_HASH_DOMAIN);
	fastmemcpy(kr, buf, 2 * KYBER_SYMBYTES);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + KYBER_SYMBYTES);

	indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);
	fastmemcpy(ss, kr, KYBER_SYMBYTES);

	return 0;
}

/*************************************************
 * Name:        crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - u8 *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - u8 *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const u8 *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng) {
	__attribute((aligned(32))) u8 coins[KYBER_SYMBYTES] = {0};
	rng_gen(rng, coins, KYBER_SYMBYTES);
	crypto_kem_enc_derand(ct, ss, pk, coins);
	return 0;
}

/*************************************************
 * Name:        crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - u8 *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const u8 *ct: pointer to input cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - const u8 *sk: pointer to input private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int crypto_kem_dec(u8 *ss, const u8 *ct, const u8 *sk) {
	int fail;
	StormContext ctx;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES];
	/* Will contain key, coins */
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES];
	__attribute__((aligned(32))) u8 cmp[KYBER_CIPHERTEXTBYTES];
	const u8 *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec(buf, ct, sk);

	/* Multitarget countermeasure for coins + contributory KEM */
	fastmemcpy(buf + KYBER_SYMBYTES,
		   sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
		   KYBER_SYMBYTES);

	storm_init(&ctx, KR_HASH_DOMAIN);
	fastmemcpy(kr, buf, 2 * KYBER_SYMBYTES);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + KYBER_SYMBYTES);

	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	storm_init(&ctx, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES);
	for (u32 i = 0; i < KYBER_CIPHERTEXTBYTES; i += 32)
		storm_next_block(&ctx, cmp + i);
	fastmemset(ss, 0, 32);
	storm_next_block(&ctx, ss);

	/* Copy true key to return buffer if fail is false */
	cmov(ss, kr, KYBER_SYMBYTES, !fail);

	return 0;
}
#endif /* !USE_AVX2 */
