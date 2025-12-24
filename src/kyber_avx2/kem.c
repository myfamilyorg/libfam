#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#ifdef USE_AVX2

#include <kyber_avx2/indcpa.h>
#include <kyber_avx2/kem.h>
#include <kyber_avx2/params.h>
#include <kyber_avx2/symmetric.h>
#include <kyber_avx2/verify.h>
#include <libfam/kem_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*************************************************
 * Name:        crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *              - uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with 2*KYBER_SYMBYTES
 *random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
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
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, Rng *rng) {
	__attribute__((aligned(32))) uint8_t coins[2 * KYBER_SYMBYTES] = {0};
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
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - const uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with KYBER_SYMBYTES random
 *bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
			  const uint8_t *coins) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES] = {0};

	__attribute__((aligned(32))) uint8_t buf[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) uint8_t kr[2 * KYBER_SYMBYTES] = {0};

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
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, Rng *rng) {
	__attribute__((aligned(32))) uint8_t coins[KYBER_SYMBYTES] = {0};
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
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *ct: pointer to input cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - const uint8_t *sk: pointer to input private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
	StormContext ctx;
	int fail;
	__attribute__((aligned(32))) uint8_t buf[2 * KYBER_SYMBYTES];
	/* Will contain key, coins */
	__attribute__((aligned(32))) uint8_t kr[2 * KYBER_SYMBYTES];
	//  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
	uint8_t cmp[KYBER_CIPHERTEXTBYTES];
	const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec(buf, ct, sk);

	/* Multitarget countermeasure for coins + contributory KEM */
	fastmemcpy(buf + KYBER_SYMBYTES,
		   sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
		   KYBER_SYMBYTES);

	storm_init(&ctx, KR_HASH_DOMAIN);
	fastmemcpy(kr, buf, 2 * KYBER_SYMBYTES);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + KYBER_SYMBYTES);

	/* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	/* Compute rejection key */
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
