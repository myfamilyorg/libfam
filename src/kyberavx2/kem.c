#ifdef __AVX2__
#include <kyberavx2/indcpa.h>
#include <kyberavx2/kem.h>
#include <kyberavx2/params.h>
#include <kyberavx2/randombytes.h>
#include <kyberavx2/verify.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const
    __attribute__((aligned(32))) u8 HASH_DOMAIN[32] = {1, 1, 2, 1, 2, 1};

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
/*
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
	indcpa_keypair_derand(pk, sk, coins);
	memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
	hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk,
	       KYBER_PUBLICKEYBYTES);
	memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
	       coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
	return 0;
}
*/
int crypto_kem_keypair_derand(u8 *pk, u8 *sk, const u8 *coins) {
	StormContext ctx;
	indcpa_keypair_derand(pk, sk, coins);
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES];

	fastmemcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	fastmemset(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, 0, 32);
	storm_next_block(&ctx, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES);

	/* Value z for pseudo-random output on reject */
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
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
	__attribute__((aligned(32))) uint8_t coins[2 * KYBER_SYMBYTES] = {0};
	randombytes(coins, 2 * KYBER_SYMBYTES);
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
/*
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
			  const uint8_t *coins) {
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];

	memcpy(buf, coins, KYBER_SYMBYTES);

	hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

	memcpy(ss, kr, KYBER_SYMBYTES);
	return 0;
}
*/

int crypto_kem_enc_derand(u8 *ct, u8 *ss, const u8 *pk, const u8 *coins) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES];
	__attribute__((aligned(32))) u8 buf_copy[2 * KYBER_SYMBYTES];
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES];

	fastmemcpy(buf, coins, KYBER_SYMBYTES);

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	fastmemset(buf + KYBER_SYMBYTES, 0, 32);
	storm_next_block(&ctx, buf + KYBER_SYMBYTES);

	fastmemcpy(buf_copy, buf, 2 * KYBER_SYMBYTES);
	storm_init(&ctx, HASH_DOMAIN);
	storm_next_block(&ctx, buf_copy);
	storm_next_block(&ctx, buf_copy + 32);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + 32);

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
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
	uint8_t coins[KYBER_SYMBYTES] = {0};
	randombytes(coins, KYBER_SYMBYTES);
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
/*
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
	int fail;
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];
	//  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
	uint8_t cmp[KYBER_CIPHERTEXTBYTES];
	const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec(buf, ct, sk);

	memcpy(buf + KYBER_SYMBYTES,
	       sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);

	return 0;
}
*/

int crypto_kem_dec(u8 *ss, const u8 *ct, const u8 *sk) {
	StormContext ctx;
	int fail;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES];
	__attribute__((aligned(32))) u8 buf_copy[2 * KYBER_SYMBYTES];
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 cmp[KYBER_CIPHERTEXTBYTES];
	__attribute__((aligned(32))) u8 sk_copy[32];

	const u8 *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec(buf, ct, sk);
	fastmemcpy(buf + KYBER_SYMBYTES,
		   sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
		   KYBER_SYMBYTES);
	fastmemcpy(buf_copy, buf, 2 * KYBER_SYMBYTES);
	storm_init(&ctx, HASH_DOMAIN);
	storm_next_block(&ctx, buf_copy);
	storm_next_block(&ctx, buf_copy + 32);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + 32);
	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	fastmemset(ss, 0, 32);
	fastmemcpy(sk_copy, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, 32);
	storm_init(&ctx, sk_copy);
	for (u32 i = 0; i < KYBER_CIPHERTEXTBYTES; i += 32)
		storm_next_block(&ctx, cmp + i);
	storm_next_block(&ctx, ss);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);
	secure_zero(sk_copy, 32);
	secure_zero(cmp, KYBER_CIPHERTEXTBYTES);

	return 0;
}
#endif /* __AVX2__ */
