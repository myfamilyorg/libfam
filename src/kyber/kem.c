#include <kyber/indcpa.h>
#include <kyber/params.h>
#include <kyber/verify.h>
#include <libfam/format.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>

__attribute__((aligned(32))) u8 HASH_DOMAIN[32] = {1, 1, 2, 1, 2, 1};
i32 pqcrystals_kyber512_avx2_keypair(u8 *pk, u8 *sk, Rng *rng);
i32 pqcrystals_kyber512_avx2_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);
i32 pqcrystals_kyber512_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);

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
 * Arguments:   - u8 *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - u8 *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int kem_keypair(u8 *pk, u8 *sk, Rng *rng) {
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
 * Arguments:   - u8 *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - u8 *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const u8 *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int kem_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng) {
	__attribute__((aligned(32))) u8 coins[KYBER_SYMBYTES] = {0};
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
int kem_dec(u8 *ss, const u8 *ct, const u8 *sk) {
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
	fail = kyber_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

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
