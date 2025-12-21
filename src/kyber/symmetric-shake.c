#include <kyber/fips202.h>
#include <kyber/params.h>
#include <kyber/symmetric.h>
#include <libfam/string.h>

/*************************************************
 * Name:        kyber_shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 specialized for the Kyber context.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const u8 *seed: pointer to KYBER_SYMBYTES input to be
 *absorbed into state
 *              - u8 i: additional byte of input
 *              - u8 j: additional byte of input
 **************************************************/
void kyber_shake128_absorb(keccak_state *state, const u8 seed[KYBER_SYMBYTES],
			   u8 x, u8 y) {
	u8 extseed[KYBER_SYMBYTES + 2];

	fastmemcpy(extseed, seed, KYBER_SYMBYTES);
	extseed[KYBER_SYMBYTES + 0] = x;
	extseed[KYBER_SYMBYTES + 1] = y;

	shake128_absorb_once(state, extseed, sizeof(extseed));
}

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - u8 *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const u8 *key: pointer to the key (of length
 *KYBER_SYMBYTES)
 *              - u8 nonce: single-byte nonce (public PRF input)
 **************************************************/
void kyber_shake256_prf(u8 *out, size_t outlen, const u8 key[KYBER_SYMBYTES],
			u8 nonce) {
	u8 extkey[KYBER_SYMBYTES + 1];

	fastmemcpy(extkey, key, KYBER_SYMBYTES);
	extkey[KYBER_SYMBYTES] = nonce;

	shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - u8 *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const u8 *key: pointer to the key (of length
 *KYBER_SYMBYTES)
 *              - u8 nonce: single-byte nonce (public PRF input)
 **************************************************/
void kyber_shake256_rkprf(u8 out[KYBER_SSBYTES], const u8 key[KYBER_SYMBYTES],
			  const u8 input[KYBER_CIPHERTEXTBYTES]) {
	keccak_state s;

	shake256_init(&s);
	shake256_absorb(&s, key, KYBER_SYMBYTES);
	shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
	shake256_finalize(&s);
	shake256_squeeze(out, KYBER_SSBYTES, &s);
}
