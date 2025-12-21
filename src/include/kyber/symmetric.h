#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <kyber/fips202.h>
#include <kyber/params.h>

typedef keccak_state xof_state;

void kyber_shake128_absorb(keccak_state *s, const u8 seed[KYBER_SYMBYTES], u8 x,
			   u8 y);

void kyber_shake256_prf(u8 *out, u64 outlen, const u8 key[KYBER_SYMBYTES],
			u8 nonce);

void kyber_shake256_rkprf(u8 out[KYBER_SSBYTES], const u8 key[KYBER_SYMBYTES],
			  const u8 input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
	kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */
