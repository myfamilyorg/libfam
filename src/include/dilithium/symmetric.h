#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <dilithium/fips202.h>

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

void dilithium_shake128_stream_init(keccak_state *state,
				    const u8 seed[SEEDBYTES], u16 nonce);

void dilithium_shake256_stream_init(keccak_state *state,
				    const u8 seed[CRHBYTES], u16 nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
	dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
	dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#endif
