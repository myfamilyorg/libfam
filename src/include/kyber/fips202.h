#ifndef FIPS202_H
#define FIPS202_H

#include <libfam/types.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
	u64 s[25];
	unsigned int pos;
} keccak_state;

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const u8 *in, u64 inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(u8 *out, u64 outlen, keccak_state *state);
void shake128_absorb_once(keccak_state *state, const u8 *in, u64 inlen);
void shake128_squeezeblocks(u8 *out, u64 nblocks, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const u8 *in, u64 inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(u8 *out, u64 outlen, keccak_state *state);
void shake256_absorb_once(keccak_state *state, const u8 *in, u64 inlen);
void shake256_squeezeblocks(u8 *out, u64 nblocks, keccak_state *state);

void shake128(u8 *out, u64 outlen, const u8 *in, u64 inlen);
void shake256(u8 *out, u64 outlen, const u8 *in, u64 inlen);
void sha3_256(u8 h[32], const u8 *in, u64 inlen);
void sha3_512(u8 h[64], const u8 *in, u64 inlen);

#endif
