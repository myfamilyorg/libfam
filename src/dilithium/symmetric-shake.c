#include <dilithium/fips202.h>
#include <dilithium/params.h>
#include <dilithium/symmetric.h>
#include <libfam/types.h>

void dilithium_shake128_stream_init(keccak_state *state,
				    const u8 seed[SEEDBYTES],
				    u16 nonce) {
	u8 t[2];
	t[0] = nonce;
	t[1] = nonce >> 8;

	shake128_init(state);
	shake128_absorb(state, seed, SEEDBYTES);
	shake128_absorb(state, t, 2);
	shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state,
				    const u8 seed[CRHBYTES],
				    u16 nonce) {
	u8 t[2];
	t[0] = nonce;
	t[1] = nonce >> 8;

	shake256_init(state);
	shake256_absorb(state, seed, CRHBYTES);
	shake256_absorb(state, t, 2);
	shake256_finalize(state);
}
