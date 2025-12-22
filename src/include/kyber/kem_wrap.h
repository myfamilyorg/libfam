#ifndef _KEM_WRAP_H
#define _KEM_WRAP_H

#include <libfam/types.h>

int kem_keypair(u8 *pk, u8 *sk, Rng *rng);
int kem_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);
int kem_dec(u8 *ss, const u8 *ct, const u8 *sk);
#ifdef __AVX2__
i32 pqcrystals_kyber512_avx2_keypair(u8 *pk, u8 *sk, Rng *rng);
i32 pqcrystals_kyber512_avx2_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);
i32 pqcrystals_kyber512_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);
#endif /* __AVX2__ */

static inline void kyber_keypair(u8 *pk, u8 *sk, Rng *rng) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_keypair(pk, sk, rng);
#else
	kem_keypair(pk, sk, rng);
#endif
}

static inline void kyber_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_enc(ct, ss, pk, rng);
#else
	kem_enc(ct, ss, pk, rng);
#endif
}

static inline void kyber_dec(u8 *ss, const u8 *ct, const u8 *sk) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_dec(ss, ct, sk);
#else
	kem_dec(ss, ct, sk);
#endif
}

#endif /* _KEM_WRAP_H */
