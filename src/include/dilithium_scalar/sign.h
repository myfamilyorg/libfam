#ifndef SIGN_H
#define SIGN_H

#include <dilithium_scalar/params.h>
#include <dilithium_scalar/poly.h>
#include <dilithium_scalar/polyvec.h>
#include <libfam/rng.h>

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(u8 *pk, u8 *sk, const u8 seed[32]);

#define crypto_sign_signature_internal DILITHIUM_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
				   const u8 *pre, u64 prelen,
				   const u8 rnd[RNDBYTES], const u8 *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
			  const u8 *ctx, u64 ctxlen, const u8 *sk, Rng *rng);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(u8 *sm, u64 *smlen, const u8 *m, u64 mlen, const u8 *ctx,
		u64 ctxlen, const u8 *sk, Rng *rng);

#define crypto_sign_verify_internal DILITHIUM_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const u8 *sig, u64 siglen, const u8 *m,
				u64 mlen, const u8 *pre, u64 prelen,
				const u8 *pk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const u8 *sig, u64 siglen, const u8 *m, u64 mlen,
		       const u8 *ctx, u64 ctxlen, const u8 *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(u8 *m, u64 *mlen, const u8 *sm, u64 smlen, const u8 *ctx,
		     u64 ctxlen, const u8 *pk);

#endif
