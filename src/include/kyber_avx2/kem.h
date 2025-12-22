#ifndef KEM_H
#define KEM_H

#include <kyber_common/params.h>
#include <libfam/rng.h>

#define CRYPTO_SECRETKEYBYTES KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES KYBER_SSBYTES

#if (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

#define crypto_kem_keypair_derand KYBER_NAMESPACE(keypair_derand)
void crypto_kem_keypair_derand(u8 *pk, u8 *sk, const u8 *coins);

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
void crypto_kem_keypair(u8 *pk, u8 *sk, Rng *rng);

#define crypto_kem_enc_derand KYBER_NAMESPACE(enc_derand)
void crypto_kem_enc_derand(u8 *ct, u8 *ss, const u8 *pk, const u8 *coins);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
void crypto_kem_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
void crypto_kem_dec(u8 *ss, const u8 *ct, const u8 *sk);

#endif
