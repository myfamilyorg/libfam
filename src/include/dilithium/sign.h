#ifndef SIGN_H
#define SIGN_H

#include <dilithium/params.h>
#include <dilithium/poly.h>
#include <dilithium/polyvec.h>
#include <stddef.h>
#include <stdint.h>

int dilithium_keypair(uint8_t *pk, uint8_t *sk);

int dilithium_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
		   const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

int dilithium_verify(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
		     const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

#endif
