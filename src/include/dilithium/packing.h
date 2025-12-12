#ifndef PACKING_H
#define PACKING_H

#include <dilithium/params.h>
#include <dilithium/polyvec.h>
#include <libfam/types.h>

void pack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	     const polyveck *t1);

void pack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	     const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyveck *t0,
	     const polyvecl *s1, const polyveck *s2);

void pack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvecl *z,
	      const polyveck *h);

void unpack_pk(u8 rho[SEEDBYTES], polyveck *t1,
	       const u8 pk[CRYPTO_PUBLICKEYBYTES]);

void unpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
	       polyveck *t0, polyvecl *s1, polyveck *s2,
	       const u8 sk[CRYPTO_SECRETKEYBYTES]);

int unpack_sig(u8 c[CTILDEBYTES], polyvecl *z, polyveck *h,
	       const u8 sig[CRYPTO_BYTES]);

#endif
