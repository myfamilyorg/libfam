#ifndef PACKING_H
#define PACKING_H

#include <dilithium/params.h>
#include <dilithium/polyvec.h>
#include <libfam/types.h>

void pack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	     const polyvec *t1);

void pack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	     const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyvec *t0,
	     const polyvec *s1, const polyvec *s2);

void pack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvec *z,
	      const polyvec *h);

void unpack_pk(u8 rho[SEEDBYTES], polyvec *t1,
	       const u8 pk[CRYPTO_PUBLICKEYBYTES]);

void unpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
	       polyvec *t0, polyvec *s1, polyvec *s2,
	       const u8 sk[CRYPTO_SECRETKEYBYTES]);

int unpack_sig(u8 c[CTILDEBYTES], polyvec *z, polyvec *h,
	       const u8 sig[CRYPTO_BYTES]);

#endif
