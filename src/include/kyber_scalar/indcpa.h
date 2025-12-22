#ifndef INDCPA_H
#define INDCPA_H

#include <kyber_common/params.h>
#include <kyber_scalar/polyvec.h>
#include <stdint.h>

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const u8 seed[KYBER_SYMBYTES], int transposed);

#define indcpa_keypair_derand KYBER_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
			   u8 sk[KYBER_INDCPA_SECRETKEYBYTES],
			   const u8 coins[KYBER_SYMBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(u8 c[KYBER_INDCPA_BYTES],
		const u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
		const u8 coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 c[KYBER_INDCPA_BYTES],
		const u8 sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
