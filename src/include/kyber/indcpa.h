#ifndef INDCPA_H
#define INDCPA_H

#include <kyber/params.h>
#include <kyber/polyvec.h>

void gen_matrix(polyvec *a, const u8 seed[KYBER_SYMBYTES], int transposed);
void indcpa_keypair_derand(u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
			   u8 sk[KYBER_INDCPA_SECRETKEYBYTES],
			   const u8 coins[KYBER_SYMBYTES]);
void indcpa_enc(u8 c[KYBER_INDCPA_BYTES], const u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
		const u8 coins[KYBER_SYMBYTES]);
void indcpa_dec(u8 m[KYBER_INDCPA_MSGBYTES], const u8 c[KYBER_INDCPA_BYTES],
		const u8 sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
