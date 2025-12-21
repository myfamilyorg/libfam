#ifndef POLY_H
#define POLY_H

#include <kyber/params.h>

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
	i16 coeffs[KYBER_N];
} poly;

void poly_compress(u8 r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress(poly *r, const u8 a[KYBER_POLYCOMPRESSEDBYTES]);
void poly_tobytes(u8 r[KYBER_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const u8 a[KYBER_POLYBYTES]);
void poly_frommsg(poly *r, const u8 msg[KYBER_INDCPA_MSGBYTES]);
void poly_tomsg(u8 msg[KYBER_INDCPA_MSGBYTES], const poly *r);
void poly_getnoise_eta1(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);
void poly_getnoise_eta2(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);
void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);
void poly_reduce(poly *r);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
