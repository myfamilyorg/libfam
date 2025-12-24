#ifndef POLY_H
#define POLY_H

#include <kyber_common/params.h>
#include <kyber_scalar/ns.h>

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
	i16 coeffs[KYBER_N];
} poly;

#define poly_compress KYBER_NAMESPACE(poly_compress)
void poly_compress(u8 r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);
#define poly_decompress KYBER_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const u8 a[KYBER_POLYCOMPRESSEDBYTES]);

#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(u8 r[KYBER_POLYBYTES], const poly *a);
#define poly_frombytes KYBER_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const u8 a[KYBER_POLYBYTES]);

#define poly_frommsg KYBER_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const u8 msg[KYBER_INDCPA_MSGBYTES]);
#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
void poly_tomsg(u8 msg[KYBER_INDCPA_MSGBYTES], const poly *r);

#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);

#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);

#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
#define poly_tomont KYBER_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
