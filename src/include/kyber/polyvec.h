#ifndef POLYVEC_H
#define POLYVEC_H

#include <kyber/params.h>
#include <kyber/poly.h>

typedef struct {
	__attribute__((aligned(32))) poly vec[KYBER_K];
} polyvec;

void polyvec_compress(u8 r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
void polyvec_decompress(polyvec *r, const u8 a[KYBER_POLYVECCOMPRESSEDBYTES]);

void polyvec_tobytes(u8 r[KYBER_POLYVECBYTES], const polyvec *a);
void polyvec_frombytes(polyvec *r, const u8 a[KYBER_POLYVECBYTES]);

void kyber_polyvec_ntt(polyvec *r);
void kyber_polyvec_invntt_tomont(polyvec *r);

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
				    const polyvec *b);

void kyber_polyvec_reduce(polyvec *r);

void kyber_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
