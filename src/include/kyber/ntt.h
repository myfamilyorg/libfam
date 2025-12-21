#ifndef NTT_H
#define NTT_H

#include <kyber/params.h>

#define zetas KYBER_NAMESPACE(zetas)
extern const i16 zetas[128];

#define ntt KYBER_NAMESPACE(ntt)
void ntt(i16 poly[256]);

#define invntt KYBER_NAMESPACE(invntt)
void invntt(i16 poly[256]);

#define basemul KYBER_NAMESPACE(basemul)
void basemul(i16 r[2], const i16 a[2], const i16 b[2],
	     i16 zeta);

#endif
