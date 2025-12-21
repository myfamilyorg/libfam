#ifndef NTT_H
#define NTT_H

#include <kyber/params.h>

extern const i16 kyber_zetas[128];

void kyber_ntt(i16 poly[256]);
void kyber_invntt(i16 poly[256]);
void basemul(i16 r[2], const i16 a[2], const i16 b[2], i16 zeta);

#endif
