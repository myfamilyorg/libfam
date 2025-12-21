#ifndef CBD_H
#define CBD_H

#include <kyber/params.h>
#include <kyber/poly.h>

void poly_cbd_eta1(poly *r, const u8 buf[KYBER_ETA1 * KYBER_N / 4]);
void poly_cbd_eta2(poly *r, const u8 buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
