#ifndef CBD_H
#define CBD_H

#include <kyber_common/params.h>
#include <kyber_scalar/poly.h>
#include <stdint.h>

#define poly_cbd_eta1 KYBER_NAMESPACE(poly_cbd_eta1)
void poly_cbd_eta1(poly *r, const u8 buf[KYBER_ETA1 * KYBER_N / 4]);

#define poly_cbd_eta2 KYBER_NAMESPACE(poly_cbd_eta2)
void poly_cbd_eta2(poly *r, const u8 buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
