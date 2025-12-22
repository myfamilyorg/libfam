#ifndef CBD_H
#define CBD_H

#include <immintrin.h>
#include <kyber_avx2/params.h>
#include <kyber_avx2/poly.h>
#include <stdint.h>

#define poly_cbd_eta1 KYBER_NAMESPACE(poly_cbd_eta1)
void poly_cbd_eta1(poly *r, const __m256i buf[KYBER_ETA1 * KYBER_N / 128 + 1]);

#define poly_cbd_eta2 KYBER_NAMESPACE(poly_cbd_eta2)
void poly_cbd_eta2(poly *r, const __m256i buf[KYBER_ETA2 * KYBER_N / 128]);

#endif
