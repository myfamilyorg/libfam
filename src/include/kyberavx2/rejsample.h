#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <stdint.h>

#include "params.h"

#define SHAKE128_RATE 168
#define REJ_UNIFORM_AVX_NBLOCKS 3
#define REJ_UNIFORM_AVX_BUFLEN 504

#define rej_uniform_avx KYBER_NAMESPACE(rej_uniform_avx)
unsigned int rej_uniform_avx(int16_t *r, const uint8_t *buf);

#endif
