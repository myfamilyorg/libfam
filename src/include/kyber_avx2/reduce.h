#ifndef REDUCE_H
#define REDUCE_H

#include <immintrin.h>
#include <kyber_common/params.h>

#define reduce_avx KYBER_NAMESPACE(reduce_avx)
void reduce_avx(__m256i *r, const __m256i *qdata);
#define tomont_avx KYBER_NAMESPACE(tomont_avx)
void tomont_avx(__m256i *r, const __m256i *qdata);

#endif
