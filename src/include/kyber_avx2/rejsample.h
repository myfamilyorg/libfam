#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <kyber_common/params.h>
#include <libfam/types.h>

#define REJ_UNIFORM_AVX_NBLOCKS 3
#define XOF_BLOCKBYTES 168

#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS * XOF_BLOCKBYTES)

#define rej_uniform_avx KYBER_NAMESPACE(rej_uniform_avx)
unsigned int rej_uniform_avx(i16 *r, const u8 *buf);

#endif
