#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <kyber_common/params.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define XOF_BLOCKBYTES SHAKE128_RATE

#define REJ_UNIFORM_AVX_NBLOCKS                                      \
	((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / \
	 XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS * XOF_BLOCKBYTES)

#define rej_uniform_avx KYBER_NAMESPACE(rej_uniform_avx)
unsigned int rej_uniform_avx(i16 *r, const u8 *buf);

#endif
