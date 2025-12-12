#ifndef NTT_H
#define NTT_H

#include <dilithium/params.h>
#include <libfam/types.h>

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(i32 a[N]);

#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(i32 a[N]);

#endif
