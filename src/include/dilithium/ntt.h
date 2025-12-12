#ifndef NTT_H
#define NTT_H

#include <dilithium/params.h>
#include <libfam/types.h>

void ntt(i32 a[N]);
void invntt_tomont(i32 a[N]);

#endif
