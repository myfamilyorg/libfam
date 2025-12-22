#ifndef VERIFY_H
#define VERIFY_H

#include <kyber_avx2/namespace.h>
#include <kyber_common/params.h>
#include <libfam/types.h>
#include <stddef.h>
#include <stdint.h>

#define verify KYBER_NAMESPACE(verify)
int verify(const u8 *a, const u8 *b, u64 len);

#define cmov KYBER_NAMESPACE(cmov)
void cmov(u8 *r, const u8 *x, u64 len, u8 b);

#define cmov_int16 KYBER_NAMESPACE(cmov_int16)
void cmov_int16(i16 *r, i16 v, u16 b);

#endif
