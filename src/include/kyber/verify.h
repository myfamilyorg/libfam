#ifndef VERIFY_H
#define VERIFY_H

#include <kyber/params.h>

int kyber_verify(const u8 *a, const u8 *b, u64 len);
void cmov(u8 *r, const u8 *x, u64 len, u8 b);
void cmov_int16(i16 *r, i16 v, u16 b);

#endif
