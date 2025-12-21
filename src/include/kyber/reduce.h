#ifndef REDUCE_H
#define REDUCE_H

#include <kyber/params.h>

#define MONT -1044  // 2^16 mod q
#define QINV -3327  // q^-1 mod 2^16

i16 montgomery_reduce16(i32 a);
i16 barrett_reduce(i16 a);

#endif
