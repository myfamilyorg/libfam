#ifndef REDUCE_H
#define REDUCE_H

#include <dilithium/params.h>

#define MONT -4186625  // 2^32 % Q
#define QINV 58728449  // q^(-1) mod 2^32

i32 montgomery_reduce(i64 a);

i32 reduce32(i32 a);

i32 caddq(i32 a);

i32 freeze(i32 a);

#endif
