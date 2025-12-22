#ifndef REDUCE_H
#define REDUCE_H

#include <kyber_common/params.h>
#include <kyber_scalar/namespace.h>
#include <stdint.h>

#define MONT -1044  // 2^16 mod q
#define QINV -3327  // q^-1 mod 2^16

#define montgomery_reduce KYBER_NAMESPACE(montgomery_reduce)
i16 montgomery_reduce(i32 a);

#define barrett_reduce KYBER_NAMESPACE(barrett_reduce)
i16 barrett_reduce(i16 a);

#endif
