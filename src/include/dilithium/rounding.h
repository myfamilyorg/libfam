#ifndef ROUNDING_H
#define ROUNDING_H

#include <dilithium/params.h>

i32 power2round(i32 *a0, i32 a);

i32 decompose(i32 *a0, i32 a);

u32 make_hint(i32 a0, i32 a1);

i32 use_hint(i32 a, u32 hint);

#endif
