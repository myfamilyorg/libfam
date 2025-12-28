#ifndef ROUNDING_H
#define ROUNDING_H

#include <dilithium_scalar/params.h>

#define power2round DILITHIUM_NAMESPACE(power2round)
i32 power2round(i32 *a0, i32 a);

#define decompose DILITHIUM_NAMESPACE(decompose)
i32 decompose(i32 *a0, i32 a);

#define make_hint DILITHIUM_NAMESPACE(make_hint)
unsigned int make_hint(i32 a0, i32 a1);

#define use_hint DILITHIUM_NAMESPACE(use_hint)
i32 use_hint(i32 a, unsigned int hint);

#endif
