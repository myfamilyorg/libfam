#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <libfam/rng.h>
#include <stddef.h>
#include <stdint.h>

void randombytes(u8 *out, u64 outlen, Rng *rng);

#endif
