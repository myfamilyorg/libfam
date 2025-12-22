#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <libfam/rng.h>
#include <stddef.h>
#include <stdint.h>

void randombytes(uint8_t *out, size_t outlen, Rng *rng);

#endif
