#include "randombytes.h"

#include <libfam/rng.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void randombytes(void *out, u64 outlen) {
	Rng rng;
	rng_init(&rng, NULL);
	rng_gen(&rng, out, outlen);
}
