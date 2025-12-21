#include "randombytes.h"

#include <libfam/rng.h>
#include <libfam/string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void randombytes(void *out, u64 outlen) {
	Rng rng;
	fastmemset(out, 0, outlen);
	rng_init(&rng);
	rng_gen(&rng, out, outlen);
}
