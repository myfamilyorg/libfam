#include <dilithium_scalar/randombytes.h>
#include <libfam/rng.h>
#include <libfam/string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void randombytes(uint8_t *out, size_t outlen) {
	Rng rng;
	rng_init(&rng);
	fastmemset(out, 0, outlen);
	rng_gen(&rng, out, outlen);
}
