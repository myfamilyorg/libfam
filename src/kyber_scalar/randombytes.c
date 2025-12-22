#include <kyber_scalar/randombytes.h>
#include <libfam/format.h>
#include <libfam/rng.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void randombytes(u8 *out, size_t outlen, Rng *rng) {
	rng_gen(rng, out, outlen);
}
