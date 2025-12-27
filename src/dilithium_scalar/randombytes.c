#include <dilithium_scalar/randombytes.h>
#include <libfam/rng.h>

void randombytes(u8 *out, u64 outlen) {
	Rng rng;
	rng_init(&rng);
	rng_gen(&rng, out, outlen);
}
