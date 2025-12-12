#include <dilithium/randombytes.h>
#include <libfam/rng.h>
void randombytes(u8 *out, u64 outlen) {
	Rng rng;
	rng_init(&rng, NULL);
	rng_gen(&rng, out, outlen);
}
