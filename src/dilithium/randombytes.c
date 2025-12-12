#include <dilithium/randombytes.h>
#include <libfam/rng.h>
void randombytes(uint8_t *out, size_t outlen) {
	Rng rng;
	rng_init(&rng, NULL);
	rng_gen(&rng, out, outlen);
}
