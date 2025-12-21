#include <kyber/verify.h>

/*************************************************
 * Name:        verify
 *
 * Description: Compare two arrays for equality in constant time.
 *
 * Arguments:   const u8 *a: pointer to first byte array
 *              const u8 *b: pointer to second byte array
 *              u64 len:       length of the byte arrays
 *
 * Returns 0 if the byte arrays are equal, 1 otherwise
 **************************************************/
int verify(const u8 *a, const u8 *b, u64 len) {
	u64 i;
	u8 r = 0;

	for (i = 0; i < len; i++) r |= a[i] ^ b[i];

	return (-(u64)r) >> 63;
}

/*************************************************
 * Name:        cmov
 *
 * Description: Copy len bytes from x to r if b is 1;
 *              don't modify x if b is 0. Requires b to be in {0,1};
 *              assumes two's complement representation of negative integers.
 *              Runs in constant time.
 *
 * Arguments:   u8 *r:       pointer to output byte array
 *              const u8 *x: pointer to input byte array
 *              u64 len:       Amount of bytes to be copied
 *              u8 b:        Condition bit; has to be in {0,1}
 **************************************************/
void cmov(u8 *r, const u8 *x, u64 len, u8 b) {
	u64 i;

#if defined(__GNUC__) || defined(__clang__)
	// Prevent the compiler from
	//    1) inferring that b is 0/1-valued, and
	//    2) handling the two cases with a branch.
	// This is not necessary when verify.c and kem.c are separate
	// translation units, but we expect that downstream consumers will copy
	// this code and/or change how it is built.
	__asm__("" : "+r"(b) : /* no inputs */);
#endif

	b = -b;
	for (i = 0; i < len; i++) r[i] ^= b & (r[i] ^ x[i]);
}

/*************************************************
 * Name:        cmov_int16
 *
 * Description: Copy input v to *r if b is 1, don't modify *r if b is 0.
 *              Requires b to be in {0,1};
 *              Runs in constant time.
 *
 * Arguments:   i16 *r:       pointer to output i16
 *              i16 v:        input i16
 *              u8 b:        Condition bit; has to be in {0,1}
 **************************************************/
void cmov_int16(i16 *r, i16 v, u16 b) {
	b = -b;
	*r ^= b & ((*r) ^ v);
}
