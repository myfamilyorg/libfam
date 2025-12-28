#include <dilithium_scalar/params.h>
#include <dilithium_scalar/reduce.h>

/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
 *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * Arguments:   - i64: finite field element a
 *
 * Returns r.
 **************************************************/
i32 montgomery_reduce(i64 a) {
	i32 t;

	t = (i64)(i32)a * QINV;
	t = (a - (i64)t * Q) >> 32;
	return t;
}

/*************************************************
 * Name:        reduce32
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
i32 reduce32(i32 a) {
	i32 t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * Q;
	return t;
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add Q if input coefficient is negative.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
i32 caddq(i32 a) {
	a += (a >> 31) & Q;
	return a;
}

/*************************************************
 * Name:        freeze
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ Q.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
i32 freeze(i32 a) {
	a = reduce32(a);
	a = caddq(a);
	return a;
}
