#include <kyber/params.h>
#include <kyber/reduce.h>

/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: Montgomery reduction; given a 32-bit integer a, computes
 *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * Arguments:   - i32 a: input integer to be reduced;
 *                           has to be in {-q2^15,...,q2^15-1}
 *
 * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 **************************************************/
i16 montgomery_reduce16(i32 a) {
	i16 t;

	t = (i16)a * QINV;
	t = (a - (i32)t * KYBER_Q) >> 16;
	return t;
}

/*************************************************
 * Name:        barrett_reduce
 *
 * Description: Barrett reduction; given a 16-bit integer a, computes
 *              centered representative congruent to a mod q in
 *{-(q-1)/2,...,(q-1)/2}
 *
 * Arguments:   - i16 a: input integer to be reduced
 *
 * Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
 **************************************************/
i16 barrett_reduce(i16 a) {
	i16 t;
	const i16 v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

	t = ((i32)v * a + (1 << 25)) >> 26;
	t *= KYBER_Q;
	return a - t;
}
