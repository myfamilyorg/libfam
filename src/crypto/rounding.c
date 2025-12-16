/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#include <libfam/dilithium_const.h>
#include <libfam/dilithium_impl.h>

/*************************************************
 * Name:        power2round
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 *              Assumes a to be standard representative.
 *
 * Arguments:   - i32 a: input element
 *              - i32 *a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
i32 power2round(i32 *a0, i32 a) {
	i32 a1;

	a1 = (a + (1 << (D - 1)) - 1) >> D;
	*a0 = a - (a1 << D);
	return a1;
}

/*************************************************
 * Name:        decompose
 *
 * Description: For finite field element a, compute high and low bits a0, a1
 *such that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except if a1
 *= (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0.
 *Assumes a to be standard representative.
 *
 * Arguments:   - i32 a: input element
 *              - i32 *a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
i32 decompose(i32 *a0, i32 a) {
	i32 a1;

	a1 = (a + 127) >> 7;
#if GAMMA2 == (Q - 1) / 32
	a1 = (a1 * 1025 + (1 << 21)) >> 22;
	a1 &= 15;
#elif GAMMA2 == (Q - 1) / 88
	a1 = (a1 * 11275 + (1 << 23)) >> 24;
	a1 ^= ((43 - a1) >> 31) & a1;
#endif

	*a0 = a - a1 * 2 * GAMMA2;
	*a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
	return a1;
}

/*************************************************
 * Name:        make_hint
 *
 * Description: Compute hint bit indicating whether the low bits of the
 *              input element overflow into the high bits.
 *
 * Arguments:   - i32 a0: low bits of input element
 *              - i32 a1: high bits of input element
 *
 * Returns 1 if overflow.
 **************************************************/
u32 make_hint(i32 a0, i32 a1) {
	if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) return 1;

	return 0;
}

/*************************************************
 * Name:        use_hint
 *
 * Description: Correct high bits according to hint.
 *
 * Arguments:   - i32 a: input element
 *              - u32 hint: hint bit
 *
 * Returns corrected high bits.
 **************************************************/
i32 use_hint(i32 a, u32 hint) {
	i32 a0, a1;

	a1 = decompose(&a0, a);
	if (hint == 0) return a1;

#if GAMMA2 == (Q - 1) / 32
	if (a0 > 0)
		return (a1 + 1) & 15;
	else
		return (a1 - 1) & 15;
#elif GAMMA2 == (Q - 1) / 88
	if (a0 > 0)
		return (a1 == 43) ? 0 : a1 + 1;
	else
		return (a1 == 0) ? 43 : a1 - 1;
#endif
}
