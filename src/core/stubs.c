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

#include <libfam/builtin.h>
#include <libfam/types.h>
#include <libfam/utils.h>

PUBLIC u128 __umodti3(u128 a, u128 b) {
	u64 a_hi, a_lo, b_lo;
	u128 rem;
	i32 shift;

	if (!b) trap();
	if (a < b) return a;
	if (!(b >> 64)) {
		b_lo = (u64)b;
		a_hi = (u64)(a >> 64);
		a_lo = (u64)a;
		if (!a_hi) return a_lo % b_lo;
		rem = a_hi % b_lo;
		rem = (rem << 32) | (a_lo >> 32);
		rem = rem % b_lo;
		rem = (rem << 32) | (a_lo & 0xffffffff);
		rem = (u64)rem % b_lo;
		return rem;
	}

	rem = a;
	shift = (i32)clz_u128(b) - (i32)clz_u128(rem);
	if (shift < 0) shift = 0;
	b <<= shift;
	while (shift >= 0) {
		if (rem >= b) rem -= b;
		b >>= 1;
		shift--;
	}
	return rem;
}

PUBLIC u128 __udivti3(u128 a, u128 b) {
	i32 shift;
	u128 quot, rem;
	if (!b) trap();
	if (a < b) return 0;
	quot = 0;
	rem = a;
	shift = (i32)clz_u128(b) - (i32)clz_u128(rem);
	if (shift < 0) shift = 0;

	b <<= shift;

	while (shift >= 0) {
		if (rem >= b) {
			rem -= b;
			quot |= ((u128)1 << shift);
		}
		b >>= 1;
		shift--;
	}
	return quot;
}
