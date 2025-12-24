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

#ifndef __AVX2__
#include <kyber_common/params.h>
#include <kyber_scalar/cbd.h>

STATIC u32 load32_littleendian(const u8 x[4]) {
	u32 r;
	r = (u32)x[0];
	r |= (u32)x[1] << 8;
	r |= (u32)x[2] << 16;
	r |= (u32)x[3] << 24;
	return r;
}

STATIC u32 load24_littleendian(const u8 x[3]) {
	u32 r;
	r = (u32)x[0];
	r |= (u32)x[1] << 8;
	r |= (u32)x[2] << 16;
	return r;
}

STATIC void cbd2(poly *r, const u8 buf[2 * KYBER_N / 4]) {
	unsigned int i, j;
	u32 t, d;
	i16 a, b;

	for (i = 0; i < KYBER_N / 8; i++) {
		t = load32_littleendian(buf + 4 * i);
		d = t & 0x55555555;
		d += (t >> 1) & 0x55555555;

		for (j = 0; j < 8; j++) {
			a = (d >> (4 * j + 0)) & 0x3;
			b = (d >> (4 * j + 2)) & 0x3;
			r->coeffs[8 * i + j] = a - b;
		}
	}
}

STATIC void cbd3(poly *r, const u8 buf[3 * KYBER_N / 4]) {
	unsigned int i, j;
	u32 t, d;
	i16 a, b;

	for (i = 0; i < KYBER_N / 4; i++) {
		t = load24_littleendian(buf + 3 * i);
		d = t & 0x00249249;
		d += (t >> 1) & 0x00249249;
		d += (t >> 2) & 0x00249249;

		for (j = 0; j < 4; j++) {
			a = (d >> (6 * j + 0)) & 0x7;
			b = (d >> (6 * j + 3)) & 0x7;
			r->coeffs[4 * i + j] = a - b;
		}
	}
}

void poly_cbd_eta1(poly *r, const u8 buf[KYBER_ETA1 * KYBER_N / 4]) {
	cbd3(r, buf);
}

void poly_cbd_eta2(poly *r, const u8 buf[KYBER_ETA2 * KYBER_N / 4]) {
	cbd2(r, buf);
}

#endif /* __AVX2__ */
