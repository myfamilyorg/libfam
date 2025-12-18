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

#include <libfam/format.h>
#include <libfam/storm.h>
#include <libfam/verihash.h>

#define GLOCKS 18446744069414584321ULL
#define GLOCKS_INV 0xFFFFFFFEFFFFFFFFULL
#define EXPONENT 5

static const u64 full_matrix[8][8] = {
    {10, 14, 2, 6, 5, 7, 1, 3}, {8, 12, 2, 2, 4, 6, 1, 1},
    {2, 6, 10, 14, 1, 3, 5, 7}, {2, 2, 8, 12, 1, 1, 4, 6},
    {5, 7, 1, 3, 10, 14, 2, 6}, {4, 6, 1, 1, 8, 12, 2, 2},
    {1, 3, 5, 7, 2, 6, 10, 14}, {1, 1, 4, 6, 2, 2, 8, 12}};

static const u64 mu[FIELD_SIZE] = {3, 5, 7, 11, 13, 17, 19, 23};

STATIC u64 mul_mod(u64 a, u64 b) {
	u128 v = (u128)a * (u128)b;
	u64 m = (u64)v * GLOCKS_INV;
	u128 t = (v + (u128)m * GLOCKS) >> 64;
	return (t >= GLOCKS) ? (u64)(t - GLOCKS) : (u64)t;
}

STATIC u64 pow_mod_mont(u64 base, u64 exponent) {
	u64 result = 1;
	u64 m = base * GLOCKS_INV;
	u128 t = (base + (u128)m * GLOCKS) >> 64;
	base = (t >= GLOCKS) ? (u64)(t - GLOCKS) : (u64)t;
	if (base == 0) return 0;

	while (exponent > 0) {
		if (exponent & 1) result = mul_mod(result, base);
		base = mul_mod(base, base);
		exponent >>= 1;
	}
	return result;
}

STATIC void verihash_round(u64 field[FIELD_SIZE], u64 round) {
	for (u64 i = 0; i < FIELD_SIZE; i++) {
		field[i] = field[i] + const_data[round][i];
		field[i] = field[i] >= GLOCKS ? GLOCKS - field[i] : field[i];
	}

	if (round < FULL_ROUNDS)
		for (u64 i = 0; i < FIELD_SIZE; i++)
			field[i] = pow_mod_mont(field[i], EXPONENT);
	else {
		if (round & 0x1) {
			for (u64 i = 0; i < FIELD_SIZE; i++)
				field[i] = pow_mod_mont(field[i], EXPONENT);

		} else {
			field[0] = pow_mod_mont(field[0], EXPONENT);
		}
	}

	u64 temp[FIELD_SIZE] = {0};
	if (round < FULL_ROUNDS) {
		for (u64 i = 0; i < FIELD_SIZE; i++) {
			for (u64 j = 0; j < FIELD_SIZE; j++) {
				temp[i] = temp[i] +
					  mul_mod(full_matrix[i][j], field[j]);
				temp[i] = temp[i] >= GLOCKS ? GLOCKS - temp[i]
							    : temp[i];
			}
		}
	} else {
		u64 s = 0;
		for (u64 j = 0; j < FIELD_SIZE; j++) {
			s += field[j];
			s = s >= GLOCKS ? GLOCKS - s : s;
		}
		for (u64 i = 0; i < FIELD_SIZE; i++) {
			temp[i] = mul_mod(mu[i], field[i]) + s;
			temp[i] =
			    temp[i] >= GLOCKS ? GLOCKS - temp[i] : temp[i];
		}
	}
	for (u64 i = 0; i < FIELD_SIZE; i++) field[i] = temp[i];
}

u128 verihash128(const u8 *in, u64 len) {
	u64 field[FIELD_SIZE] = {0};
	for (u64 i = 0; i < len; i++) ((u8 *)field)[i & FIELD_MASK] ^= in[i];
	field[0] ^= (1 + len);
	for (u64 i = 0; i < FIELD_SIZE; i++)
		field[i] = field[i] >= GLOCKS ? field[i] - GLOCKS : field[i];
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++)
		verihash_round(field, i);
	u128 *ret = (void *)field;
	return ret[0];
}

void verihash256(const u8 *in, u64 len, u8 out[32]) {
	u64 field[FIELD_SIZE] = {0};
	for (u64 i = 0; i < len; i++) ((u8 *)field)[i & FIELD_MASK] ^= in[i];
	field[0] ^= (1 + len);
	for (u64 i = 0; i < FIELD_SIZE; i++)
		field[i] = field[i] >= GLOCKS ? field[i] - GLOCKS : field[i];
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++)
		verihash_round(field, i);
	fastmemcpy(out, field, 32);
}
