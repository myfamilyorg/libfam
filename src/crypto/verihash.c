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
#define FIELD_SIZE 8
#define FULL_ROUNDS 8
#define PARTIAL_ROUNDS 22
#define EXPONENT 7

static const u64 full_matrix[8][8] = {
    {10, 14, 2, 6, 5, 7, 1, 3}, {8, 12, 2, 2, 4, 6, 1, 1},
    {2, 6, 10, 14, 1, 3, 5, 7}, {2, 2, 8, 12, 1, 1, 4, 6},
    {5, 7, 1, 3, 10, 14, 2, 6}, {4, 6, 1, 1, 8, 12, 2, 2},
    {1, 3, 5, 7, 2, 6, 10, 14}, {1, 1, 4, 6, 2, 2, 8, 12}};

static const u64 mu[FIELD_SIZE] = {3, 5, 7, 11, 13, 17, 19, 23};

__attribute__((aligned(32))) static const u8 VERIHASH_DOMAIN[32] = {1, 2, 39,
								    99};
__attribute__((aligned(
    32))) static u64 const_data[FULL_ROUNDS + PARTIAL_ROUNDS][FIELD_SIZE];

STATIC u64 mul_mod(u64 a, u64 b, u64 modulus) {
	u128 v = (u128)a * (u128)b;
	u128 m = modulus;

	return v % m;
}

STATIC u64 pow_mod(u64 base, u64 exponent, u64 modulus) {
	u64 result = 1;
	base %= modulus;
	if (base == 0) return 0;

	while (exponent > 0) {
		if (exponent & 1) result = mul_mod(result, base, modulus);
		base = mul_mod(base, base, modulus);
		exponent >>= 1;
	}
	return result;
}

STATIC void verihash_round(u64 field[FIELD_SIZE], u64 round) {
	for (u64 i = 0; i < FIELD_SIZE; i++)
		field[i] = (field[i] + const_data[round][i]) % GLOCKS;

	if (round < FULL_ROUNDS)
		for (u64 i = 0; i < FIELD_SIZE; i++)
			field[i] = pow_mod(field[i], EXPONENT, GLOCKS);
	else {
		if (round & 0x1) {
			for (u64 i = 0; i < FIELD_SIZE; i++)
				field[i] = pow_mod(field[i], EXPONENT, GLOCKS);

		} else {
			field[0] = pow_mod(field[0], EXPONENT, GLOCKS);
		}
	}

	u64 temp[FIELD_SIZE] = {0};
	if (round < FULL_ROUNDS) {
		for (u64 i = 0; i < FIELD_SIZE; i++) {
			for (u64 j = 0; j < FIELD_SIZE; j++) {
				temp[i] =
				    (temp[i] + mul_mod(full_matrix[i][j],
						       field[j], GLOCKS)) %
				    GLOCKS;
			}
		}
	} else {
		u64 s = 0;
		for (u64 j = 0; j < FIELD_SIZE; j++) {
			s = (s + field[j]) % GLOCKS;
		}
		for (u64 i = 0; i < FIELD_SIZE; i++) {
			temp[i] =
			    (mul_mod(mu[i], field[i], GLOCKS) + s) % GLOCKS;
		}
	}
	for (u64 i = 0; i < FIELD_SIZE; i++) field[i] = temp[i];
}

void verihash_init(void) {
	Storm256Context ctx;
	storm256_init(&ctx, VERIHASH_DOMAIN);
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++) {
		for (u64 j = 0; j < FIELD_SIZE / 4; j++)
			storm256_next_block(&ctx,
					    (((u8 *)const_data[i]) + j * 32));
	}
}

#include <libfam/aighthash.h>

u128 verihash(const u8 *in, u64 len) {
	u64 field[FIELD_SIZE] = {0};
	for (u64 i = 0; i < len; i++)
		((u8 *)field)[i % (FIELD_SIZE * 8)] ^= in[i];
	field[0] ^= (1 + len);
	for (u64 i = 0; i < FIELD_SIZE; i++) field[i] %= GLOCKS;
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++)
		verihash_round(field, i);
	u128 *ret = (void *)field;
	return ret[0];
}
