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

#include <libfam/aighthash.h>
#include <libfam/bible.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/test_base.h>

Test(aighthash) {
	u32 v1, v2, v3;

	v1 = aighthash32("11111111abc", 11, 0);
	v2 = aighthash32("11111111abc\0", 12, 0);
	v3 = aighthash32("11111111abc", 11, 0);
	ASSERT(v1 != v2, "v1 != v2");
	ASSERT(v1 == v3, "v1 == v3");

	u64 h1, h2, h3;

	h1 = aighthash64("XXXXXXXXXXXXXXXXxyz", 19, 0);
	h2 = aighthash64("XXXXXXXXXXXXXXXXxyz\0", 20, 0);
	h3 = aighthash64("XXXXXXXXXXXXXXXXxyz", 19, 0);
	ASSERT(h1 != h2, "h1 != h2");
	ASSERT(h1 == h3, "h1 == h3");
}

Test(storm) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute__((aligned(32))) u8 buffer1[32] = {0};
	__attribute__((aligned(32))) u8 buffer2[32] = {0};
	__attribute__((aligned(32))) u8 buffer3[32] = {0};
	__attribute__((aligned(32))) u8 buffer4[32] = {0};
	__attribute__((aligned(32))) u8 buffer5[32] = {0};

	storm_init(&ctx, SEED);
	faststrcpy(buffer1, "test1");
	storm_xcrypt_buffer(&ctx, buffer1);
	faststrcpy(buffer2, "test2");
	storm_xcrypt_buffer(&ctx, buffer2);
	faststrcpy(buffer3, "blahblah");
	storm_xcrypt_buffer(&ctx, buffer3);
	faststrcpy(buffer4, "ok");
	storm_xcrypt_buffer(&ctx, buffer4);
	faststrcpy(buffer5, "x");
	storm_xcrypt_buffer(&ctx, buffer5);

	ASSERT(memcmp(buffer1, "test1", 5), "ne1");
	ASSERT(memcmp(buffer2, "test2", 5), "ne2");
	ASSERT(memcmp(buffer3, "blahblah", 8), "ne3");
	ASSERT(memcmp(buffer4, "ok", 2), "ne4");
	ASSERT(memcmp(buffer5, "x", 1), "ne5");

	StormContext ctx2;
	storm_init(&ctx2, SEED);

	storm_xcrypt_buffer(&ctx2, buffer1);
	ASSERT(!memcmp(buffer1, "test1", 5), "eq1");
	storm_xcrypt_buffer(&ctx2, buffer2);
	ASSERT(!memcmp(buffer2, "test2", 5), "eq2");

	storm_xcrypt_buffer(&ctx2, buffer3);
	ASSERT(!memcmp(buffer3, "blahblah", 8), "eq3");

	storm_xcrypt_buffer(&ctx2, buffer4);
	ASSERT(!memcmp(buffer4, "ok", 2), "eq4");

	storm_xcrypt_buffer(&ctx2, buffer5);
	ASSERT(!memcmp(buffer5, "x", 1), "eq5");
}

Test(storm_vectors) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf1);

	u8 exp1[32] = {0x90, 0xC0, 0xC6, 0x22, 0xE6, 0x25, 0x85, 0x38,
		       0x17, 0x59, 0x2F, 0x3,  0xA,  0x3C, 0xD9, 0x98,
		       0x1C, 0x41, 0x99, 0xC6, 0x9D, 0x5C, 0x79, 0x36,
		       0xED, 0x98, 0x94, 0xF5, 0xB3, 0xEF, 0x7F, 0xE2};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {0x71, 0xEF, 0xAB, 0x45, 0x53, 0x34, 0x1C, 0x3C,
		       0xE1, 0xDC, 0x38, 0x32, 0x8A, 0x6,  0xF5, 0x3,
		       0xDE, 0xFF, 0xD1, 0x53, 0xE3, 0x9A, 0x7A, 0x8D,
		       0x4B, 0xD0, 0xD,	 0x9A, 0x64, 0x54, 0x1E, 0xA7};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf2);

	u8 exp3[32] = {0x80, 0xFA, 0x57, 0x25, 0xD2, 0xE9, 0x6C, 0x6,
		       0x96, 0x5C, 0x62, 0x1D, 0xF2, 0x5B, 0xD6, 0x1,
		       0x5E, 0x6A, 0xFE, 0x3B, 0x32, 0xD3, 0x49, 0xB8,
		       0xDD, 0xA2, 0xDF, 0xB0, 0x74, 0x6F, 0x4A, 0xBD};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm_next_block(&ctx, buf2);

	u8 exp4[32] = {0x8F, 0x15, 0x94, 0x6D, 0x72, 0x5C, 0xE6, 0xB4,
		       0x92, 0x79, 0xFE, 0xEF, 0x85, 0x38, 0x55, 0x21,
		       0x2E, 0x70, 0xBC, 0xD9, 0xFC, 0xF3, 0xA7, 0xDC,
		       0x4A, 0x4F, 0x9B, 0x44, 0x24, 0x75, 0x2C, 0xAA};
	ASSERT(!memcmp(buf2, exp4, sizeof(buf2)), "buf2 round2");
}

Test(rng) {
	Rng rng1;
	__attribute__((aligned(32))) u8 v[36] = {0};
	__attribute__((aligned(32))) u8 entropy[] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	__attribute__((aligned(32))) u8 k1[32] = {1};

	rng_init(&rng1, entropy);

	rng_gen(&rng1, v, 36);
	ASSERT(memcmp(v, entropy, 32), "check entropy");

	rng_reseed(&rng1, NULL);
	rng_test_seed(&rng1, k1);
}

/*
#define BIBLE_PATH "resources/test_bible.dat"

Test(bible) {
	const Bible *b;
	u64 sbox[256];
	__attribute__((aligned(32))) static const u8 input[128] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	__attribute__((aligned(32))) u8 output[32];

	if (!exists(BIBLE_PATH)) {
		b = bible_gen();
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_sbox8_64(sbox);
	bible_hash(b, input, output, sbox);

	u8 expected[32] = {0xBF, 0x3E, 0x2,  0xD6, 0xE5, 0xF5, 0x92, 0xCE,
			   0x9C, 0x1,  0xFF, 0x27, 0xA1, 0xB5, 0x5A, 0x52,
			   0xD8, 0x4,  0x72, 0xDE, 0x29, 0xF1, 0x80, 0x8E,
			   0xA0, 0xB6, 0x1C, 0x5D, 0x32, 0x95, 0xFE, 0x2E};
	ASSERT(!memcmp(output, expected, 32), "hash");
	bible_destroy(b);
	b = bible_load(BIBLE_PATH);
	bible_destroy(b);
}

Test(bible_mine) {
	const Bible *b;
	u32 nonce = 0;
	u64 sbox[256];
	__attribute__((aligned(32))) u8 output[32] = {0};
	u8 target[32];
	__attribute((aligned(32))) u8 header[HASH_INPUT_LEN];

	for (u32 i = 0; i < HASH_INPUT_LEN; i++) header[i] = i;

	if (!exists(BIBLE_PATH)) {
		b = bible_gen();
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	memset(target, 0xFF, 32);
	target[0] = 0;
	target[1] = 0;
	bible_sbox8_64(sbox);
	mine_block(b, header, target, output, &nonce, U32_MAX, sbox);

	ASSERT_EQ(nonce, 26647, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	130, 112, 151, 22,  74,	 167,
				      170, 113, 109, 27,  234, 235, 45,	 189,
				      100, 230, 166, 0,	  116, 241, 182, 57,
				      182, 170, 158, 209, 46,  165, 155, 209},
		       32),
	       "hash");
	bible_destroy(b);
}
*/
