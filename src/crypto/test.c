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

#include <libfam/aesenc.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

Test(aesenc) {
	__attribute__((aligned(32))) u8 data[32] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	__attribute__((aligned(32))) u8 key[32] = {
	    100, 200, 103, 104, 5,  6,	7,  8,	9,  10, 11, 12, 13, 14, 15, 16,
	    17,	 18,  19,  20,	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	aesenc256(data, key);

	u8 expected[] = {204, 221, 103, 39, 254, 203, 234, 91,	166, 251, 7,
			 191, 26,  157, 39, 39,	 11,  151, 54,	167, 96,  177,
			 98,  126, 236, 0,  171, 53,  98,  164, 54,  237};
	ASSERT(!memcmp(data, expected, 32), "expected");
}

Test(storm_vectors) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    9,	 93,  216, 137, 224, 212, 105, 200, 163, 28,  146,
	    246, 75,  164, 149, 109, 209, 70,  183, 116, 224, 157,
	    245, 221, 5,   53,	245, 155, 165, 135, 142, 218};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf1);

	u8 exp1[32] = {0,   44, 64, 186, 106, 113, 172, 78,  14,  234, 67,
		       247, 7,	57, 25,	 97,  57,  105, 29,  115, 159, 138,
		       37,  57, 65, 176, 12,  144, 174, 186, 4,	  236};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {251, 118, 24, 7,	  134, 162, 181, 56,  104, 171, 241,
		       102, 12,	 17, 194, 205, 73,  90,	 17,  78,  7,	206,
		       216, 90,	 46, 112, 167, 0,   220, 189, 35,  152};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf2);

	u8 exp3[32] = {76,  212, 26,  233, 216, 75,  41,  110, 6,   94,	 20,
		       169, 41,	 185, 138, 213, 219, 243, 79,  197, 109, 50,
		       141, 245, 8,   239, 144, 130, 167, 122, 21,  239};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm_next_block(&ctx, buf2);

	u8 exp4[32] = {171, 25,	 33,  63,  64,	148, 34, 113, 226, 143, 249,
		       45,  126, 243, 149, 154, 104, 67, 52,  212, 249, 62,
		       221, 50,	 108, 82,  89,	78,  32, 101, 129, 119};

	ASSERT(!memcmp(buf2, exp4, sizeof(buf2)), "buf2 round2");
}

Test(storm_cipher_vector) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute__((aligned(32))) u8 buffer1[32] = {0};
	__attribute__((aligned(32))) u8 buffer2[32] = {0};

	storm_init(&ctx, SEED);
	faststrcpy(buffer1, "test1");
	storm_xcrypt_buffer(&ctx, buffer1);
	faststrcpy(buffer2, "test2");
	storm_xcrypt_buffer(&ctx, buffer2);

	u8 expected1[32] = {208, 219, 23,  2,	102, 98,  157, 53,
			    88,	 199, 188, 237, 126, 195, 16,  183,
			    63,	 14,  194, 187, 89,  153, 201, 245,
			    3,	 242, 121, 53,	200, 243, 205, 126};
	ASSERT(!memcmp(buffer1, expected1, 32), "expected1");
	u8 expected2[32] = {122, 168, 177, 161, 78,  252, 56,  211,
			    58,	 186, 147, 163, 255, 252, 96,  14,
			    166, 29,  4,   110, 123, 47,  127, 43,
			    234, 190, 86,  201, 179, 133, 244, 82};

	/*
	for (u32 i = 0; i < 32; i++) {
		write_num(2, buffer2[i]);
		pwrite(2, ", ", 2, 0);
	}
	*/

	ASSERT(!memcmp(buffer2, expected2, 32), "expected2");
}

Test(storm_cipher) {
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

Bench(storm) {
#define STORM_COUNT (10000000000 / 32)
	static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};
	static __attribute__((aligned(32))) u8 ONE_SEED[32] = {1};
	static __attribute__((aligned(32))) u8 TWO_SEED[32] = {2};
	static __attribute__((aligned(32))) u8 THREE_SEED[32] = {3};
	static __attribute__((aligned(32))) u8 FOUR_SEED[32] = {4};
	static __attribute__((aligned(32))) u8 FIVE_SEED[32] = {5};

	i64 timer;
	__attribute__((aligned(32))) u8 buf1[64] = {0};
	__attribute__((aligned(32))) u8 buf2[64] = {0};
	__attribute__((aligned(32))) u8 buf3[64] = {0};
	__attribute__((aligned(32))) u8 buf4[64] = {0};
	__attribute__((aligned(32))) u8 buf5[64] = {0};
	__attribute__((aligned(32))) u8 buf6[64] = {0};

	StormContext ctx1;
	StormContext ctx2;
	StormContext ctx3;
	StormContext ctx4;
	StormContext ctx5;
	StormContext ctx6;

	storm_init(&ctx1, ZERO_SEED);
	storm_init(&ctx2, ONE_SEED);
	storm_init(&ctx3, TWO_SEED);
	storm_init(&ctx4, THREE_SEED);
	storm_init(&ctx5, FOUR_SEED);
	storm_init(&ctx6, FIVE_SEED);

	timer = micros();
	for (u32 i = 0; i < STORM_COUNT; i++) {
		u8* block1 = buf1 + (i & 32);
		u8* block2 = buf2 + (i & 32);
		u8* block3 = buf3 + (i & 32);
		u8* block4 = buf4 + (i & 32);
		u8* block5 = buf5 + (i & 32);
		u8* block6 = buf6 + (i & 32);

		storm_xcrypt_buffer(&ctx1, block1);
		storm_xcrypt_buffer(&ctx2, block2);
		storm_xcrypt_buffer(&ctx3, block3);
		storm_xcrypt_buffer(&ctx4, block4);
		storm_xcrypt_buffer(&ctx5, block5);
		storm_xcrypt_buffer(&ctx6, block6);
	}
	timer = micros() - timer;
	f64 secs = timer / 1000000.0;
	f64 gbps = 60.0 / secs;
	u8 gbps_str[MAX_F64_STRING_LEN] = {0};
	f64_to_string(gbps_str, gbps, 3, false);

	pwrite(2, "gbps=", 5, 0);
	pwrite(2, gbps_str, strlen(gbps_str), 0);
	pwrite(2, ",avg=", 5, 0);
	write_num(2, (timer * 1000) / STORM_COUNT);
	pwrite(2, "ns\n", 3, 0);
}

Bench(storm_longneighbors) {
	Rng rng = {0};
	__attribute__((aligned(32))) u8 a[32] = {0};
	__attribute__((aligned(32))) u8 b[32] = {0};

	rng_init(&rng);
	// rng_test_seed(&rng, ZERO_SEED);
	__attribute__((aligned(32))) u8 key[32] = {0};

	int total_fail = 0;
	int iter = 1000;

	(void)total_fail;

	for (u32 i = 0; i < iter; i++) {
		int total_tests = 0;
		int bias[256] = {0};
		for (int trial = 0; trial < 10000; ++trial) {
			StormContext ctx1, ctx2;

			storm_init(&ctx1, key);
			storm_init(&ctx2, key);
			rng_gen(&rng, a, 32);
			fastmemcpy(b, a, 32);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 32;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);
			storm_next_block(&ctx1, a);
			storm_next_block(&ctx2, b);
			u64 diff = *(u64*)a ^ *(u64*)b;
			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[bit]++;
				}
			}
			diff = *(u64*)(a + 8) ^ *(u64*)(b + 8);
			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[64 + bit]++;
				}
			}

			diff = *(u64*)(a + 16) ^ *(u64*)(b + 16);
			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[128 + bit]++;
				}
			}

			diff = *(u64*)((u8*)a + 24) ^ *(u64*)((u8*)b + 24);
			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[192 + bit]++;
				}
			}

			total_tests++;
		}

		int failed = 0;
		for (int bit = 0; bit < 256; ++bit) {
			f64 p = 100.0 * bias[bit] / total_tests;
			if (p < 48.0 || p > 52.0) {
				failed++;
			}
		}

		total_fail += (failed != 0);
		(void)total_tests;
	}

	f64 fail_perc = (100.0 * total_fail) / (iter * 4);
	u8 fail_str[MAX_F64_STRING_LEN] = {0};
	f64_to_string(fail_str, fail_perc, 3, false);
	pwrite(2, "fail_rate=", 10, 0);
	pwrite(2, fail_str, strlen(fail_str), 0);
	pwrite(2, "%\n", 2, 0);
}

