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
#include <libfam/aighthash.h>
#include <libfam/bible.h>
#include <libfam/env.h>
#include <libfam/kem.h>
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/sign.h>
#include <libfam/storm.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>
#include <libfam/wots.h>

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
			if (p < 47.8 || p > 52.2) failed++;
		}

		total_fail += (failed != 0);
		(void)total_tests;
	}

	f64 fail_perc = (100.0 * total_fail) / iter;
	u8 fail_str[MAX_F64_STRING_LEN] = {0};
	f64_to_string(fail_str, fail_perc, 3, false);
	pwrite(2, "fail_rate=", 10, 0);
	pwrite(2, fail_str, strlen(fail_str), 0);
	pwrite(2, "%\n", 2, 0);
}

Bench(aighthash_longneighbors) {
	Rng rng = {0};
	__attribute__((aligned(32))) u8 a[8192] = {0};
	__attribute__((aligned(32))) u8 b[8192] = {0};

	rng_init(&rng);

	int total_fail = 0;
	int iter = 100;

	(void)total_fail;

	for (u32 i = 0; i < iter; i++) {
		int total_tests = 0;
		int bias[64] = {0};
		for (int trial = 0; trial < 10000; ++trial) {
			rng_gen(&rng, a, 8192);
			fastmemcpy(b, a, 8192);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 8192;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);

			u64 v1 = aighthash64(a, 8192, 0);
			u64 v2 = aighthash64(b, 8192, 0);
			u64 diff = v1 ^ v2;
			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[bit]++;
				}
			}

			total_tests++;
		}

		int failed = 0;
		for (int bit = 0; bit < 64; ++bit) {
			f64 p = 100.0 * bias[bit] / total_tests;
			if (p < 48.2 || p > 51.8) failed++;
		}

		total_fail += (failed != 0);
		(void)total_tests;
	}
	f64 fail_perc = (100.0 * total_fail) / (iter);
	u8 fail_str[MAX_F64_STRING_LEN] = {0};
	f64_to_string(fail_str, fail_perc, 3, false);
	pwrite(2, "fail_rate=", 10, 0);
	pwrite(2, fail_str, strlen(fail_str), 0);
	pwrite(2, "%\n", 2, 0);
}

#define COUNT (1024 * 1024)
#define SIZE 8192

Bench(aighthash) {
	Rng rng;
	__attribute__((aligned(32))) u8 text[SIZE] = {0};
	u64* v = (void*)text;
	u32 sum = 0;
	u64 cycle_sum = 0;

	rng_init(&rng);

	for (u32 i = 0; i < COUNT; i++) {
		u64 r, timer;
		rng_gen(&rng, text, SIZE);
		timer = cycle_counter();
		r = aighthash64(text, SIZE, 0);
		cycle_sum += cycle_counter() - timer;
		(*v)++;
		sum += r;
	}
	pwrite(2, "cycles=", 7, 0);
	write_num(2, cycle_sum);
	pwrite(2, ",sum=", 5, 0);
	write_num(2, sum);
	pwrite(2, "\n", 1, 0);
}

Test(aighthash_vector) {
	u8 vector[1024] = {0};
	u64 r;
	for (u32 i = 0; i < 1024; i++) vector[i] = i % 256;
	r = aighthash64(vector, 1024, 0);
	ASSERT_EQ(r, 17797804553278143541ULL, "vector1");
	r = aighthash64(vector, 1024, 1);
	ASSERT_EQ(r, 10881699377260999209ULL, "vector2");
}

Test(aighthash) {
	u64 h1, h2, h3;

	h1 = aighthash64("XXXXXXXXXXXXXXXXxyz", 19, 0);
	h2 = aighthash64("XXXXXXXXXXXXXXXXxyz\0", 20, 0);
	h3 = aighthash64("XXXXXXXXXXXXXXXXxyz", 19, 0);
	ASSERT(h1 != h2, "h1 != h2");
	ASSERT(h1 == h3, "h1 == h3");

	h1 = aighthash64("012345678901234567890123456789012", 32, 0);
	h2 = aighthash64("012345678901234567890123456789012\0", 33, 0);
	h3 = aighthash64("012345678901234567890123456789012", 32, 0);
	ASSERT(h1 != h2, "h1 != h2");
	ASSERT(h1 == h3, "h1 == h3");
}

Test(rng) {
	u64 x = 0, y = 0;
	__attribute__((aligned(32))) u8 z[64] = {0};
	Rng rng;
	__attribute__((aligned(32))) u8 key[32] = {5, 5, 5, 5};
	rng_init(&rng);
	rng_gen(&rng, &x, sizeof(x));
	rng_init(&rng);
	rng_gen(&rng, &y, sizeof(y));
	ASSERT(x != y, "x!=y");

	rng_test_seed(&rng, key);
	rng_gen(&rng, z, sizeof(z));

	u8 expected[64] = {
	    241, 172, 79,  71,	20,  35,  84,  2,   39,	 165, 18,  232, 21,
	    84,	 178, 57,  205, 39,  187, 146, 20,  199, 114, 41,  245, 137,
	    175, 6,   181, 187, 130, 62,  132, 84,  126, 222, 37,  132, 105,
	    219, 163, 233, 140, 146, 144, 123, 56,  27,	 226, 203, 36,	30,
	    42,	 31,  252, 121, 105, 163, 164, 166, 16,	 128, 80,  195};
	ASSERT_EQ(memcmp(z, expected, 64), 0, "z");
}

#define RNG_BYTES (32 * 1000000ULL)

Bench(rng) {
	u8 fbuf[1024] = {0};
	__attribute__((aligned(32))) u8 buffer1[32] = {0};
	__attribute__((aligned(32))) u8 buffer2[32] = {0};
	__attribute__((aligned(32))) u8 buffer3[32] = {0};
	__attribute__((aligned(32))) u8 buffer4[32] = {0};
	__attribute__((aligned(32))) u8 buffer5[32] = {0};
	__attribute__((aligned(32))) u8 buffer6[32] = {0};

	i64 needed = RNG_BYTES;
	Rng rng1, rng2, rng3, rng4, rng5, rng6;
	u64 total_cycles = 0;

	rng_init(&rng1);
	rng_init(&rng2);
	rng_init(&rng3);
	rng_init(&rng4);
	rng_init(&rng5);
	rng_init(&rng6);

	while (needed > 0) {
		u64 start;
		start = cycle_counter();
		rng_gen(&rng1, buffer1, 32);
		rng_gen(&rng2, buffer2, 32);
		rng_gen(&rng3, buffer3, 32);
		rng_gen(&rng4, buffer4, 32);
		rng_gen(&rng5, buffer5, 32);
		rng_gen(&rng6, buffer6, 32);
		total_cycles += cycle_counter() - start;

		needed -= 32;
	}
	const u8 msg[] = "cycles_per_byte=";
	pwrite(2, msg, strlen(msg), 0);
	f64_to_string(fbuf,
		      (f64)(total_cycles * 100 / (6 * RNG_BYTES)) / (f64)100, 2,
		      false);
	pwrite(2, fbuf, strlen(fbuf), 0);
	pwrite(2, "\n", 1, 0);
}

Test(wots) {
	__attribute__((aligned(32))) u8 key[32] = {1, 2, 3, 4, 5};
	WotsPubKey pk;
	WotsSecKey sk;
	WotsSig sig;
	u8 msg[32] = {9, 9, 9, 9, 9, 4};

	wots_keyfrom(key, &pk, &sk);
	wots_sign(&sk, msg, &sig);
	ASSERT(!wots_verify(&pk, &sig, msg), "verify");
	msg[0]++;
	ASSERT(wots_verify(&pk, &sig, msg), "!verify");
}

#define WOTS_COUNT 1000

Bench(wotsp) {
	__attribute__((aligned(32))) u8 key[32] = {0};
	__attribute__((aligned(32))) u8 msg[32] = {0};
	WotsPubKey pk;
	WotsSecKey sk;
	WotsSig sig;

	Rng rng;
	u64 keygen_sum = 0;
	u64 sign_sum = 0;
	u64 verify_sum = 0;

	rng_init(&rng);

	for (u32 i = 0; i < WOTS_COUNT; i++) {
		rng_gen(&rng, key, 32);
		rng_gen(&rng, msg, 32);

		u64 start = cycle_counter();
		wots_keyfrom(key, &pk, &sk);
		keygen_sum += cycle_counter() - start;
		start = cycle_counter();
		wots_sign(&sk, msg, &sig);
		sign_sum += cycle_counter() - start;
		start = cycle_counter();
		i32 res = wots_verify(&pk, &sig, msg);
		verify_sum += cycle_counter() - start;
		ASSERT(!res, "verify");
		msg[0]++;
		ASSERT(wots_verify(&pk, &sig, msg), "!verify");
	}
	pwrite(2, "keygen=", 7, 0);
	write_num(2, keygen_sum / WOTS_COUNT);
	pwrite(2, ",sign=", 6, 0);
	write_num(2, sign_sum / WOTS_COUNT);
	pwrite(2, ",verify=", 8, 0);
	write_num(2, verify_sum / WOTS_COUNT);
	pwrite(2, "\n", 1, 0);
}

#define BIBLE_PATH "resources/test_bible.dat"

Test(bible) {
	const Bible* b;
	u64 sbox[256];
	__attribute__((aligned(32))) static const u8 input[128] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	__attribute__((aligned(32))) u8 output[32];

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(false);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_sbox8_64(sbox);
	bible_hash(b, input, output, sbox);

	u8 expected[32] = {222, 244, 143, 174, 216, 100, 54, 26,  244, 218, 190,
			   252, 148, 64,  106, 67,  107, 40, 178, 224, 103, 235,
			   92,	138, 72,  8,   20,  178, 69, 165, 100, 231};

	ASSERT(!memcmp(output, expected, 32), "hash");
	bible_destroy(b);
	b = bible_load(BIBLE_PATH);
	bible_destroy(b);
}

Test(bible_mine) {
	const Bible* b;
	u32 nonce = 0;
	u64 sbox[256];
	__attribute__((aligned(32))) u8 output[32] = {0};
	u8 target[32];
	__attribute((aligned(32))) u8 header[HASH_INPUT_LEN];

	for (u32 i = 0; i < HASH_INPUT_LEN; i++) header[i] = i;

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(false);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	memset(target, 0xFF, 32);
	target[0] = 0;
	target[1] = 0;
	bible_sbox8_64(sbox);
	mine_block(b, header, target, output, &nonce, U32_MAX, sbox);

	ASSERT_EQ(nonce, 68994, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	245, 95,  148, 134, 208, 252,
				      26,  201, 67,  172, 120, 76,  64,	 169,
				      199, 139, 61,  202, 241, 114, 3,	 35,
				      238, 133, 153, 157, 124, 93,  210, 215},
		       32),
	       "hash");
	bible_destroy(b);
}

Test(kem) {
	KemSecKey sk;
	KemPubKey pk;
	KemCipherText ct;
	KemSharedSecret ss_bob = {0}, ss_alice = {0};

	Rng rng1, rng2;
	rng_init(&rng1);
	rng_init(&rng2);
	keypair(&pk, &sk, &rng1);
	enc(&ct, &ss_bob, &pk, &rng2);
	dec(&ss_alice, &ct, &sk);
	ASSERT(!fastmemcmp(&ss_bob, &ss_alice, KEM_SS_SIZE), "shared secret");
}

Test(kem_iter) {
	KemSecKey sk;
	KemPubKey pk;
	KemCipherText ct;
	KemSharedSecret ss_bob = {0}, ss_alice = {0};
	Rng rng1, rng2;

	for (u32 i = 0; i < 1000; i++) {
		rng_init(&rng1);
		rng_init(&rng2);

		keypair(&pk, &sk, &rng1);
		enc(&ct, &ss_bob, &pk, &rng2);
		dec(&ss_alice, &ct, &sk);
		ASSERT(!fastmemcmp(&ss_bob, &ss_alice, KEM_SS_SIZE),
		       "shared secret");
	}
}

#define KEM_COUNT 10000

Bench(kempf) {
	KemSecKey sk;
	KemPubKey pk;
	KemCipherText ct;
	KemSharedSecret ss_bob = {0}, ss_alice = {0};
	Rng rng1, rng2;
	u64 keygen_sum = 0;
	u64 enc_sum = 0;
	u64 dec_sum = 0;

	for (u32 i = 0; i < KEM_COUNT; i++) {
		rng_init(&rng1);
		rng_init(&rng2);

		u64 start = cycle_counter();
		keypair(&pk, &sk, &rng1);
		keygen_sum += cycle_counter() - start;
		start = cycle_counter();
		enc(&ct, &ss_bob, &pk, &rng2);
		enc_sum += cycle_counter() - start;
		start = cycle_counter();
		dec(&ss_alice, &ct, &sk);
		dec_sum += cycle_counter() - start;
		ASSERT(!fastmemcmp(&ss_bob, &ss_alice, KEM_SS_SIZE),
		       "shared secret");
	}

	pwrite(2, "keygen=", 7, 0);
	write_num(2, keygen_sum / KEM_COUNT);
	pwrite(2, ",enc=", 5, 0);
	write_num(2, enc_sum / KEM_COUNT);
	pwrite(2, ",dec=", 5, 0);
	write_num(2, dec_sum / KEM_COUNT);
	pwrite(2, "\n", 1, 0);
}

Test(kem_vector) {
	__attribute__((aligned(32))) u8 seed[32] = {1, 2, 3};
	KemSecKey sk;
	KemPubKey pk;
	KemCipherText ct;
	KemSharedSecret ss_bob = {0}, ss_alice = {0};

	Rng rng;
	rng_init(&rng);
	rng_test_seed(&rng, seed);
	keypair(&pk, &sk, &rng);
	// print("pk: ");
	// for (u32 i = 0; i < sizeof(pk); i++) print("{}, ", pk.data[i]);
	u8 expected_sk[] = {
	    165, 19,  90,  74,	176, 27,  103, 182, 14,	 159, 12,  174, 250,
	    224, 61,  187, 99,	12,  205, 183, 182, 132, 136, 52,  81,	42,
	    138, 179, 177, 177, 196, 70,  134, 75,  17,	 136, 223, 18,	72,
	    101, 156, 179, 106, 101, 168, 241, 102, 130, 171, 71,  185, 161,
	    133, 4,   184, 24,	37,  8,	  164, 39,  183, 226, 115, 87,	58,
	    199, 63,  164, 205, 212, 44,  4,   70,  97,	 105, 158, 40,	5,
	    56,	 35,  11,  156, 132, 93,  137, 229, 87,	 246, 132, 158, 21,
	    200, 151, 64,  74,	122, 57,  17,  170, 136, 184, 38,  103, 250,
	    51,	 171, 183, 189, 190, 180, 115, 103, 252, 205, 121, 99,	110,
	    2,	 248, 91,  104, 214, 84,  197, 171, 55,	 66,  236, 46,	162,
	    43,	 122, 207, 128, 92,  224, 155, 204, 50,	 32,  107, 82,	88,
	    206, 223, 171, 46,	160, 251, 128, 33,  53,	 181, 53,  23,	174,
	    123, 34,  145, 78,	0,   137, 190, 128, 81,	 184, 225, 60,	92,
	    245, 121, 33,  99,	172, 100, 217, 124, 145, 138, 13,  53,	39,
	    102, 196, 105, 92,	255, 214, 78,  102, 149, 181, 252, 147, 42,
	    122, 241, 10,  95,	58,  205, 96,  55,  207, 234, 152, 184, 2,
	    199, 160, 88,  198, 64,  47,  25,  201, 72,	 151, 207, 239, 161,
	    61,	 149, 170, 119, 158, 200, 181, 39,  147, 19,  35,  165, 52,
	    96,	 153, 15,  76,	151, 136, 28,  102, 21,	 137, 133, 133, 205,
	    201, 63,  154, 144, 89,  242, 224, 191, 137, 50,  43,  72,	236,
	    198, 26,  124, 198, 46,  36,  177, 101, 96,	 93,  121, 165, 206,
	    133, 32,  67,  7,	97,  36,  196, 0,   3,	 212, 130, 153, 46,
	    116, 64,  133, 129, 119, 226, 32,  184, 232, 167, 57,  147, 137,
	    101, 104, 60,  97,	135, 115, 37,  168, 247, 26,  128, 1,	200,
	    8,	 214, 206, 113, 67,  57,  249, 162, 82,	 85,  26,  186, 132,
	    36,	 52,  208, 230, 189, 200, 128, 47,  189, 1,   12,  79,	145,
	    52,	 88,  133, 37,	194, 242, 11,  92,  176, 206, 103, 43,	1,
	    230, 57,  145, 161, 170, 145, 174, 119, 121, 144, 22,  78,	12,
	    183, 105, 222, 165, 41,  141, 229, 204, 231, 5,   160, 60,	72,
	    140, 158, 182, 185, 41,  64,  205, 251, 80,	 43,  203, 212, 136,
	    25,	 84,  163, 71,	21,  74,  106, 105, 108, 164, 164, 48,	79,
	    177, 16,  113, 163, 83,  17,  177, 177, 251, 203, 189, 193, 188,
	    6,	 161, 232, 106, 155, 217, 156, 185, 202, 170, 240, 103, 112,
	    55,	 246, 199, 0,	2,   92,  69,  9,   176, 111, 163, 4,	103,
	    32,	 31,  204, 88,	106, 80,  226, 207, 250, 130, 30,  21,	121,
	    32,	 114, 218, 11,	147, 103, 121, 76,  136, 53,  229, 128, 87,
	    3,	 69,  76,  153, 192, 109, 223, 16,  54,	 18,  24,  53,	247,
	    74,	 134, 255, 201, 54,  148, 4,   19,  19,	 113, 131, 33,	193,
	    19,	 210, 66,  132, 182, 186, 150, 192, 32,	 163, 220, 75,	102,
	    146, 96,  165, 164, 154, 50,  214, 196, 105, 1,   119, 182, 50,
	    130, 155, 128, 145, 203, 53,  152, 58,  169, 246, 6,   47,	231,
	    58,	 74,  236, 77,	16,  52,  63,  150, 42,	 38,  200, 195, 115,
	    255, 137, 68,  201, 39,  87,  50,  75,  163, 185, 150, 179, 184,
	    250, 50,  102, 129, 12,  94,  216, 197, 198, 166, 13,  146, 213,
	    123, 201, 219, 164, 166, 251, 43,  164, 211, 24,  183, 218, 173,
	    148, 136, 177, 208, 107, 153, 240, 70,  120, 180, 200, 114, 251,
	    54,	 203, 150, 35,	122, 211, 197, 147, 178, 167, 83,  175, 0,
	    131, 91,  228, 30,	77,  104, 56,  211, 169, 4,   219, 83,	61,
	    118, 249, 61,  85,	117, 42,  93,  228, 52,	 114, 11,  116, 81,
	    214, 35,  236, 182, 50,  196, 248, 165, 148, 220, 25,  239, 106,
	    110, 129, 160, 63,	25,  187, 112, 105, 192, 59,  156, 81,	95,
	    180, 65,  14,  251, 67,  84,  233, 219, 44,	 105, 208, 184, 111,
	    163, 165, 14,  27,	140, 157, 105, 96,  213, 148, 117, 67,	123,
	    106, 50,  49,  57,	171, 69,  40,  70,  176, 106, 83,  86,	10,
	    222, 168, 55,  2,	85,  101, 93,  106, 59,	 51,  215, 156, 119,
	    162, 118, 226, 104, 112, 104, 209, 137, 177, 171, 151, 222, 51,
	    57,	 118, 196, 71,	101, 2,	  151, 45,  38,	 124, 78,  112, 48,
	    221, 228, 132, 44,	115, 45,  47,  103, 189, 167, 182, 185, 138,
	    167, 127, 107, 103, 32,  203, 86,  207, 223, 16,  127, 3,	5,
	    199, 122, 228, 185, 192, 146, 1,   171, 23,	 173, 172, 160, 174,
	    192, 85,  73,  168, 16,  150, 197, 36,  14,	 157, 91,  130, 176,
	    178, 41,  126, 89,	190, 26,  171, 72,  201, 28,  106, 155, 58,
	    39,	 21,  153, 163, 221, 118, 124, 253, 149, 137, 52,  100, 52,
	    211, 74,  48,  105, 248, 67,  160, 85,  203, 44,  114, 81,	137,
	    242, 191, 32,  176, 112, 160, 51,  85,  121, 113, 100, 40,	50,
	    193, 198, 103, 201, 12,  113, 181, 3,   84,	 42,  248, 155, 139,
	    20,	 210, 117, 234, 201, 196, 64,  41,  84,	 163, 82,  42,	174,
	    99,	 134, 226, 101, 108, 56,  99,  104, 68,	 36,  34,  27,	5,
	    12,	 145, 131, 168, 64,  164, 176, 69,  170, 128, 195, 119, 87,
	    101, 209, 46,  235, 124, 106, 22,  50,  132, 8,   102, 95,	119,
	    41,	 37,  43,  44,	67,  73,  19,  15,  129, 241, 163, 160, 107,
	    127, 156, 184, 80,	73,  180, 136, 12,  148, 70,  103, 122, 41,
	    133, 48,  149, 236, 119, 84,  153, 16,  85,	 244, 149, 156, 128,
	    197, 138, 218, 245, 60,  211, 204, 99,  149, 197, 199, 60,	52,
	    101, 52,  153, 110, 215, 20,  127, 34,  135, 103, 80,  137, 161,
	    35,	 32,  168, 158, 90,  93,  88,  229, 113, 100, 234, 143, 196,
	    10,	 101, 182, 26,	91,  240, 243, 118, 226, 118, 207, 44,	26,
	    196, 102, 144, 160, 88,  82,  139, 141, 147, 58,  243, 48,	0,
	    21,	 88,  117, 128, 65,  135, 119, 87,  193, 87,  75,  195, 64,
	    56,	 168, 172, 169, 24,  14,  34,  199, 52,	 226, 153, 176, 91,
	    62,	 212, 235, 69,	120, 188, 195, 230, 117, 39,  69,  0,	143,
	    136, 181, 126, 111, 181, 31,  168, 114, 91,	 65,  248, 86,	237,
	    124, 6,   247, 146, 70,  207, 177, 86,  128, 6,   185, 95,	163,
	    71,	 161, 97,  157, 214, 92,  168, 115, 145, 68,  49,  51,	3,
	    125, 106, 88,  226, 70,  200, 183, 235, 184, 17,  214, 123, 254,
	    82,	 152, 157, 154, 129, 137, 121, 90,  173, 89,  101, 236, 83,
	    35,	 230, 121, 124, 69,  218, 173, 164, 149, 164, 154, 73,	32,
	    206, 99,  165, 229, 241, 117, 171, 91,  95,	 243, 59,  133, 210,
	    208, 111, 224, 70,	143, 229, 252, 138, 46,	 60,  3,   218, 6,
	    36,	 170, 165, 185, 247, 129, 60,  139, 11,	 165, 156, 48,	63,
	    38,	 198, 37,  241, 229, 80,  235, 241, 100, 11,  34,  128, 197,
	    97,	 166, 191, 122, 89,  105, 74,  204, 119, 4,   73,  119, 68,
	    58,	 86,  89,  179, 51,  17,  94,  132, 156, 168, 146, 86,	41,
	    29,	 193, 75,  208, 97,  109, 59,  98,  30,	 204, 6,   159, 155,
	    83,	 121, 171, 18,	12,  191, 32,  33,  23,	 119, 87,  27,	118,
	    93,	 30,  134, 132, 120, 101, 112, 102, 202, 0,   143, 244, 202,
	    190, 42,  207, 19,	54,  33,  206, 209, 18,	 210, 163, 44,	57,
	    243, 52,  5,   200, 44,  243, 148, 160, 9,	 246, 2,   142, 51,
	    186, 11,  102, 57,	20,  160, 146, 252, 199, 156, 186, 118, 161,
	    54,	 67,  179, 165, 244, 83,  93,  179, 19,	 180, 160, 200, 79,
	    102, 193, 201, 182, 166, 31,  129, 139, 38,	 12,  20,  171, 51,
	    60,	 139, 98,  180, 176, 67,  10,  27,  27,	 72,  113, 5,	97,
	    121, 28,  172, 98,	209, 188, 80,  201, 65,	 99,  194, 187, 224,
	    249, 79,  95,  212, 203, 252, 243, 26,  186, 252, 175, 151, 118,
	    97,	 155, 87,  120, 249, 71,  81,  92,  103, 5,   73,  161, 122,
	    37,	 136, 100, 230, 164, 164, 160, 156, 140, 36,  88,  161, 171,
	    68,	 85,  207, 160, 81,  132, 40,  171, 202, 242, 37,  29,	162,
	    205, 229, 80,  119, 14,  128, 201, 185, 22,	 175, 109, 167, 75,
	    40,	 244, 97,  44,	130, 34,  9,   22,  104, 220, 97,  29,	212,
	    231, 90,  44,  38,	94,  154, 202, 147, 136, 208, 10,  101, 123,
	    16,	 212, 101, 53,	139, 240, 108, 40,  99,	 168, 84,  16,	35,
	    29,	 184, 132, 64,	185, 145, 9,   176, 151, 102, 243, 115, 125,
	    42,	 14,  62,  179, 50,  22,  133, 174, 179, 218, 182, 196, 251,
	    116, 171, 3,   140, 23,  32,  24,  238, 59,	 106, 21,  81,	69,
	    159, 121, 11,  6,	50,  5,	  0,   236, 84,	 251, 115, 73,	63,
	    155, 50,  75,  213, 98,  129, 85,  129, 163, 26,  79,  38,	73,
	    25,	 162, 153, 23,	191, 139, 137, 4,   97,	 143, 228, 244, 45,
	    22,	 19,  119, 237, 58,  178, 165, 227, 39,	 57,  245, 100, 85,
	    23,	 58,  250, 30,	19,  136, 6,   35,  19,	 153, 114, 61,	42,
	    183, 70,  185, 223, 50,  0,	  13,  111, 183, 61,  118, 47,	189,
	    227, 89,  26,  152, 245, 247, 226, 81,  248, 42,  20,  51,	181,
	    193, 202, 151, 26,	47,  133, 73,  220, 137, 226, 109, 237, 244,
	    4,	 53,  237, 111, 38,  137, 77,  119, 97,	 59,  9,   215, 69,
	    58,	 192, 116, 83,	197, 110, 27,  236, 162, 217, 187, 31,	127,
	    6,	 241, 183, 237, 108, 237, 8,   120, 98,	 1,   193, 234, 24,
	    1,	 155, 246, 12,	197, 174, 171};

	u8 expected_pk[] = {
	    122, 228, 185, 192, 146, 1,	  171, 23,  173, 172, 160, 174, 192,
	    85,	 73,  168, 16,	150, 197, 36,  14,  157, 91,  130, 176, 178,
	    41,	 126, 89,  190, 26,  171, 72,  201, 28,	 106, 155, 58,	39,
	    21,	 153, 163, 221, 118, 124, 253, 149, 137, 52,  100, 52,	211,
	    74,	 48,  105, 248, 67,  160, 85,  203, 44,	 114, 81,  137, 242,
	    191, 32,  176, 112, 160, 51,  85,  121, 113, 100, 40,  50,	193,
	    198, 103, 201, 12,	113, 181, 3,   84,  42,	 248, 155, 139, 20,
	    210, 117, 234, 201, 196, 64,  41,  84,  163, 82,  42,  174, 99,
	    134, 226, 101, 108, 56,  99,  104, 68,  36,	 34,  27,  5,	12,
	    145, 131, 168, 64,	164, 176, 69,  170, 128, 195, 119, 87,	101,
	    209, 46,  235, 124, 106, 22,  50,  132, 8,	 102, 95,  119, 41,
	    37,	 43,  44,  67,	73,  19,  15,  129, 241, 163, 160, 107, 127,
	    156, 184, 80,  73,	180, 136, 12,  148, 70,	 103, 122, 41,	133,
	    48,	 149, 236, 119, 84,  153, 16,  85,  244, 149, 156, 128, 197,
	    138, 218, 245, 60,	211, 204, 99,  149, 197, 199, 60,  52,	101,
	    52,	 153, 110, 215, 20,  127, 34,  135, 103, 80,  137, 161, 35,
	    32,	 168, 158, 90,	93,  88,  229, 113, 100, 234, 143, 196, 10,
	    101, 182, 26,  91,	240, 243, 118, 226, 118, 207, 44,  26,	196,
	    102, 144, 160, 88,	82,  139, 141, 147, 58,	 243, 48,  0,	21,
	    88,	 117, 128, 65,	135, 119, 87,  193, 87,	 75,  195, 64,	56,
	    168, 172, 169, 24,	14,  34,  199, 52,  226, 153, 176, 91,	62,
	    212, 235, 69,  120, 188, 195, 230, 117, 39,	 69,  0,   143, 136,
	    181, 126, 111, 181, 31,  168, 114, 91,  65,	 248, 86,  237, 124,
	    6,	 247, 146, 70,	207, 177, 86,  128, 6,	 185, 95,  163, 71,
	    161, 97,  157, 214, 92,  168, 115, 145, 68,	 49,  51,  3,	125,
	    106, 88,  226, 70,	200, 183, 235, 184, 17,	 214, 123, 254, 82,
	    152, 157, 154, 129, 137, 121, 90,  173, 89,	 101, 236, 83,	35,
	    230, 121, 124, 69,	218, 173, 164, 149, 164, 154, 73,  32,	206,
	    99,	 165, 229, 241, 117, 171, 91,  95,  243, 59,  133, 210, 208,
	    111, 224, 70,  143, 229, 252, 138, 46,  60,	 3,   218, 6,	36,
	    170, 165, 185, 247, 129, 60,  139, 11,  165, 156, 48,  63,	38,
	    198, 37,  241, 229, 80,  235, 241, 100, 11,	 34,  128, 197, 97,
	    166, 191, 122, 89,	105, 74,  204, 119, 4,	 73,  119, 68,	58,
	    86,	 89,  179, 51,	17,  94,  132, 156, 168, 146, 86,  41,	29,
	    193, 75,  208, 97,	109, 59,  98,  30,  204, 6,   159, 155, 83,
	    121, 171, 18,  12,	191, 32,  33,  23,  119, 87,  27,  118, 93,
	    30,	 134, 132, 120, 101, 112, 102, 202, 0,	 143, 244, 202, 190,
	    42,	 207, 19,  54,	33,  206, 209, 18,  210, 163, 44,  57,	243,
	    52,	 5,   200, 44,	243, 148, 160, 9,   246, 2,   142, 51,	186,
	    11,	 102, 57,  20,	160, 146, 252, 199, 156, 186, 118, 161, 54,
	    67,	 179, 165, 244, 83,  93,  179, 19,  180, 160, 200, 79,	102,
	    193, 201, 182, 166, 31,  129, 139, 38,  12,	 20,  171, 51,	60,
	    139, 98,  180, 176, 67,  10,  27,  27,  72,	 113, 5,   97,	121,
	    28,	 172, 98,  209, 188, 80,  201, 65,  99,	 194, 187, 224, 249,
	    79,	 95,  212, 203, 252, 243, 26,  186, 252, 175, 151, 118, 97,
	    155, 87,  120, 249, 71,  81,  92,  103, 5,	 73,  161, 122, 37,
	    136, 100, 230, 164, 164, 160, 156, 140, 36,	 88,  161, 171, 68,
	    85,	 207, 160, 81,	132, 40,  171, 202, 242, 37,  29,  162, 205,
	    229, 80,  119, 14,	128, 201, 185, 22,  175, 109, 167, 75,	40,
	    244, 97,  44,  130, 34,  9,	  22,  104, 220, 97,  29,  212, 231,
	    90,	 44,  38,  94,	154, 202, 147, 136, 208, 10,  101, 123, 16,
	    212, 101, 53,  139, 240, 108, 40,  99,  168, 84,  16,  35,	29,
	    184, 132, 64,  185, 145, 9,	  176, 151, 102, 243, 115, 125, 42,
	    14,	 62,  179, 50,	22,  133, 174, 179, 218, 182, 196, 251, 116,
	    171, 3,   140, 23,	32,  24,  238, 59,  106, 21,  81,  69,	159,
	    121, 11,  6,   50,	5,   0,	  236, 84,  251, 115, 73,  63,	155,
	    50,	 75,  213, 98,	129, 85,  129, 163, 26,	 79,  38,  73,	25,
	    162, 153, 23,  191, 139, 137, 4,   97,  143, 228, 244, 45,	22,
	    19,	 119, 237, 58,	178, 165, 227, 39,  57,	 245, 100, 85,	23,
	    58,	 250, 30,  19,	136, 6,	  35,  19,  153, 114, 61,  42,	183,
	    70,	 185, 223, 50,	0,   13,  111, 183, 61,	 118, 47,  189, 227,
	    89,	 26,  152, 245, 247, 226, 81};

	ASSERT(!fastmemcmp(pk.data, expected_pk, sizeof(pk)), "pk");
	ASSERT(!fastmemcmp(sk.data, expected_sk, sizeof(sk)), "sk");
	enc(&ct, &ss_bob, &pk, &rng);
	u8 expected_ct[] = {
	    108, 65,  248, 7,	207, 148, 27,  195, 46,	 228, 97,  63,	192,
	    33,	 40,  81,  135, 175, 99,  101, 175, 50,	 198, 54,  75,	106,
	    60,	 41,  192, 41,	195, 183, 101, 239, 104, 193, 56,  128, 236,
	    84,	 148, 211, 64,	214, 240, 8,   23,  101, 93,  113, 246, 31,
	    212, 61,  119, 8,	244, 153, 197, 139, 255, 23,  26,  12,	232,
	    18,	 117, 202, 200, 252, 175, 220, 103, 227, 142, 16,  33,	37,
	    67,	 44,  38,  92,	205, 80,  60,  244, 113, 137, 233, 128, 121,
	    128, 96,  206, 95,	34,  210, 215, 204, 176, 53,  33,  137, 238,
	    174, 30,  228, 4,	198, 69,  176, 225, 149, 49,  194, 98,	174,
	    214, 209, 22,  243, 241, 66,  38,  211, 230, 52,  126, 172, 14,
	    88,	 203, 29,  45,	191, 110, 161, 102, 60,	 129, 18,  218, 24,
	    118, 125, 59,  234, 190, 93,  201, 232, 41,	 253, 79,  211, 138,
	    64,	 232, 48,  122, 119, 118, 46,  194, 194, 3,   66,  158, 200,
	    71,	 171, 36,  181, 131, 139, 205, 101, 68,	 101, 72,  195, 118,
	    59,	 71,  142, 209, 170, 65,  106, 208, 145, 16,  12,  238, 22,
	    194, 167, 243, 110, 20,  169, 132, 231, 162, 134, 151, 143, 190,
	    190, 121, 0,   34,	221, 154, 112, 122, 24,	 11,  217, 86,	10,
	    120, 141, 140, 107, 108, 185, 2,   180, 34,	 170, 161, 204, 176,
	    252, 203, 64,  33,	220, 25,  96,  16,  62,	 63,  149, 122, 132,
	    140, 44,  19,  107, 131, 26,  110, 213, 217, 95,  166, 108, 29,
	    16,	 55,  225, 176, 76,  100, 206, 17,  57,	 195, 24,  76,	149,
	    169, 227, 178, 10,	124, 39,  13,  204, 210, 196, 166, 168, 17,
	    47,	 36,  77,  12,	55,  188, 222, 145, 209, 168, 57,  65,	195,
	    97,	 136, 163, 187, 30,  159, 151, 255, 12,	 192, 183, 161, 10,
	    2,	 238, 105, 9,	224, 10,  107, 192, 195, 52,  13,  62,	92,
	    34,	 174, 46,  86,	173, 247, 204, 24,  7,	 112, 255, 68,	142,
	    244, 48,  67,  229, 43,  57,  238, 195, 214, 104, 234, 81,	172,
	    247, 17,  203, 50,	172, 163, 186, 196, 173, 109, 5,   103, 232,
	    92,	 85,  149, 12,	41,  47,  71,  199, 213, 117, 87,  180, 156,
	    123, 13,  76,  218, 65,  121, 45,  112, 61,	 104, 224, 206, 178,
	    95,	 236, 25,  60,	216, 29,  141, 236, 156, 181, 135, 198, 234,
	    26,	 219, 180, 190, 251, 243, 55,  186, 195, 79,  109, 180, 104,
	    194, 23,  196, 198, 34,  210, 89,  2,   49,	 39,  53,  137, 65,
	    120, 57,  154, 63,	121, 143, 85,  29,  245, 9,   213, 72,	4,
	    15,	 93,  82,  169, 157, 175, 31,  196, 37,	 36,  238, 105, 215,
	    2,	 239, 169, 107, 191, 203, 255, 139, 92,	 168, 26,  3,	236,
	    69,	 44,  7,   152, 214, 226, 33,  51,  240, 49,  26,  211, 216,
	    165, 125, 156, 24,	233, 198, 198, 30,  27,	 226, 88,  153, 67,
	    155, 237, 148, 36,	83,  200, 241, 164, 221, 185, 16,  223, 125,
	    158, 176, 159, 33,	16,  168, 45,  148, 77,	 23,  169, 85,	203,
	    143, 193, 55,  215, 255, 38,  216, 68,  33,	 144, 81,  201, 11,
	    203, 251, 204, 84,	228, 189, 97,  223, 236, 221, 111, 143, 226,
	    198, 115, 39,  226, 188, 107, 78,  151, 139, 243, 149, 10,	93,
	    169, 97,  215, 110, 225, 61,  81,  172, 198, 24,  227, 100, 106,
	    163, 160, 23,  207, 103, 0,	  62,  86,  199, 18,  231, 0,	204,
	    151, 1,   126, 123, 59,  101, 56,  247, 59,	 144, 34,  35,	1,
	    174, 137, 72,  55,	237, 198, 57,  204, 131, 99,  191, 13,	116,
	    202, 167, 170, 250, 40,  16,  91,  8,   177, 130, 193, 173, 244,
	    104, 197, 2,   73,	74,  129, 179, 240, 41,	 1,   69,  92,	86,
	    255, 140, 250, 164, 126, 71,  77,  152, 116, 29,  2,   138, 40,
	    244, 99,  65,  79,	81,  63,  157, 118, 21,	 8,   50,  231, 159,
	    61,	 38,  127, 28,	248, 11,  36,  37,  163, 93,  115, 117, 9,
	    235, 247, 241, 33,	211, 2,	  160, 80,  0,	 129, 110, 74,	100,
	    142, 71,  184, 110, 225, 162, 215, 107, 39,	 228, 104, 199, 221,
	    25,	 11,  226, 60,	237, 36,  29,  58,  245, 194, 97,  190, 220,
	    83,	 46,  180, 112, 247, 75,  198, 88,  39,	 82,  70,  38,	2,
	    144, 72,  235, 245, 132, 154, 61,  173, 159, 220, 25,  145, 140,
	    203, 143, 53,  118, 3,   163, 127, 6,   151, 61,  245, 142, 167,
	    19,	 243, 17,  95,	214, 9,	  99,  39,  161, 75,  116, 185, 124,
	    88};

	// print("ct: ");
	// for (u32 i = 0; i < sizeof(ct); i++) print("{}, ", ct.data[i]);
	(void)expected_ct;
	(void)expected_pk;
	(void)expected_sk;
	ASSERT(!memcmp(&ct, expected_ct, sizeof(ct)), "ct");
	dec(&ss_alice, &ct, &sk);
	// for (u32 i = 0; i < sizeof(ss_bob); i++) print("{}, ",
	// ss_bob.data[i]);

	ASSERT(!fastmemcmp(&ss_bob, &ss_alice, KEM_SS_SIZE), "shared secret");

	u8 expected[32] = {133, 204, 162, 190, 5,   97,	 254, 225,
			   58,	92,  55,  36,  148, 86,	 156, 196,
			   191, 154, 213, 35,  119, 100, 131, 153,
			   102, 104, 83,  123, 229, 45,	 157, 103};

	ASSERT(!fastmemcmp(&ss_bob, expected, KEM_SS_SIZE), "expected");
}

Test(dilithium) {
	Rng rng;
	__attribute__((aligned(32))) u8 seed[32] = {1, 2, 3, 4};
	__attribute__((aligned(32))) u8 msg[32] = {5, 4, 2, 1};
	PublicKey pk;
	SecretKey sk;
	Signature sig;
	rng_init(&rng);
	keyfrom(seed, &sk, &pk);
	sign(msg, &sk, &sig, &rng);
	i32 res = verify(msg, &pk, &sig);
	ASSERT(!res, "verify");
	msg[4]++;
	res = verify(msg, &pk, &sig);
	ASSERT_EQ(res, -1, "bad sig");
}

Test(dilithium_vector) {
	__attribute__((aligned(32))) u8 seed[32] = {1, 2, 3, 4};
	__attribute__((aligned(32))) u8 msg[32] = {5, 4, 2, 1};
	PublicKey pk = {0};
	SecretKey sk = {0};
	Signature sig = {0};
	Rng rng;

	rng_test_seed(&rng, seed);
	keyfrom(seed, &sk, &pk);
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ", sk.data[i]);
	sign(msg, &sk, &sig, &rng);
	// for (u32 i = 0; i < sizeof(sig); i++) print("{}, ", sig.data[i]);
	u8 expected_pk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  154, 210, 70,	 131, 203, 92,	109,
	    88,	 84,  114, 166, 74,  57,  168, 154, 168, 5,   7,   96,	223,
	    131, 175, 170, 156, 248, 118, 97,  73,  158, 42,  62,  57,	94,
	    44,	 177, 55,  131, 193, 221, 246, 210, 146, 239, 200, 129, 75,
	    206, 64,  53,  221, 197, 91,  186, 97,  110, 61,  113, 216, 201,
	    143, 41,  11,  124, 161, 218, 122, 138, 247, 173, 69,  137, 119,
	    249, 6,   6,   17,	62,  61,  30,  44,  94,	 133, 219, 181, 215,
	    162, 16,  133, 195, 108, 98,  232, 3,   184, 98,  151, 189, 249,
	    164, 19,  32,  152, 22,  229, 188, 27,  188, 47,  191, 240, 115,
	    218, 55,  60,  76,	88,  141, 105, 143, 161, 66,  219, 48,	83,
	    251, 94,  255, 4,	184, 52,  21,  10,  123, 191, 55,  98,	75,
	    242, 179, 93,  246, 87,  100, 71,  38,  80,	 57,  11,  66,	171,
	    184, 101, 41,  18,	255, 160, 138, 23,  13,	 191, 217, 247, 174,
	    162, 193, 243, 164, 216, 178, 221, 75,  62,	 133, 106, 86,	194,
	    36,	 62,  174, 255, 200, 29,  221, 84,  37,	 193, 131, 124, 164,
	    108, 0,   157, 192, 196, 17,  114, 109, 1,	 118, 46,  128, 83,
	    154, 2,   202, 79,	240, 0,	  218, 60,  122, 196, 110, 138, 30,
	    239, 91,  228, 191, 102, 123, 144, 24,  190, 178, 157, 120, 16,
	    250, 4,   23,  195, 149, 86,  48,  22,  225, 35,  102, 80,	4,
	    138, 152, 188, 38,	52,  223, 39,  82,  105, 67,  3,   148, 25,
	    56,	 31,  15,  115, 29,  243, 107, 104, 114, 151, 88,  33,	200,
	    122, 54,  233, 252, 120, 148, 63,  148, 75,	 44,  9,   194, 108,
	    3,	 245, 69,  240, 128, 117, 47,  146, 118, 130, 80,  7,	84,
	    70,	 194, 86,  81,	17,  253, 123, 129, 86,	 20,  143, 231, 25,
	    207, 216, 28,  6,	114, 28,  175, 228, 215, 34,  42,  56,	60,
	    212, 103, 53,  54,	51,  240, 159, 171, 3,	 195, 187, 149, 179,
	    54,	 96,  167, 141, 181, 206, 61,  80,  77,	 202, 215, 208, 83,
	    242, 217, 174, 232, 78,  130, 197, 28,  105, 65,  53,  178, 203,
	    11,	 143, 152, 117, 11,  199, 58,  237, 210, 71,  79,  6,	34,
	    64,	 228, 107, 238, 55,  106, 151, 211, 67,	 57,  192, 142, 13,
	    165, 47,  67,  94,	16,  44,  127, 118, 225, 68,  197, 154, 128,
	    38,	 185, 53,  103, 48,  175, 17,  128, 71,	 245, 76,  21,	184,
	    148, 101, 166, 43,	52,  94,  23,  187, 36,	 192, 255, 159, 52,
	    54,	 242, 237, 181, 160, 171, 23,  24,  15,	 31,  218, 102, 216,
	    63,	 118, 237, 109, 39,  151, 48,  97,  33,	 128, 240, 40,	155,
	    77,	 181, 142, 129, 222, 118, 188, 65,  138, 50,  45,  70,	55,
	    253, 153, 39,  110, 124, 187, 240, 161, 197, 211, 118, 102, 132,
	    192, 166, 96,  156, 33,  130, 215, 7,   76,	 210, 197, 144, 246,
	    143, 89,  20,  72,	1,   211, 212, 187, 132, 137, 128, 225, 121,
	    16,	 145, 8,   156, 56,  165, 12,  206, 169, 82,  88,  13,	28,
	    146, 212, 37,  39,	214, 134, 206, 197, 97,	 18,  112, 9,	163,
	    246, 4,   146, 212, 180, 111, 167, 17,  231, 171, 18,  55,	123,
	    30,	 91,  234, 210, 130, 189, 128, 47,  111, 1,   254, 253, 148,
	    230, 221, 10,  55,	173, 126, 175, 228, 37,	 142, 98,  190, 183,
	    127, 170, 211, 4,	124, 210, 4,   201, 116, 229, 104, 102, 78,
	    188, 213, 176, 123, 88,  101, 163, 239, 180, 42,  214, 249, 183,
	    66,	 46,  143, 178, 255, 133, 26,  213, 158, 59,  153, 33,	251,
	    233, 243, 77,  16,	6,   203, 157, 205, 70,	 177, 175, 141, 215,
	    185, 39,  39,  32,	205, 201, 247, 209, 79,	 209, 179, 90,	246,
	    0,	 252, 93,  10,	44,  164, 37,  28,  157, 36,  163, 62,	238,
	    43,	 118, 119, 119, 71,  254, 222, 196, 26,	 149, 163, 211, 64,
	    146, 170, 85,  68,	79,  180, 34,  194, 139, 61,  65,  220, 81,
	    93,	 232, 122, 252, 147, 0,	  98,  229, 221, 161, 71,  56,	53,
	    180, 119, 29,  59,	151, 38,  133, 28,  106, 201, 134, 88,	219,
	    6,	 220, 180, 53,	113, 119, 188, 172, 0,	 103, 233, 9,	198,
	    1,	 177, 147, 212, 105, 157, 191, 163, 102, 61,  95,  91,	159,
	    106, 34,  208, 15,	161, 6,	  29,  94,  3,	 85,  64,  242, 100,
	    212, 187, 166, 119, 133, 69,  56,  73,  194, 60,  128, 106, 249,
	    156, 67,  63,  92,	28,  136, 249, 123, 99,	 157, 79,  78,	244,
	    186, 82,  129, 148, 127, 31,  125, 197, 70,	 20,  239, 165, 52,
	    82,	 136, 50,  103, 108, 171, 97,  214, 119, 128, 70,  87,	231,
	    14,	 201, 241, 130, 113, 45,  86,  150, 28,	 194, 87,  232, 199,
	    166, 179, 90,  29,	67,  129, 222, 152, 189, 87,  53,  246, 140,
	    226, 149, 23,  232, 54,  153, 225, 185, 76,	 12,  250, 145, 123,
	    65,	 71,  26,  197, 253, 67,  226, 54,  69,	 129, 112, 25,	37,
	    42,	 147, 164, 128, 210, 18,  131, 253, 243, 104, 7,   133, 218,
	    185, 187, 186, 204, 88,  231, 99,  174, 247, 113, 51,  33,	126,
	    62,	 158, 166, 201, 253, 44,  84,  111, 245, 131, 99,  38,	122,
	    241, 139, 44,  210, 18,  27,  66,  86,  191, 244, 75,  165, 197,
	    249, 73,  238, 94,	167, 242, 141, 102, 8,	 200, 171, 102, 250,
	    105, 79,  113, 129, 244, 74,  157, 28,  84,	 173, 71,  242, 198,
	    36,	 102, 132, 119, 244, 111, 0,   187, 44,	 50,  14,  52,	160,
	    171, 128, 180, 27,	111, 162, 179, 210, 208, 121, 165, 117, 44,
	    48,	 150, 96,  5,	110, 93,  152, 125, 35,	 76,  57,  195, 241,
	    64,	 176, 77,  161, 238, 186, 39,  201, 14,	 26,  48,  47,	50,
	    58,	 205, 235, 4,	222, 78,  128, 246, 17,	 129, 117, 208, 236,
	    131, 113, 83,  78,	139, 116, 227, 146, 114, 39,  226, 128, 43,
	    161, 195, 182, 97,	251, 173, 48,  240, 225, 54,  185, 148, 250,
	    15,	 77,  87,  227, 179, 86,  155, 207, 114, 5,   231, 46,	79,
	    127, 234, 63,  142, 130, 117, 76,  134, 106, 181, 90,  181, 109,
	    104, 147, 59,  9,	218, 172, 246, 220, 115, 144, 215, 72,	220,
	    20,	 169, 2,   97,	248, 23,  52,  67,  248, 242, 107, 12,	253,
	    111, 198, 32,  162, 180, 167, 211, 241, 196, 226, 150, 138, 92,
	    135, 96,  53,  195, 66,  7,	  209, 156, 80,	 139, 175, 200, 8,
	    138, 56,  163, 160, 27,  241, 212, 152, 146, 238, 123, 89,	81,
	    33,	 108, 215, 184, 5,   26,  235, 86,  98,	 95,  33,  222, 26,
	    244, 74,  139, 136, 7,   77,  156, 128, 215, 90,  220, 75,	125,
	    28,	 7,   220, 246, 127, 231, 55,  73,  131, 220, 196, 201, 201,
	    179, 158, 254, 157, 100, 184, 73,  9,   187, 149, 103, 81,	208,
	    177, 247, 150, 198, 207, 82,  233, 214, 19,	 210, 193, 0,	87,
	    10,	 81,  222, 228, 154, 191, 20,  142, 247, 133, 142, 34,	228,
	    240, 60,  41,  204, 76,  117, 57,  84,  228, 187, 77,  215, 244,
	    128, 86,  225, 248, 3,   140, 157, 129, 221, 233, 70,  53,	235,
	    184, 13,  138, 234, 205, 46,  80,  153, 173, 201, 233, 195, 175,
	    91,	 208, 118, 180, 88,  47,  167, 11,  143, 204, 244, 248, 105,
	    222, 203, 121, 178, 239, 196, 27,  203, 130, 152, 79,  126, 231,
	    197, 233, 62,  202, 169, 6,	  241, 138, 225, 49,  32,  154, 223,
	    66,	 145, 252, 192, 170, 194, 131, 248, 49,	 98,  139, 19,	78,
	    92,	 73,  141, 214, 218, 239, 94,  203, 101, 7,   238, 52};
	u8 expected_sk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  151, 92,  158, 208, 93,  24,	254,
	    98,	 1,   112, 135, 110, 0,	  165, 198, 67,	 97,  47,  44,	253,
	    189, 186, 200, 214, 199, 125, 87,  65,  19,	 157, 189, 100, 182,
	    72,	 77,  159, 7,	122, 3,	  212, 222, 29,	 245, 34,  218, 244,
	    253, 20,  28,  162, 226, 173, 6,   4,   11,	 120, 94,  170, 30,
	    241, 114, 26,  224, 124, 120, 210, 173, 85,	 105, 219, 54,	255,
	    75,	 211, 87,  140, 232, 144, 124, 80,  72,	 15,  4,   24,	16,
	    19,	 93,  120, 224, 140, 137, 172, 45,  229, 117, 145, 12,	70,
	    130, 219, 192, 81,	0,   168, 69,  145, 38,	 64,  11,  32,	129,
	    193, 196, 40,  2,	17,  65,  145, 66,  64,	 26,  198, 129, 67,
	    66,	 68,  24,  18,	128, 96,  132, 129, 1,	 9,   34,  76,	148,
	    97,	 9,   49,  96,	16,  67,  74,  138, 4,	 36,  3,   69,	114,
	    9,	 56,  69,  8,	0,   130, 128, 8,   46,	 9,   4,   4,	202,
	    68,	 2,   218, 150, 140, 220, 34,  2,   155, 200, 76,  33,	9,
	    76,	 83,  24,  10,	27,  128, 72,  156, 50,	 113, 210, 0,	32,
	    18,	 196, 44,  74,	54,  8,	  153, 150, 44,	 153, 38,  145, 11,
	    137, 113, 16,  67,	13,  33,  161, 97,  26,	 49,  106, 10,	19,
	    129, 18,  23,  134, 152, 54,  69,  2,   70,	 78,  33,  54,	34,
	    98,	 72,  73,  152, 168, 73,  200, 52,  8,	 75,  50,  82,	11,
	    178, 112, 8,   152, 132, 100, 40,  34,  2,	 9,   140, 225, 194,
	    44,	 144, 56,  138, 20,  180, 13,  140, 50,	 134, 34,  18,	32,
	    161, 70,  18,  98,	198, 133, 203, 144, 17,	 194, 130, 97,	27,
	    19,	 133, 65,  38,	130, 9,	  179, 133, 33,	 179, 136, 19,	1,
	    80,	 17,  162, 144, 10,  3,	  144, 131, 52,	 144, 28,  128, 144,
	    211, 72,  101, 25,	180, 140, 210, 8,   73,	 3,   50,  129, 72,
	    22,	 45,  154, 68,	130, 33,  52,  37,  136, 4,   137, 25,	51,
	    141, 25,  133, 144, 98,  66,  45,  19,  24,	 1,   204, 56,	49,
	    73,	 136, 101, 228, 38,  14,  10,  73,  100, 10,  20,  32,	24,
	    19,	 42,  34,  193, 140, 152, 64,  144, 195, 72,  140, 26,	20,
	    68,	 97,  38,  132, 211, 18,  10,  84,  144, 12,  137, 136, 49,
	    72,	 0,   109, 19,	0,   144, 20,  137, 136, 97,  34,  106, 34,
	    162, 32,  76,  150, 128, 99,  6,   134, 203, 32,  50,  73,	144,
	    0,	 74,  2,   134, 26,  50,  106, 99,  50,	 68,  216, 182, 37,
	    219, 56,  80,  210, 178, 96,  204, 16,  42,	 211, 48,  45,	88,
	    144, 97,  89,  22,	140, 8,	  67,  98,  3,	 33,  109, 12,	8,
	    97,	 66,  54,  36,	97,  150, 72,  228, 134, 69,  8,   147, 49,
	    73,	 130, 4,   18,	164, 12,  152, 130, 65,	 164, 50,  81,	155,
	    192, 41,  8,   36,	37,  1,	  17,  70,  9,	 34,  12,  220, 0,
	    5,	 28,  193, 113, 96,  52,  5,   18,  2,	 108, 1,   70,	141,
	    72,	 198, 145, 80,	68,  141, 227, 64,  113, 164, 64,  2,	68,
	    132, 9,   19,  19,	72,  67,  184, 68,  98,	 130, 104, 84,	16,
	    5,	 155, 24,  77,	96,  160, 33,  147, 70,	 9,   210, 38,	13,
	    18,	 180, 48,  12,	66,  2,	  28,  137, 45,	 225, 160, 136, 131,
	    162, 64,  25,  131, 32,  73,  0,   33,  75,	 18,  68,  1,	33,
	    40,	 99,  178, 32,	217, 162, 129, 32,  146, 129, 2,   50,	130,
	    16,	 65,  97,  132, 22,  133, 210, 194, 105, 203, 192, 44,	19,
	    17,	 64,  219, 128, 69,  80,  152, 96,  91,	 152, 41,  12,	55,
	    36,	 144, 34,  82,	225, 166, 73,  36,  20,	 101, 208, 180, 137,
	    16,	 20,  66,  32,	6,   134, 131, 196, 129, 68,  22,  129, 1,
	    181, 137, 220, 40,	129, 35,  182, 133, 90,	 148, 101, 20,	182,
	    12,	 137, 150, 96,	129, 50,  18,  32,  182, 9,   12,  36,	137,
	    144, 4,   46,  12,	196, 32,  98,  168, 12,	 196, 50,  109, 91,
	    64,	 130, 25,  51,	66,  194, 38,  136, 211, 50,  109, 136, 4,
	    134, 84,  16,  74,	18,  8,	  141, 73,  32,	 110, 34,  7,	128,
	    2,	 50,  46,  225, 132, 5,	  3,   7,   98,	 76,  146, 12,	152,
	    184, 37,  36,  201, 136, 132, 70,  132, 17,	 131, 112, 18,	17,
	    112, 65,  68,  14,	24,  176, 12,  24,  49,	 101, 82,  198, 68,
	    153, 128, 41,  25,	34,  13,  217, 0,   44,	 12,  137, 81,	36,
	    41,	 130, 28,  181, 76,  209, 50,  36,  73,	 52,  74,  19,	23,
	    112, 226, 168, 44,	139, 64,  36,  8,   137, 96,  12,  51,	40,
	    156, 200, 8,   138, 194, 137, 33,  21,  68,	 20,  145, 129, 65,
	    34,	 9,   201, 68,	97,  32,  38,  97,  89,	 66,  70,  32,	64,
	    13,	 3,   135, 5,	28,  7,	  50,  76,  20,	 37,  12,  7,	10,
	    217, 34,  16,  35,	48,  45,  212, 64,  129, 217, 66,  18,	147,
	    152, 17,  155, 72,	82,  164, 136, 9,   0,	 4,   1,   203, 0,
	    16,	 154, 70,  9,	132, 34,  8,   1,   3,	 1,   20,  70,	110,
	    1,	 151, 112, 193, 18,  101, 163, 168, 132, 96,  176, 80,	179,
	    154, 250, 118, 199, 243, 52,  165, 62,  254, 64,  251, 220, 72,
	    175, 96,  69,  175, 52,  77,  172, 153, 127, 47,  97,  159, 105,
	    26,	 1,   215, 106, 198, 181, 175, 123, 7,	 54,  154, 87,	44,
	    44,	 196, 86,  4,	147, 217, 180, 186, 214, 61,  52,  139, 21,
	    204, 232, 37,  201, 175, 25,  29,  144, 67,	 223, 106, 231, 185,
	    37,	 34,  74,  160, 146, 103, 218, 90,  18,	 33,  144, 25,	66,
	    178, 81,  222, 8,	94,  71,  15,  249, 69,	 1,   133, 191, 247,
	    190, 102, 123, 74,	99,  250, 185, 35,  250, 108, 224, 124, 14,
	    175, 136, 69,  176, 83,  195, 65,  151, 55,	 254, 125, 140, 46,
	    246, 123, 221, 20,	139, 230, 27,  178, 240, 106, 169, 228, 123,
	    78,	 226, 96,  242, 1,   187, 201, 227, 11,	 119, 68,  17,	74,
	    209, 232, 104, 141, 9,   45,  167, 38,  208, 110, 184, 151, 94,
	    21,	 244, 39,  22,	49,  62,  97,  47,  142, 53,  83,  213, 95,
	    55,	 8,   17,  40,	107, 164, 196, 139, 204, 152, 95,  5,	156,
	    215, 50,  208, 212, 244, 115, 235, 151, 76,	 179, 176, 199, 36,
	    205, 52,  222, 104, 227, 132, 46,  73,  180, 105, 192, 228, 176,
	    225, 43,  18,  142, 121, 66,  197, 177, 171, 99,  195, 186, 174,
	    178, 130, 62,  189, 52,  171, 87,  119, 37,	 74,  61,  45,	57,
	    245, 237, 176, 228, 144, 87,  246, 174, 125, 46,  237, 178, 227,
	    149, 172, 250, 75,	50,  9,	  149, 10,  124, 20,  35,  179, 122,
	    89,	 226, 234, 217, 210, 233, 110, 161, 162, 218, 89,  135, 232,
	    121, 222, 230, 124, 175, 62,  177, 157, 159, 137, 233, 206, 207,
	    19,	 186, 105, 113, 16,  247, 188, 26,  28,	 191, 207, 247, 9,
	    176, 126, 94,  146, 205, 51,  78,  201, 26,	 224, 176, 157, 2,
	    9,	 178, 54,  95,	149, 16,  203, 248, 120, 230, 95,  211, 117,
	    82,	 106, 194, 6,	166, 36,  111, 209, 70,	 165, 85,  158, 112,
	    116, 242, 180, 216, 154, 54,  92,  76,  162, 251, 3,   99,	63,
	    249, 7,   77,  199, 162, 118, 181, 112, 244, 48,  174, 30,	53,
	    25,	 154, 70,  131, 3,   228, 144, 124, 65,	 11,  18,  46,	220,
	    68,	 247, 6,   168, 8,   176, 99,  230, 198, 250, 115, 195, 199,
	    15,	 20,  151, 199, 83,  33,  197, 205, 225, 202, 233, 114, 48,
	    190, 123, 228, 200, 232, 231, 235, 104, 52,	 242, 66,  218, 157,
	    118, 87,  209, 155, 50,  15,  183, 197, 38,	 153, 196, 7,	244,
	    143, 160, 139, 71,	175, 21,  30,  16,  214, 190, 62,  141, 188,
	    78,	 62,  169, 68,	130, 48,  194, 159, 141, 17,  159, 46,	71,
	    22,	 152, 7,   49,	251, 17,  61,  63,  202, 142, 131, 158, 78,
	    243, 187, 76,  85,	235, 62,  213, 12,  166, 206, 185, 253, 6,
	    118, 110, 178, 161, 15,  19,  192, 81,  119, 183, 95,  190, 81,
	    32,	 249, 180, 200, 221, 73,  161, 255, 115, 97,  55,  149, 158,
	    88,	 79,  145, 18,	42,  8,	  235, 185, 231, 131, 99,  217, 39,
	    128, 197, 172, 204, 100, 231, 108, 249, 146, 185, 226, 89,	245,
	    237, 59,  167, 213, 70,  191, 147, 187, 148, 255, 90,  174, 124,
	    149, 149, 178, 65,	2,   65,  44,  132, 83,	 45,  108, 94,	123,
	    243, 42,  181, 56,	28,  50,  197, 107, 166, 39,  24,  36,	10,
	    146, 180, 87,  243, 219, 49,  94,  10,  54,	 71,  89,  131, 180,
	    182, 117, 82,  176, 152, 82,  236, 44,  9,	 47,  45,  223, 78,
	    132, 109, 122, 153, 3,   83,  191, 200, 186, 204, 86,  179, 211,
	    169, 42,  120, 243, 208, 98,  126, 197, 176, 82,  14,  171, 102,
	    250, 75,  78,  162, 65,  36,  10,  80,  121, 104, 164, 75,	152,
	    32,	 49,  241, 84,	102, 243, 219, 111, 98,	 208, 101, 178, 25,
	    20,	 104, 129, 20,	248, 152, 13,  30,  196, 217, 158, 57,	177,
	    17,	 193, 79,  144, 216, 190, 26,  21,  233, 165, 97,  58,	59,
	    146, 147, 236, 137, 233, 246, 157, 152, 131, 197, 203, 149, 184,
	    115, 120, 81,  22,	9,   21,  98,  222, 33,	 146, 24,  203, 60,
	    61,	 156, 157, 116, 143, 115, 109, 84,  4,	 80,  20,  34,	223,
	    124, 236, 247, 30,	99,  158, 9,   127, 45,	 225, 123, 207, 74,
	    217, 237, 57,  215, 145, 60,  15,  195, 64,	 118, 102, 132, 220,
	    200, 81,  123, 29,	64,  196, 173, 177, 15,	 174, 8,   58,	236,
	    103, 84,  166, 54,	238, 248, 232, 82,  160, 254, 100, 114, 137,
	    2,	 231, 179, 42,	61,  149, 244, 53,  213, 201, 211, 251, 33,
	    53,	 182, 76,  28,	74,  105, 137, 7,   240, 46,  87,  130, 86,
	    133, 196, 26,  120, 120, 15,  72,  173, 217, 158, 168, 135, 88,
	    149, 44,  14,  250, 126, 149, 189, 37,  181, 162, 192, 223, 178,
	    243, 46,  239, 187, 97,  87,  244, 236, 99,	 181, 220, 212, 100,
	    29,	 164, 113, 151, 92,  251, 35,  231, 195, 5,   196, 219, 106,
	    141, 12,  26,  114, 123, 146, 161, 56,  98,	 239, 166, 60,	235,
	    51,	 95,  26,  59,	11,  95,  99,  61,  120, 9,   84,  95,	199,
	    33,	 140, 197, 141, 73,  160, 168, 68,  78,	 3,   118, 125, 229,
	    210, 180, 70,  31,	137, 162, 143, 223, 183, 135, 139, 10,	26,
	    151, 18,  135, 160, 138, 227, 121, 129, 183, 63,  202, 129, 44,
	    174, 120, 212, 223, 93,  153, 89,  115, 40,	 140, 172, 196, 228,
	    231, 244, 250, 252, 207, 232, 176, 39,  172, 63,  255, 205, 60,
	    68,	 184, 144, 194, 120, 209, 173, 205, 124, 3,   58,  245, 219,
	    217, 238, 117, 187, 234, 118, 32,  224, 60,	 24,  232, 132, 80,
	    109, 221, 137, 74,	108, 149, 249, 102, 60,	 245, 64,  37,	57,
	    125, 114, 61,  120, 213, 221, 155, 107, 51,	 125, 182, 235, 105,
	    110, 236, 156, 184, 91,  253, 41,  2,   160, 208, 20,  100, 116,
	    68,	 69,  118, 191, 94,  126, 45,  179, 149, 71,  19,  232, 66,
	    165, 51,  4,   103, 156, 81,  229, 203, 182, 48,  39,  83,	155,
	    41,	 255, 46,  251, 96,  240, 37,  89,  146, 24,  105, 162, 129,
	    119, 30,  117, 6,	126, 89,  190, 218, 136, 9,   63,  213, 199,
	    107, 70,  68,  192, 124, 31,  58,  157, 70,	 180, 241, 239, 187,
	    19,	 115, 213, 184, 124, 134, 31,  16,  69,	 234, 27,  179, 198,
	    66,	 49,  53,  40,	104, 153, 36,  46,  168, 200, 74,  202, 148,
	    181, 94,  238, 99,	190, 211, 58,  80,  92,	 209, 118, 77,	62,
	    52,	 31,  239, 41,	9,   170, 252, 126, 100, 31,  121, 104, 126,
	    96,	 78,  147, 242, 95,  251, 51,  48,  210, 40,  61,  80,	193,
	    11,	 199, 39,  24,	135, 195, 49,  51,  141, 22,  172, 8,	202,
	    12,	 52,  119, 83,	28,  129, 255, 156, 82,	 191, 110, 15,	115,
	    237, 134, 119, 188, 50,  53,  4,   191, 56,	 12,  23,  194, 174,
	    194, 249, 225, 210, 11,  159, 120, 40,  41,	 172, 35,  50,	142,
	    2,	 85,  14,  132, 181, 36,  82,  7,   58,	 17,  35,  168, 160,
	    68,	 50,  158, 117, 185, 202, 133, 11,  254, 8,   151, 244, 141,
	    147, 211, 31,  154, 211, 144, 192, 52,  48,	 50,  246, 86,	140,
	    217, 173, 129, 226, 138, 248, 217, 192, 94,	 152, 22,  238, 165,
	    75,	 13,  232, 111, 97,  164, 160, 73,  42,	 54,  255, 178, 79,
	    255, 206, 94,  12,	237, 22,  80,  111, 197, 241, 192, 146, 239,
	    19,	 117, 253, 220, 66,  140, 95,  102, 201, 247, 46,  38,	48,
	    216, 45,  234, 12,	81,  81,  23,  133, 203, 98,  56,  0,	180,
	    74,	 90,  8,   77,	226, 197, 183, 163, 227, 127, 46,  143, 176,
	    129, 118, 138, 63,	88,  171, 73,  8,   183, 129, 142, 59,	153,
	    120, 134, 81,  3,	77,  125, 104, 198, 247, 99,  232, 79,	25,
	    43,	 214, 205, 228, 87,  49,  84,  188, 70,	 68,  173, 186, 218,
	    156, 143, 20,  113, 106, 28,  21,  22,  255, 200, 2,   220, 15,
	    122, 145, 26,  214, 9,   156, 171, 144, 177, 214, 162, 105, 11,
	    58,	 204, 175, 138, 218, 233, 89,  176, 29,	 125, 110, 163, 12,
	    77,	 187, 162, 120, 213, 66,  205, 198, 247, 215, 31,  123, 9,
	    160, 24,  83,  251, 168, 25,  47,  240, 3,	 204, 96,  158, 117,
	    71,	 76,  241, 110, 197, 216, 2,   218, 106, 225, 104, 99,	55,
	    170, 83,  248, 14,	132, 51,  35,  10,  24,	 58,  251, 200, 103,
	    56,	 87,  42,  114, 90,  234, 66,  130, 187, 30,  29,  186, 222,
	    68,	 143, 254, 181, 59,  63,  162, 72,  182, 62,  142, 243, 152,
	    145, 57,  41,  224, 110, 247, 232, 225, 23,	 72,  252, 176, 172,
	    113, 23,  191, 198, 122, 12,  176, 54,  33,	 226, 240, 39,	92,
	    240, 165, 112, 244, 144, 103, 230, 8,   169, 18,  174, 233, 109,
	    66,	 146, 147, 140, 101, 66,  124, 36,  30,	 238, 196, 58,	204,
	    160, 237, 23,  191, 93,  152, 253, 182, 29,	 144, 50,  232, 250,
	    94,	 113, 142, 70,	59,  242, 101, 48,  241, 47,  73,  225, 38,
	    187, 165, 163, 75,	188, 9,	  138, 152, 3,	 38,  58,  100, 194,
	    255, 79,  2,   41,	22,  56,  140, 49,  203, 168, 60,  113, 235,
	    52,	 172, 58,  50,	175, 195, 34,  46,  244, 189, 167, 110, 146,
	    192, 143, 157, 25,	216, 50,  254, 1,   128, 134, 222, 79,	124,
	    35,	 23,  237, 23,	179, 62,  159, 55,  14,	 208, 6,   0,	172,
	    242, 221, 79,  104, 8,   126, 7,   67,  97,	 64,  81,  249, 99,
	    204, 144, 130, 178, 15,  55,  166, 51,  243, 161, 73,  236, 87,
	    166, 139, 173, 120, 70,  147, 11,  57,  22,	 135, 121, 178, 58,
	    196, 54,  24,  134, 7,   204, 129, 165, 28,	 166, 29,  2,	52,
	    115, 246, 150, 213, 110, 70,  146, 90,  245, 192, 253, 9};
	u8 expected_sig[] = {
	    8,	 149, 236, 239, 197, 112, 92,  188, 83,	 106, 147, 143, 46,
	    26,	 42,  130, 0,	131, 150, 9,   174, 224, 70,  240, 166, 231,
	    236, 143, 242, 43,	146, 165, 82,  203, 118, 91,  156, 62,	133,
	    177, 89,  237, 169, 199, 238, 198, 0,   190, 5,   242, 71,	159,
	    209, 96,  129, 37,	228, 124, 252, 255, 35,	 65,  198, 65,	15,
	    173, 165, 211, 181, 110, 52,  51,  204, 56,	 29,  122, 189, 130,
	    108, 30,  104, 166, 238, 80,  248, 112, 222, 147, 239, 240, 229,
	    142, 94,  129, 155, 62,  186, 80,  248, 250, 16,  201, 0,	155,
	    32,	 150, 168, 112, 122, 117, 12,  29,  86,	 220, 243, 138, 187,
	    57,	 173, 209, 219, 87,  112, 121, 147, 229, 202, 210, 148, 20,
	    57,	 7,   245, 88,	19,  46,  170, 158, 186, 6,   112, 123, 179,
	    32,	 212, 232, 12,	18,  136, 89,  234, 65,	 123, 234, 95,	237,
	    144, 183, 218, 56,	174, 21,  20,  143, 32,	 208, 155, 139, 142,
	    177, 49,  183, 8,	95,  86,  101, 169, 239, 54,  18,  133, 244,
	    36,	 188, 144, 2,	65,  12,  227, 50,  44,	 77,  149, 247, 45,
	    92,	 243, 244, 240, 102, 71,  214, 162, 217, 158, 135, 120, 242,
	    149, 85,  210, 41,	247, 162, 230, 15,  62,	 135, 148, 125, 250,
	    223, 2,   40,  223, 233, 33,  103, 116, 24,	 6,   155, 142, 131,
	    129, 23,  15,  128, 156, 167, 37,  108, 28,	 5,   67,  145, 192,
	    187, 143, 22,  71,	137, 159, 138, 142, 8,	 12,  246, 9,	166,
	    174, 19,  234, 74,	231, 150, 204, 39,  172, 40,  5,   27,	98,
	    79,	 116, 7,   52,	39,  100, 14,  53,  243, 45,  93,  240, 210,
	    99,	 127, 196, 194, 20,  171, 171, 174, 112, 233, 66,  155, 238,
	    181, 234, 168, 30,	189, 41,  181, 113, 85,	 252, 140, 213, 244,
	    57,	 92,  141, 0,	122, 162, 192, 165, 248, 81,  17,  33,	161,
	    249, 14,  102, 71,	208, 192, 240, 115, 18,	 9,   36,  22,	205,
	    194, 176, 213, 88,	62,  22,  88,  112, 1,	 189, 118, 43,	137,
	    109, 32,  182, 64,	112, 154, 67,  210, 204, 43,  57,  8,	109,
	    29,	 213, 77,  148, 204, 162, 108, 170, 45,	 128, 173, 123, 151,
	    11,	 39,  11,  161, 60,  25,  149, 124, 60,	 105, 64,  125, 254,
	    175, 66,  23,  129, 243, 136, 14,  216, 254, 240, 33,  110, 138,
	    25,	 5,   38,  208, 195, 152, 140, 165, 149, 203, 71,  178, 104,
	    160, 242, 224, 191, 212, 154, 210, 149, 81,	 20,  226, 67,	118,
	    22,	 241, 59,  158, 168, 174, 97,  19,  1,	 79,  63,  204, 23,
	    121, 211, 125, 91,	253, 240, 147, 222, 135, 251, 40,  182, 3,
	    144, 180, 90,  174, 222, 131, 133, 240, 24,	 67,  54,  229, 160,
	    210, 156, 59,  151, 212, 255, 74,  203, 219, 220, 229, 21,	58,
	    136, 172, 5,   162, 182, 134, 26,  81,  184, 84,  25,  245, 19,
	    63,	 156, 136, 16,	88,  5,	  130, 57,  80,	 170, 172, 207, 103,
	    242, 193, 200, 29,	129, 136, 29,  188, 34,	 212, 119, 203, 255,
	    161, 24,  199, 170, 215, 78,  8,   51,  58,	 21,  22,  17,	25,
	    239, 170, 128, 11,	206, 228, 40,  128, 34,	 113, 8,   250, 9,
	    135, 164, 181, 85,	79,  84,  64,  206, 248, 245, 4,   92,	79,
	    188, 25,  149, 145, 106, 129, 196, 109, 142, 229, 3,   7,	169,
	    131, 155, 203, 222, 141, 83,  119, 143, 140, 118, 22,  22,	214,
	    103, 73,  53,  140, 155, 21,  79,  199, 140, 65,  194, 252, 36,
	    36,	 171, 178, 108, 191, 218, 71,  66,  145, 163, 124, 88,	209,
	    76,	 179, 136, 23,	239, 196, 178, 238, 140, 173, 46,  127, 40,
	    179, 127, 93,  236, 85,  127, 8,   50,  62,	 59,  40,  14,	150,
	    211, 76,  235, 251, 166, 93,  132, 96,  182, 118, 27,  232, 13,
	    177, 242, 146, 254, 9,   198, 113, 166, 119, 131, 112, 32,	212,
	    32,	 85,  84,  14,	155, 181, 74,  82,  52,	 60,  39,  6,	69,
	    129, 224, 198, 114, 238, 12,  22,  22,  155, 140, 192, 21,	59,
	    219, 208, 210, 61,	172, 78,  13,  48,  10,	 166, 54,  18,	25,
	    229, 224, 46,  10,	213, 104, 209, 220, 33,	 71,  155, 48,	66,
	    68,	 226, 183, 84,	240, 174, 60,  225, 239, 149, 101, 48,	32,
	    218, 22,  94,  149, 222, 101, 131, 147, 80,	 47,  227, 154, 61,
	    253, 91,  33,  162, 56,  226, 0,   65,  154, 31,  93,  176, 123,
	    87,	 140, 135, 71,	143, 190, 229, 10,  16,	 1,   6,   219, 163,
	    48,	 21,  227, 171, 15,  222, 133, 22,  126, 107, 63,  18,	252,
	    246, 97,  205, 210, 33,  138, 179, 52,  192, 117, 38,  161, 181,
	    87,	 171, 218, 49,	44,  229, 18,  163, 175, 108, 72,  170, 6,
	    134, 138, 69,  211, 253, 168, 118, 239, 59,	 31,  107, 62,	204,
	    114, 90,  81,  157, 7,   89,  36,  137, 133, 230, 241, 30,	227,
	    230, 218, 78,  42,	33,  226, 71,  185, 232, 64,  114, 112, 109,
	    228, 5,   206, 149, 246, 245, 86,  157, 132, 171, 191, 124, 66,
	    12,	 170, 85,  223, 231, 247, 41,  132, 217, 196, 3,   99,	48,
	    68,	 115, 231, 245, 193, 116, 98,  96,  222, 77,  236, 152, 117,
	    10,	 255, 35,  68,	239, 211, 79,  95,  140, 185, 220, 52,	79,
	    112, 197, 141, 155, 63,  132, 82,  196, 140, 98,  189, 140, 207,
	    25,	 126, 12,  203, 225, 69,  177, 154, 73,	 251, 54,  67,	197,
	    147, 177, 114, 187, 210, 120, 37,  55,  216, 83,  233, 221, 233,
	    107, 155, 164, 3,	255, 46,  10,  69,  83,	 184, 125, 117, 46,
	    173, 90,  188, 31,	31,  137, 22,  139, 173, 162, 188, 10,	183,
	    84,	 20,  234, 67,	51,  210, 185, 125, 10,	 109, 55,  88,	226,
	    128, 124, 56,  226, 28,  199, 191, 77,  78,	 2,   96,  85,	159,
	    22,	 7,   79,  217, 239, 86,  5,   214, 94,	 227, 66,  149, 225,
	    136, 19,  166, 75,	182, 237, 51,  104, 74,	 66,  11,  127, 151,
	    197, 229, 124, 135, 209, 27,  28,  49,  15,	 107, 107, 4,	65,
	    16,	 13,  189, 151, 254, 227, 115, 71,  195, 30,  54,  135, 127,
	    140, 172, 15,  40,	165, 251, 74,  52,  165, 30,  125, 229, 17,
	    33,	 161, 15,  221, 86,  104, 53,  149, 42,	 119, 182, 47,	9,
	    227, 40,  62,  29,	54,  82,  232, 107, 90,	 156, 110, 90,	24,
	    181, 182, 187, 106, 217, 164, 131, 181, 40,	 187, 0,   197, 56,
	    38,	 153, 12,  221, 113, 14,  235, 27,  63,	 225, 227, 172, 235,
	    156, 171, 240, 55,	183, 13,  59,  4,   26,	 242, 156, 139, 228,
	    189, 49,  207, 13,	130, 45,  221, 153, 36,	 140, 177, 70,	168,
	    160, 245, 123, 131, 20,  128, 14,  170, 128, 94,  47,  26,	236,
	    235, 213, 25,  88,	212, 229, 220, 247, 43,	 57,  47,  242, 35,
	    133, 146, 222, 226, 66,  17,  142, 208, 29,	 179, 96,  36,	119,
	    10,	 42,  233, 235, 5,   92,  73,  18,  251, 252, 12,  234, 66,
	    45,	 153, 23,  225, 10,  225, 39,  166, 98,	 18,  57,  141, 78,
	    231, 61,  218, 97,	250, 113, 63,  195, 197, 120, 33,  3,	149,
	    243, 94,  183, 13,	185, 137, 185, 66,  191, 186, 145, 171, 75,
	    218, 208, 12,  102, 147, 215, 250, 129, 38,	 10,  16,  130, 250,
	    176, 251, 155, 206, 135, 34,  141, 41,  133, 48,  196, 31,	213,
	    73,	 243, 3,   149, 102, 163, 122, 118, 56,	 20,  143, 79,	220,
	    154, 125, 115, 176, 194, 204, 246, 119, 195, 172, 84,  250, 109,
	    105, 125, 232, 193, 29,  36,  241, 42,  55,	 27,  222, 49,	197,
	    132, 122, 132, 225, 17,  31,  53,  167, 60,	 34,  129, 128, 120,
	    32,	 212, 11,  40,	251, 214, 139, 178, 187, 234, 226, 57,	204,
	    113, 199, 123, 104, 24,  155, 87,  80,  189, 121, 77,  19,	224,
	    140, 231, 103, 83,	83,  181, 35,  160, 68,	 4,   237, 146, 225,
	    192, 57,  240, 70,	42,  169, 178, 83,  15,	 153, 108, 96,	194,
	    232, 72,  68,  184, 84,  43,  183, 110, 19,	 158, 182, 25,	137,
	    227, 224, 245, 50,	61,  206, 34,  135, 19,	 53,  94,  106, 198,
	    143, 241, 129, 209, 23,  178, 216, 221, 174, 149, 105, 193, 26,
	    113, 226, 45,  226, 220, 221, 3,   130, 77,	 30,  188, 183, 50,
	    229, 136, 33,  164, 173, 41,  57,  194, 60,	 86,  244, 31,	73,
	    171, 150, 109, 87,	196, 129, 182, 167, 131, 190, 215, 131, 148,
	    1,	 67,  84,  73,	175, 36,  252, 207, 142, 61,  123, 230, 193,
	    220, 88,  112, 69,	243, 55,  129, 85,  215, 192, 177, 172, 121,
	    20,	 255, 70,  79,	45,  169, 8,   125, 155, 77,  27,  171, 170,
	    160, 125, 10,  168, 35,  27,  38,  52,  28,	 33,  167, 130, 143,
	    40,	 120, 62,  46,	115, 172, 51,  90,  29,	 115, 193, 69,	215,
	    111, 239, 184, 13,	9,   44,  61,  87,  113, 70,  204, 58,	65,
	    15,	 95,  115, 239, 113, 205, 169, 124, 5,	 185, 172, 5,	112,
	    153, 234, 204, 150, 58,  169, 187, 30,  237, 199, 158, 219, 248,
	    152, 49,  104, 83,	231, 160, 177, 210, 77,	 110, 198, 47,	237,
	    209, 80,  244, 13,	82,  191, 131, 106, 233, 111, 171, 35,	219,
	    157, 197, 236, 160, 177, 81,  49,  38,  196, 195, 154, 143, 15,
	    179, 55,  218, 90,	73,  243, 186, 174, 80,	 230, 0,   188, 55,
	    45,	 10,  122, 72,	150, 199, 237, 186, 126, 92,  120, 131, 24,
	    125, 93,  186, 72,	82,  152, 252, 219, 6,	 28,  212, 188, 198,
	    201, 129, 175, 135, 89,  131, 53,  198, 77,	 68,  60,  169, 96,
	    116, 37,  70,  52,	78,  236, 189, 21,  179, 155, 38,  55,	129,
	    69,	 76,  41,  130, 142, 165, 4,   170, 15,	 88,  16,  80,	209,
	    21,	 17,  3,   98,	97,  254, 138, 209, 154, 60,  215, 101, 250,
	    113, 189, 91,  164, 48,  51,  192, 110, 218, 228, 184, 238, 56,
	    80,	 34,  163, 66,	198, 21,  16,  172, 177, 201, 94,  33,	120,
	    100, 197, 98,  12,	81,  96,  251, 47,  81,	 29,  219, 41,	155,
	    10,	 195, 88,  72,	240, 31,  145, 25,  251, 38,  20,  46,	29,
	    7,	 190, 53,  58,	244, 105, 37,  5,   97,	 1,   112, 141, 117,
	    240, 55,  37,  25,	219, 151, 166, 200, 245, 108, 12,  3,	224,
	    100, 177, 135, 115, 231, 42,  107, 202, 202, 12,  228, 132, 61,
	    100, 76,  44,  3,	1,   219, 171, 33,  166, 145, 122, 228, 83,
	    166, 150, 132, 46,	48,  191, 97,  250, 145, 235, 200, 56,	177,
	    2,	 255, 194, 49,	198, 251, 22,  6,   214, 165, 29,  199, 149,
	    40,	 28,  210, 14,	191, 28,  116, 103, 148, 132, 240, 205, 205,
	    145, 143, 229, 78,	133, 100, 173, 8,   153, 127, 124, 99,	15,
	    86,	 255, 127, 128, 133, 87,  51,  212, 146, 197, 68,  171, 68,
	    181, 7,   207, 161, 61,  60,  162, 74,  166, 160, 46,  143, 122,
	    41,	 181, 185, 72,	134, 52,  125, 114, 56,	 222, 35,  37,	129,
	    165, 97,  134, 76,	230, 31,  207, 187, 45,	 68,  46,  248, 74,
	    120, 251, 120, 164, 227, 70,  73,  232, 175, 13,  111, 136, 210,
	    218, 114, 240, 151, 127, 118, 60,  171, 168, 250, 26,  184, 145,
	    140, 108, 116, 189, 209, 185, 221, 181, 105, 43,  56,  217, 96,
	    234, 85,  113, 143, 127, 202, 152, 249, 212, 137, 166, 246, 91,
	    176, 74,  100, 211, 119, 128, 185, 116, 58,	 9,   83,  117, 138,
	    22,	 214, 30,  152, 81,  219, 49,  30,  71,	 110, 98,  74,	8,
	    96,	 49,  17,  3,	218, 85,  92,  46,  131, 165, 95,  90,	186,
	    32,	 224, 174, 94,	25,  98,  211, 244, 201, 220, 142, 129, 48,
	    30,	 167, 110, 224, 30,  36,  42,  122, 172, 4,   50,  85,	224,
	    138, 113, 124, 27,	73,  23,  77,  11,  140, 35,  145, 174, 129,
	    85,	 219, 30,  37,	93,  126, 26,  138, 124, 43,  102, 82,	191,
	    147, 147, 138, 40,	14,  2,	  149, 228, 132, 113, 242, 72,	127,
	    72,	 67,  196, 252, 193, 14,  33,  93,  230, 155, 216, 150, 137,
	    231, 125, 154, 154, 74,  131, 176, 103, 103, 23,  183, 92,	128,
	    52,	 25,  65,  135, 84,  201, 143, 101, 168, 81,  155, 146, 220,
	    28,	 73,  78,  28,	74,  255, 92,  201, 90,	 26,  121, 231, 91,
	    148, 10,  161, 209, 73,  65,  170, 249, 223, 9,   57,  99,	161,
	    143, 208, 204, 18,	217, 170, 250, 248, 170, 164, 50,  215, 25,
	    33,	 186, 203, 231, 31,  248, 237, 196, 227, 142, 195, 96,	134,
	    143, 55,  60,  123, 73,  158, 27,  136, 142, 94,  210, 234, 207,
	    154, 165, 118, 118, 151, 118, 212, 167, 162, 202, 54,  6,	163,
	    48,	 248, 211, 234, 144, 131, 62,  23,  197, 163, 191, 154, 79,
	    23,	 227, 250, 112, 87,  200, 219, 65,  42,	 14,  184, 25,	188,
	    2,	 89,  87,  7,	59,  33,  227, 15,  141, 85,  57,  70,	16,
	    167, 115, 146, 111, 41,  17,  25,  122, 6,	 73,  193, 136, 202,
	    188, 180, 236, 14,	71,  77,  8,   214, 77,	 158, 16,  155, 85,
	    255, 225, 134, 214, 95,  35,  8,   63,  94,	 142, 44,  135, 185,
	    18,	 229, 39,  177, 30,  181, 236, 154, 95,	 92,  33,  100, 25,
	    212, 126, 154, 208, 103, 185, 225, 165, 72,	 109, 143, 117, 182,
	    150, 118, 92,  83,	163, 183, 219, 15,  91,	 243, 26,  213, 122,
	    29,	 182, 248, 112, 156, 36,  55,  249, 49,	 52,  147, 152, 116,
	    19,	 228, 252, 32,	96,  211, 54,  15,  202, 112, 118, 53,	36,
	    192, 144, 242, 232, 113, 137, 242, 228, 150, 133, 59,  180, 155,
	    133, 121, 107, 131, 25,  120, 74,  48,  190, 17,  122, 15,	76,
	    208, 232, 235, 0,	206, 185, 187, 14,  216, 11,  196, 159, 116,
	    43,	 167, 171, 179, 28,  237, 173, 183, 55,	 11,  79,  92,	117,
	    128, 146, 151, 160, 183, 189, 209, 234, 254, 41,  54,  55,	65,
	    68,	 75,  85,  106, 135, 149, 155, 160, 180, 183, 195, 197, 218,
	    230, 231, 240, 2,	3,   4,	  26,  45,  47,	 68,  76,  84,	140,
	    148, 178, 192, 217, 247, 78,  89,  90,  102, 110, 138, 146, 163,
	    165, 171, 172, 196, 199, 203, 207, 215, 238, 247, 0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   13,	33,
	    48,	 66,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
	    0};
	ASSERT_EQ(verify(msg, &pk, &sig), 0, "verify");
	ASSERT(!memcmp(expected_pk, pk.data, sizeof(pk)), "expected pk");
	ASSERT(!memcmp(expected_sk, sk.data, sizeof(sk)), "expected sk");
	ASSERT(!memcmp(expected_sig, sig.data, sizeof(expected_sig)),
	       "expected sig");

	(void)expected_sig;
}

#define DILITHIUM_TESTS 1000
Bench(dilithium) {
	Rng rng;
	PublicKey pk;
	SecretKey sk;
	Signature sig;
	__attribute__((aligned(32))) u8 m[32];
	__attribute__((aligned(32))) u8 seed[32];
	u64 keyfrom_sum = 0, sign_sum = 0, verify_sum = 0;

	rng_init(&rng);
	for (u32 i = 0; i < DILITHIUM_TESTS; i++) {
		rng_gen(&rng, seed, 32);
		rng_gen(&rng, m, 32);

		u64 timer = cycle_counter();
		keyfrom(seed, &sk, &pk);
		keyfrom_sum += cycle_counter() - timer;
		timer = cycle_counter();
		sign(m, &sk, &sig, &rng);
		sign_sum += cycle_counter() - timer;
		timer = cycle_counter();
		i32 res = verify(m, &pk, &sig);
		verify_sum += cycle_counter() - timer;
		ASSERT(!res, "verify");
	}

	pwrite(2, "keyfrom=", 8, 0);
	write_num(2, keyfrom_sum / DILITHIUM_TESTS);
	pwrite(2, ",sign=", 6, 0);
	write_num(2, sign_sum / DILITHIUM_TESTS);
	pwrite(2, ",verify=", 8, 0);
	write_num(2, verify_sum / DILITHIUM_TESTS);
	pwrite(2, "\n", 1, 0);
}

Test(dilithium_loop) {
	Rng rng;
	PublicKey pk;
	SecretKey sk;
	Signature sig;
	__attribute__((aligned(32))) u8 m[32] = {0};
	__attribute__((aligned(32))) u8 seed[32] = {0};

	rng_init(&rng);
	for (u32 i = 0; i < DILITHIUM_TESTS; i++) {
		rng_gen(&rng, seed, 32);
		rng_gen(&rng, m, 32);

		keyfrom(seed, &sk, &pk);
		sign(m, &sk, &sig, &rng);
		i32 res = verify(m, &pk, &sig);
		ASSERT(!res, "verify");
	}
}

