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
	// for (u32 i = 0; i < sizeof(pk); i++) print("{}, ", pk.data[i]);
	sign(msg, &sk, &sig, &rng);
	// for (u32 i = 0; i < sizeof(sig); i++) print("{}, ", sig.data[i]);
	u8 expected_pk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  27,  16,  95,	 235, 11,  202, 155,
	    5,	 27,  155, 145, 225, 32,  123, 52,  232, 114, 159, 84,	192,
	    43,	 35,  254, 239, 80,  163, 61,  14,  39,	 152, 65,  254, 174,
	    124, 52,  77,  164, 200, 225, 125, 19,  122, 190, 217, 165, 77,
	    147, 158, 202, 108, 99,  106, 235, 15,  126, 241, 83,  93,	1,
	    105, 113, 61,  200, 79,  156, 19,  7,   24,	 20,  103, 105, 5,
	    136, 210, 56,  57,	86,  90,  203, 250, 170, 172, 201, 251, 84,
	    232, 7,   122, 244, 186, 121, 233, 23,  247, 175, 195, 126, 13,
	    66,	 206, 27,  102, 160, 53,  181, 80,  179, 161, 242, 119, 161,
	    53,	 193, 239, 88,	232, 123, 51,  73,  207, 200, 59,  240, 83,
	    113, 184, 52,  249, 161, 142, 230, 52,  131, 151, 123, 152, 152,
	    6,	 85,  186, 135, 24,  169, 35,  190, 180, 251, 11,  57,	169,
	    171, 219, 33,  180, 168, 165, 23,  170, 76,	 30,  229, 236, 7,
	    219, 107, 239, 30,	76,  62,  24,  101, 166, 69,  7,   60,	244,
	    153, 144, 99,  171, 176, 236, 214, 134, 209, 235, 57,  151, 234,
	    234, 3,   79,  203, 105, 240, 133, 185, 136, 255, 31,  51,	179,
	    111, 204, 75,  143, 40,  89,  99,  17,  27,	 219, 90,  224, 43,
	    87,	 255, 157, 76,	205, 8,	  123, 147, 66,	 240, 223, 20,	219,
	    127, 25,  120, 4,	214, 139, 244, 112, 54,	 138, 21,  134, 2,
	    165, 160, 6,   254, 9,   78,  101, 231, 94,	 126, 208, 108, 176,
	    166, 133, 49,  197, 59,  157, 59,  36,  16,	 5,   66,  249, 193,
	    125, 205, 167, 177, 80,  190, 113, 120, 250, 250, 136, 62,	207,
	    174, 200, 179, 121, 232, 118, 108, 171, 223, 140, 19,  95,	109,
	    115, 113, 55,  150, 71,  59,  187, 68,  117, 197, 44,  58,	169,
	    205, 28,  84,  246, 16,  179, 27,  219, 131, 85,  195, 2,	69,
	    122, 34,  66,  9,	135, 74,  42,  92,  117, 242, 158, 66,	174,
	    71,	 217, 143, 240, 104, 54,  46,  47,  119, 84,  76,  9,	231,
	    160, 151, 164, 217, 130, 93,  231, 136, 200, 67,  78,  159, 187,
	    54,	 106, 84,  18,	27,  39,  105, 125, 77,	 217, 26,  158, 250,
	    179, 209, 10,  179, 240, 79,  51,  78,  122, 201, 179, 201, 25,
	    206, 173, 61,  153, 226, 112, 23,  184, 148, 19,  65,  104, 232,
	    14,	 143, 145, 75,	49,  239, 84,  253, 33,	 61,  132, 218, 235,
	    226, 52,  201, 122, 154, 46,  88,  20,  248, 180, 218, 194, 164,
	    196, 29,  88,  114, 72,  116, 70,  7,   173, 173, 127, 118, 111,
	    48,	 23,  51,  72,	31,  14,  210, 72,  187, 40,  200, 158, 229,
	    28,	 246, 237, 205, 227, 105, 153, 135, 99,	 46,  90,  80,	10,
	    181, 188, 165, 248, 115, 253, 49,  112, 66,	 66,  134, 204, 207,
	    32,	 71,  80,  30,	106, 140, 73,  12,  9,	 6,   167, 183, 158,
	    75,	 66,  186, 4,	179, 97,  193, 239, 100, 160, 188, 236, 39,
	    47,	 232, 202, 92,	153, 140, 42,  35,  80,	 84,  185, 150, 174,
	    244, 19,  86,  113, 3,   103, 162, 48,  69,	 216, 110, 137, 120,
	    134, 73,  173, 30,	87,  25,  125, 29,  48,	 222, 129, 95,	75,
	    13,	 254, 137, 71,	240, 138, 231, 194, 148, 184, 255, 230, 100,
	    209, 212, 113, 141, 73,  43,  30,  6,   75,	 122, 45,  142, 135,
	    238, 254, 242, 50,	100, 67,  193, 128, 44,	 62,  114, 28,	239,
	    210, 5,   97,  158, 243, 234, 20,  135, 45,	 32,  129, 183, 241,
	    109, 199, 85,  13,	105, 164, 62,  197, 235, 207, 123, 74,	85,
	    61,	 252, 90,  216, 230, 73,  95,  104, 205, 35,  213, 125, 25,
	    153, 50,  232, 71,	91,  240, 156, 220, 223, 34,  205, 84,	32,
	    213, 26,  204, 129, 146, 181, 74,  20,  214, 149, 184, 189, 203,
	    106, 4,   189, 144, 82,  97,  1,   181, 12,	 233, 100, 154, 50,
	    139, 196, 130, 148, 192, 168, 152, 176, 243, 251, 34,  79,	38,
	    212, 116, 137, 4,	151, 209, 130, 106, 171, 245, 162, 208, 2,
	    125, 35,  151, 42,	43,  62,  13,  1,   60,	 94,  250, 169, 209,
	    83,	 7,   203, 111, 162, 232, 123, 169, 238, 190, 179, 227, 182,
	    196, 48,  112, 241, 162, 198, 199, 139, 78,	 201, 19,  53,	72,
	    92,	 56,  134, 245, 93,  0,	  57,  53,  230, 116, 25,  155, 53,
	    42,	 239, 163, 226, 230, 85,  221, 169, 245, 41,  201, 232, 11,
	    192, 126, 97,  140, 35,  157, 170, 159, 134, 212, 230, 151, 19,
	    101, 150, 74,  191, 180, 123, 53,  187, 243, 15,  191, 92,	70,
	    6,	 153, 27,  10,	1,   98,  235, 131, 91,	 94,  76,  141, 105,
	    119, 135, 132, 1,	0,   26,  125, 190, 102, 134, 168, 246, 212,
	    82,	 35,  137, 156, 236, 31,  22,  29,  81,	 60,  38,  217, 95,
	    52,	 105, 132, 93,	255, 48,  207, 36,  208, 86,  201, 6,	41,
	    92,	 44,  237, 160, 166, 146, 132, 249, 58,	 150, 7,   16,	37,
	    174, 29,  197, 85,	66,  77,  37,  243, 107, 214, 47,  65,	227,
	    53,	 235, 219, 54,	157, 186, 151, 19,  103, 145, 62,  246, 43,
	    82,	 139, 65,  188, 93,  55,  178, 167, 243, 158, 170, 245, 242,
	    98,	 185, 204, 210, 107, 137, 149, 99,  207, 196, 216, 103, 70,
	    130, 32,  242, 48,	119, 116, 141, 13,  248, 15,  247, 206, 177,
	    203, 45,  38,  50,	185, 96,  45,  64,  236, 68,  197, 132, 242,
	    56,	 49,  98,  196, 150, 41,  195, 26,  11,	 127, 120, 81,	52,
	    220, 101, 17,  35,	166, 55,  248, 154, 178, 187, 201, 58,	122,
	    225, 150, 26,  1,	138, 49,  204, 157, 157, 218, 128, 208, 71,
	    99,	 123, 122, 165, 206, 236, 80,  171, 161, 198, 39,  51,	106,
	    252, 31,  240, 8,	170, 18,  93,  48,  82,	 244, 95,  141, 23,
	    45,	 58,  33,  99,	46,  93,  97,  156, 208, 151, 247, 205, 76,
	    94,	 147, 110, 42,	181, 227, 77,  188, 81,	 125, 10,  216, 57,
	    172, 212, 182, 154, 110, 70,  176, 232, 239, 7,   105, 77,	40,
	    161, 140, 48,  153, 183, 120, 130, 198, 38,	 147, 26,  45,	136,
	    5,	 20,  53,  25,	172, 106, 235, 231, 114, 84,  185, 203, 89,
	    216, 40,  249, 121, 66,  241, 221, 61,  2,	 151, 125, 51,	74,
	    232, 251, 129, 119, 172, 227, 39,  156, 62,	 148, 72,  77,	216,
	    221, 201, 125, 73,	214, 215, 147, 101, 185, 112, 42,  107, 146,
	    37,	 58,  18,  232, 237, 250, 25,  162, 170, 138, 13,  13,	41,
	    216, 141, 46,  99,	185, 169, 247, 202, 212, 36,  182, 140, 192,
	    89,	 104, 19,  204, 103, 126, 150, 151, 146, 39,  36,  247, 246,
	    53,	 118, 155, 236, 115, 198, 92,  201, 207, 109, 223, 11,	103,
	    198, 209, 7,   2,	14,  224, 83,  7,   250, 222, 26,  28,	41,
	    114, 36,  187, 202, 80,  238, 149, 225, 30,	 184, 147, 28,	100,
	    21,	 184, 43,  107, 62,  5,	  229, 119, 176, 130, 231, 200, 14,
	    154, 60,  159, 104, 150, 74,  81,  155, 219, 117, 168, 25,	198,
	    170, 198, 164, 55,	119, 192, 28,  0,   139, 250, 80,  232, 219,
	    235, 121, 75,  207, 184, 104, 56,  237, 67,	 152, 0,   11,	103,
	    5,	 246, 149, 89,	195, 234, 34,  237, 213, 231, 30,  115, 145,
	    9,	 30,  66,  130, 29,  156, 229, 167, 154, 72,  26,  249, 50,
	    19,	 180, 123, 224, 33,  210, 200, 69,  181, 225, 213, 26,	207,
	    166, 222, 78,  223, 234, 164, 197, 149, 142, 39,  228, 211, 200,
	    118, 146, 59,  159, 30,  153, 56,  69,  156, 231, 48,  222};
	u8 expected_sk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  151, 92,  158, 208, 93,  24,	254,
	    98,	 1,   112, 135, 110, 0,	  165, 198, 67,	 97,  47,  44,	253,
	    189, 186, 200, 214, 199, 125, 87,  65,  19,	 157, 189, 100, 16,
	    119, 121, 6,   35,	70,  94,  190, 53,  152, 77,  69,  244, 127,
	    173, 94,  13,  220, 72,  132, 105, 38,  69,	 140, 22,  217, 50,
	    167, 154, 232, 154, 55,  220, 10,  117, 146, 194, 236, 83,	141,
	    79,	 135, 167, 250, 216, 105, 100, 248, 73,	 242, 207, 222, 74,
	    56,	 84,  28,  156, 123, 123, 246, 10,  109, 49,  196, 12,	70,
	    130, 219, 192, 81,	0,   168, 69,  145, 38,	 64,  11,  32,	129,
	    193, 196, 40,  2,	17,  65,  145, 66,  64,	 26,  198, 129, 67,
	    66,	 68,  24,  18,	128, 96,  132, 129, 1,	 9,   34,  76,	148,
	    97,	 9,   49,  96,	16,  67,  74,  138, 4,	 36,  3,   69,	114,
	    9,	 56,  69,  8,	0,   130, 128, 8,   46,	 9,   4,   4,	202,
	    68,	 2,   218, 150, 140, 220, 34,  2,   155, 200, 76,  33,	9,
	    76,	 83,  24,  10,	27,  128, 72,  156, 50,	 113, 210, 0,	32,
	    18,	 196, 44,  12,	70,  130, 219, 192, 81,	 0,   168, 69,	145,
	    38,	 64,  11,  32,	129, 193, 196, 40,  2,	 17,  65,  145, 66,
	    64,	 26,  198, 129, 67,  66,  68,  24,  18,	 128, 96,  132, 129,
	    1,	 9,   34,  76,	148, 97,  9,   49,  96,	 16,  51,  110, 17,
	    7,	 1,   36,  69,	82,  33,  3,   108, 10,	 54,  33,  67,	134,
	    144, 144, 2,   104, 220, 22,  34,  4,   64,	 104, 20,  193, 144,
	    36,	 2,   138, 25,	195, 40,  66,  176, 48,	 152, 48,  105, 163,
	    16,	 18,  228, 18,	134, 130, 200, 40,  12,	 70,  130, 219, 192,
	    81,	 0,   168, 69,	145, 38,  64,  11,  32,	 129, 193, 196, 40,
	    2,	 17,  65,  145, 66,  64,  26,  198, 129, 67,  66,  68,	24,
	    18,	 128, 96,  132, 129, 1,	  9,   34,  76,	 148, 97,  9,	49,
	    96,	 16,  70,  146, 8,   55,  36,  72,  136, 48,  36,  73,	9,
	    12,	 151, 96,  98,	128, 33,  3,   23,  40,	 0,   179, 13,	146,
	    152, 140, 26,  24,	10,  16,  137, 5,   76,	 20,  45,  33,	8,
	    144, 161, 22,  98,	137, 164, 109, 216, 178, 108, 65,  16,	37,
	    12,	 70,  130, 219, 192, 81,  0,   168, 69,	 145, 38,  64,	11,
	    32,	 129, 193, 196, 40,  2,	  17,  65,  145, 66,  64,  26,	198,
	    129, 67,  66,  68,	24,  18,  128, 96,  132, 129, 1,   9,	34,
	    76,	 148, 97,  9,	49,  96,  16,  163, 132, 82,  52,  141, 211,
	    22,	 110, 204, 50,	113, 161, 2,   76,  0,	 69,  41,  128, 192,
	    100, 212, 8,   130, 11,  167, 81,  33,  133, 32,  0,   176, 100,
	    155, 24,  72,  12,	33,  73,  204, 182, 128, 65,  134, 1,	32,
	    180, 48,  89,  32,	38,  12,  70,  130, 219, 192, 81,  0,	168,
	    69,	 145, 38,  64,	11,  32,  129, 193, 196, 40,  2,   17,	65,
	    145, 66,  64,  26,	198, 129, 67,  66,  68,	 24,  18,  128, 96,
	    132, 129, 1,   9,	34,  76,  148, 97,  9,	 49,  96,  144, 180,
	    17,	 156, 148, 81,	0,   25,  9,   32,  34,	 133, 137, 4,	64,
	    209, 164, 112, 64,	8,   38,  26,  25,  50,	 24,  163, 12,	91,
	    148, 4,   131, 0,	42,  156, 16,  45,  73,	 8,   81,  192, 134,
	    136, 219, 132, 140, 131, 6,	  13,  32,  55,	 2,   12,  70,	130,
	    219, 192, 81,  0,	168, 69,  145, 38,  64,	 11,  32,  129, 193,
	    196, 40,  2,   17,	65,  145, 66,  64,  26,	 198, 129, 67,	66,
	    68,	 24,  18,  128, 96,  132, 129, 1,   9,	 34,  76,  148, 97,
	    9,	 49,  96,  144, 48,  101, 136, 164, 140, 9,   64,  2,	27,
	    137, 109, 3,   177, 81,  2,	  21,  2,   2,	 37,  73,  27,	162,
	    45,	 201, 34,  72,	75,  178, 33,  226, 16,	 68,  138, 24,	10,
	    4,	 193, 141, 162, 196, 77,  36,  8,   109, 73,  50,  44,	67,
	    52,	 80,  12,  70,	130, 219, 192, 81,  0,	 168, 69,  145, 38,
	    64,	 11,  32,  129, 193, 196, 40,  2,   17,	 65,  145, 66,	64,
	    26,	 198, 129, 67,	66,  68,  24,  18,  128, 96,  132, 129, 1,
	    9,	 34,  76,  148, 97,  9,	  49,  96,  208, 40,  128, 35,	16,
	    5,	 16,  152, 96,	217, 8,	  65,  225, 18,	 70,  162, 16,	76,
	    89,	 196, 97,  204, 134, 41,  220, 176, 76,	 152, 192, 132, 131,
	    152, 68,  193, 56,	44,  97,  152, 140, 140, 54,  73,  34,	52,
	    13,	 83,  132, 108, 210, 52,  140, 12,  70,	 130, 219, 192, 81,
	    0,	 168, 69,  145, 38,  64,  11,  32,  129, 193, 196, 40,	2,
	    17,	 65,  145, 66,	64,  26,  198, 129, 67,	 66,  68,  24,	18,
	    128, 96,  132, 129, 1,   9,	  34,  76,  148, 97,  9,   49,	96,
	    208, 50,  105, 1,	185, 5,	  19,  50,  106, 145, 56,  18,	20,
	    134, 145, 132, 40,	104, 1,	  40,  65,  32,	 181, 105, 74,	20,
	    66,	 131, 38,  112, 8,   48,  128, 209, 36,	 142, 164, 70,	48,
	    81,	 24,  16,  82,	40,  129, 138, 70,  36,	 145, 146, 80,	112,
	    181, 89,  69,  65,	234, 76,  250, 230, 189, 131, 38,  49,	1,
	    157, 50,  142, 96,	109, 162, 210, 134, 26,	 185, 8,   253, 96,
	    68,	 98,  218, 81,	8,   81,  242, 199, 16,	 45,  104, 20,	81,
	    21,	 145, 136, 195, 45,  240, 164, 172, 5,	 104, 22,  151, 128,
	    109, 105, 83,  186, 193, 52,  75,  236, 120, 188, 19,  113, 162,
	    149, 77,  119, 192, 83,  39,  27,  89,  202, 249, 65,  232, 192,
	    115, 173, 52,  142, 65,  235, 234, 229, 172, 178, 81,  244, 77,
	    113, 48,  179, 75,	213, 28,  81,  78,  226, 216, 143, 91,	183,
	    85,	 237, 31,  17,	170, 7,	  205, 113, 236, 142, 106, 208, 93,
	    168, 207, 167, 57,	159, 241, 186, 46,  228, 54,  28,  112, 128,
	    160, 167, 132, 39,	24,  126, 145, 90,  156, 198, 202, 189, 17,
	    158, 165, 151, 49,	75,  105, 19,  23,  147, 117, 2,   235, 82,
	    10,	 48,  221, 12,	64,  221, 185, 125, 121, 133, 137, 27,	197,
	    90,	 2,   131, 250, 113, 133, 48,  147, 201, 36,  49,  154, 226,
	    178, 202, 164, 46,	55,  40,  180, 194, 44,	 145, 55,  194, 232,
	    180, 151, 53,  197, 177, 249, 128, 73,  200, 203, 192, 16,	162,
	    44,	 110, 240, 155, 246, 199, 103, 228, 91,	 32,  129, 15,	237,
	    138, 214, 89,  238, 44,  95,  4,   103, 63,	 45,  222, 77,	171,
	    178, 77,  66,  216, 215, 143, 200, 25,  148, 229, 181, 210, 155,
	    133, 193, 50,  146, 151, 82,  64,  243, 177, 4,   142, 12,	219,
	    153, 206, 123, 234, 199, 51,  235, 152, 132, 253, 22,  176, 84,
	    147, 105, 243, 174, 3,   20,  203, 230, 217, 4,   160, 79,	218,
	    70,	 134, 241, 8,	71,  224, 69,  171, 131, 33,  148, 30,	111,
	    140, 140, 244, 72,	114, 154, 160, 34,  187, 153, 220, 47,	240,
	    117, 195, 62,  197, 188, 202, 122, 206, 171, 5,   77,  64,	182,
	    5,	 246, 118, 110, 31,  90,  254, 252, 219, 22,  174, 7,	67,
	    1,	 218, 12,  151, 34,  160, 136, 17,  116, 141, 45,  246, 110,
	    61,	 167, 101, 59,	177, 159, 122, 78,  146, 31,  137, 68,	249,
	    82,	 204, 158, 178, 137, 34,  241, 5,   235, 11,  79,  116, 110,
	    126, 105, 251, 171, 3,   160, 35,  170, 147, 123, 40,  252, 208,
	    197, 83,  154, 106, 222, 193, 210, 74,  164, 40,  194, 105, 90,
	    171, 52,  138, 118, 101, 63,  109, 241, 238, 207, 245, 235, 202,
	    243, 230, 24,  56,	209, 116, 82,  226, 254, 154, 221, 249, 242,
	    174, 98,  17,  172, 88,  197, 139, 114, 160, 237, 80,  108, 253,
	    112, 183, 135, 96,	108, 67,  67,  207, 73,	 139, 91,  248, 241,
	    47,	 126, 70,  138, 60,  165, 123, 233, 169, 139, 32,  166, 242,
	    1,	 188, 132, 241, 115, 245, 38,  29,  134, 67,  16,  213, 175,
	    106, 206, 127, 83,	125, 157, 14,  44,  163, 172, 197, 34,	54,
	    107, 205, 67,  9,	206, 103, 196, 200, 87,	 73,  6,   171, 131,
	    61,	 232, 140, 192, 79,  114, 32,  100, 76,	 65,  191, 54,	211,
	    151, 91,  118, 87,	71,  75,  136, 211, 105, 169, 18,  27,	32,
	    141, 96,  63,  102, 40,  36,  31,  183, 225, 62,  205, 78,	12,
	    184, 22,  161, 223, 22,  166, 6,   184, 74,	 26,  44,  164, 189,
	    229, 215, 66,  101, 131, 233, 58,  170, 30,	 45,  20,  244, 179,
	    36,	 22,  22,  146, 210, 145, 136, 196, 171, 36,  190, 39,	33,
	    95,	 244, 156, 40,	8,   107, 90,  29,  12,	 55,  237, 58,	145,
	    112, 244, 246, 199, 120, 214, 101, 48,  145, 65,  87,  39,	12,
	    143, 48,  14,  163, 207, 248, 173, 156, 134, 71,  231, 68,	173,
	    44,	 69,  123, 13,	29,  165, 207, 137, 109, 153, 212, 112, 231,
	    230, 152, 67,  118, 67,  81,  16,  61,  42,	 207, 121, 39,	32,
	    252, 238, 254, 63,	192, 158, 102, 0,   76,	 133, 34,  60,	106,
	    172, 39,  240, 49,	6,   151, 71,  225, 13,	 171, 128, 77,	75,
	    101, 116, 206, 222, 194, 62,  16,  124, 106, 148, 146, 153, 203,
	    144, 153, 108, 15,	201, 140, 140, 8,   96,	 222, 63,  12,	75,
	    167, 218, 3,   181, 14,  134, 254, 1,   119, 99,  156, 126, 113,
	    157, 126, 173, 35,	193, 196, 221, 112, 195, 172, 35,  248, 208,
	    45,	 109, 89,  21,	161, 46,  3,   220, 222, 71,  48,  42,	37,
	    199, 150, 75,  134, 82,  172, 141, 10,  81,	 145, 47,  33,	65,
	    191, 74,  24,  122, 185, 189, 136, 33,  167, 15,  175, 46,	217,
	    13,	 130, 46,  66,	198, 144, 232, 83,  43,	 153, 156, 131, 150,
	    244, 227, 16,  98,	147, 78,  160, 139, 147, 161, 218, 98,	81,
	    103, 75,  44,  234, 247, 80,  191, 236, 123, 110, 191, 81,	239,
	    12,	 106, 14,  97,	100, 9,	  150, 223, 171, 125, 189, 195, 109,
	    182, 119, 161, 191, 28,  88,  123, 150, 33,	 48,  23,  145, 229,
	    74,	 97,  39,  208, 227, 204, 35,  252, 209, 10,  55,  115, 206,
	    153, 10,  35,  107, 130, 187, 33,  36,  196, 89,  175, 166, 143,
	    136, 80,  6,   11,	31,  148, 127, 208, 237, 211, 93,  66,	188,
	    147, 233, 153, 205, 199, 146, 33,  15,  141, 121, 252, 165, 39,
	    91,	 139, 128, 248, 253, 76,  106, 49,  12,	 155, 50,  211, 197,
	    118, 214, 32,  185, 0,   56,  129, 16,  94,	 143, 224, 126, 237,
	    136, 150, 10,  182, 117, 7,	  191, 206, 161, 234, 111, 224, 156,
	    118, 57,  207, 68,	0,   7,	  57,  185, 248, 244, 5,   236, 212,
	    195, 237, 229, 64,	48,  55,  29,  23,  118, 217, 145, 131, 92,
	    9,	 99,  70,  240, 197, 188, 26,  115, 34,	 150, 213, 15,	103,
	    81,	 215, 55,  118, 13,  46,  17,  101, 136, 103, 232, 39,	76,
	    147, 230, 15,  8,	128, 184, 253, 230, 43,	 147, 252, 27,	82,
	    66,	 6,   81,  25,	192, 218, 58,  9,   114, 24,  65,  17,	16,
	    101, 179, 83,  135, 142, 79,  78,  52,  3,	 114, 71,  149, 93,
	    202, 42,  115, 49,	215, 5,	  240, 251, 137, 32,  163, 0,	181,
	    84,	 111, 28,  240, 221, 147, 219, 83,  113, 87,  207, 127, 250,
	    66,	 254, 131, 158, 103, 17,  103, 27,  133, 27,  222, 94,	243,
	    107, 8,   247, 29,	214, 162, 107, 106, 53,	 45,  133, 94,	197,
	    64,	 95,  187, 174, 1,   184, 96,  164, 185, 129, 113, 33,	251,
	    143, 109, 123, 21,	148, 224, 18,  25,  68,	 85,  79,  187, 122,
	    87,	 216, 38,  154, 218, 162, 49,  123, 175, 97,  186, 177, 133,
	    90,	 28,  171, 228, 99,  241, 151, 49,  178, 97,  57,  218, 243,
	    108, 12,  214, 81,	45,  123, 187, 103, 7,	 252, 193, 16,	243,
	    205, 33,  42,  247, 68,  160, 226, 23,  94,	 175, 17,  1,	119,
	    218, 153, 38,  5,	84,  240, 15,  53,  224, 105, 18,  71,	29,
	    253, 131, 125, 36,	59,  36,  202, 141, 126, 31,  105, 189, 2,
	    2,	 106, 57,  182, 9,   222, 95,  73,  73,	 6,   103, 47,	97,
	    189, 19,  72,  217, 4,   79,  23,  37,  48,	 17,  51,  10,	82,
	    146, 177, 77,  176, 88,  249, 110, 194, 60,	 182, 139, 151, 84,
	    2,	 219, 23,  52,	19,  108, 139, 140, 71,	 189, 218, 8,	55,
	    255, 191, 33,  101, 255, 74,  147, 131, 174, 236, 255, 252, 70,
	    83,	 65,  63,  194, 126, 129, 0,   26,  123, 175, 15,  139, 202,
	    102, 36,  242, 26,	149, 251, 140, 208, 29,	 243, 227, 137, 208,
	    12,	 6,   5,   225, 187, 198, 142, 169, 229, 17,  162, 9,	18,
	    202, 71,  1,   236, 218, 152, 190, 121, 168, 71,  118, 255, 165,
	    152, 130, 132, 143, 111, 144, 156, 89,  24,	 28,  60,  49,	205,
	    124, 133, 190, 175, 131, 227, 70,  178, 168, 46,  22,  15,	218,
	    237, 96,  117, 135, 152, 238, 7,   231, 181, 171, 44,  253, 249,
	    245, 102, 163, 223, 169, 216, 160, 191, 125, 13,  141, 211, 45,
	    203, 189, 157, 254, 197, 255, 174, 200, 239, 143, 105, 137, 227,
	    5,	 89,  12,  151, 213, 22,  113, 1,   18,	 244, 64,  43,	214,
	    110, 96,  144, 231, 165, 66,  203, 151, 24,	 65,  139, 104, 250,
	    151, 106, 113, 49,	178, 180, 148, 186, 113, 47,  54,  83,	113,
	    242, 184, 210, 119, 213, 8,	  195, 63,  234, 104, 243, 99,	29,
	    27,	 53,  121, 221, 155, 247, 106, 84,  205, 176, 204, 172, 48,
	    99,	 150, 155, 92,	33,  59,  74,  131, 203, 160, 202, 228, 106,
	    141, 136, 255, 201, 70,  220, 47,  75,  178, 64,  77,  14,	235,
	    71,	 255, 183, 247, 73,  10,  31,  203, 117, 45,  161, 90,	138,
	    107, 192, 126, 255, 242, 109, 145, 211, 105, 203, 227, 59,	108,
	    67,	 155, 203, 14,	107, 44,  103, 240, 254, 190, 212, 225, 117,
	    68,	 132, 77,  15,	84,  93,  169, 76,  4,	 15,  246, 140, 61,
	    178, 24,  94,  147, 117, 69,  107, 88,  55,	 211, 140, 255, 229,
	    157, 174, 142, 231, 166, 148, 149, 233, 120, 18,  224, 87,	102,
	    43,	 68,  213, 141, 138, 224, 181, 171, 224, 167, 70,  60,	76,
	    178, 165, 174, 201, 83,  91,  144, 177, 138, 178, 2,   139, 40,
	    244, 131, 120, 65,	247, 32,  25,  201, 134, 137, 20,  191, 53,
	    89,	 234, 253, 81,	9,   186, 122, 231, 197, 7,   158, 218, 125,
	    174, 214, 136, 187, 249, 63,  217, 163, 150, 199, 10,  162, 186,
	    185, 95,  187, 67,	69,  141, 51,  211, 191, 198, 6,   42,	9,
	    146, 126, 241, 35,	90,  90,  60,  133, 149, 220, 206, 197, 137,
	    135, 5,   204, 247, 99,  141, 230, 103, 192, 228, 205, 73,	9,
	    129, 43,  219, 112, 241, 28,  150, 248, 148, 196, 173, 99,	150,
	    190, 157, 197, 32,	98,  222, 108, 243, 101, 36,  39,  209, 202,
	    250, 31,  0,   190, 231, 130, 223, 210, 238, 165, 101, 85};
	u8 expected_sig[] = {
	    58,	 175, 186, 81,	207, 175, 48,  219, 32,	 207, 149, 54,	135,
	    10,	 245, 13,  64,	9,   183, 57,  102, 39,	 87,  137, 244, 145,
	    243, 99,  172, 16,	76,  194, 209, 238, 227, 216, 255, 229, 74,
	    153, 109, 187, 52,	79,  119, 82,  185, 243, 141, 190, 25,	78,
	    101, 253, 57,  23,	183, 58,  218, 66,  186, 131, 181, 82,	38,
	    131, 67,  39,  200, 238, 53,  179, 149, 161, 52,  226, 152, 120,
	    219, 34,  127, 187, 132, 28,  146, 123, 177, 54,  183, 22,	13,
	    71,	 0,   55,  246, 154, 166, 163, 69,  236, 217, 251, 254, 162,
	    168, 102, 222, 255, 41,  139, 162, 18,  53,	 215, 202, 170, 251,
	    213, 155, 36,  92,	200, 168, 129, 159, 211, 70,  214, 218, 182,
	    17,	 39,  185, 247, 153, 159, 215, 125, 75,	 113, 132, 201, 194,
	    214, 194, 203, 121, 170, 55,  185, 70,  29,	 140, 251, 167, 5,
	    246, 207, 196, 128, 97,  98,  252, 118, 54,	 225, 37,  197, 8,
	    55,	 107, 249, 47,	247, 94,  197, 192, 46,	 47,  110, 252, 160,
	    246, 240, 243, 95,	243, 173, 199, 112, 197, 75,  99,  90,	75,
	    206, 221, 119, 217, 113, 27,  13,  220, 137, 56,  220, 186, 59,
	    125, 244, 200, 75,	248, 73,  45,  99,  95,	 11,  57,  152, 208,
	    125, 202, 138, 232, 241, 134, 101, 197, 31,	 229, 146, 48,	94,
	    207, 245, 90,  210, 162, 249, 237, 126, 177, 48,  217, 168, 61,
	    68,	 27,  30,  158, 47,  242, 244, 31,  126, 123, 154, 27,	62,
	    155, 190, 6,   16,	192, 131, 60,  104, 186, 212, 50,  196, 178,
	    166, 197, 54,  140, 253, 172, 125, 105, 34,	 13,  65,  155, 25,
	    72,	 100, 202, 212, 226, 31,  96,  179, 166, 17,  241, 113, 126,
	    186, 21,  91,  158, 102, 146, 4,   9,   7,	 105, 99,  211, 63,
	    69,	 21,  246, 18,	190, 53,  202, 153, 92,	 49,  36,  193, 245,
	    224, 97,  73,  77,	158, 20,  87,  117, 76,	 243, 156, 119, 250,
	    100, 39,  230, 209, 116, 244, 39,  134, 191, 177, 118, 143, 179,
	    76,	 100, 134, 205, 102, 133, 145, 145, 253, 231, 254, 97,	95,
	    244, 120, 48,  130, 122, 151, 43,  117, 29,	 106, 130, 97,	7,
	    217, 154, 158, 180, 103, 100, 32,  15,  149, 17,  225, 70,	211,
	    133, 148, 243, 181, 63,  199, 223, 101, 141, 213, 28,  237, 252,
	    184, 242, 46,  4,	10,  2,	  112, 43,  40,	 36,  230, 143, 196,
	    148, 203, 32,  66,	68,  152, 145, 190, 182, 246, 252, 24,	156,
	    184, 63,  112, 202, 214, 122, 77,  36,  229, 8,   181, 159, 229,
	    217, 194, 216, 242, 28,  33,  229, 50,  130, 13,  8,   132, 1,
	    247, 111, 117, 111, 222, 4,	  73,  31,  234, 78,  123, 250, 242,
	    190, 186, 53,  131, 215, 2,	  45,  145, 100, 88,  219, 139, 10,
	    237, 88,  14,  51,	150, 100, 76,  234, 11,	 38,  27,  170, 243,
	    151, 126, 124, 164, 105, 151, 86,  81,  187, 231, 150, 77,	47,
	    34,	 38,  230, 4,	180, 61,  107, 100, 60,	 149, 44,  144, 239,
	    135, 58,  44,  176, 244, 75,  214, 24,  22,	 47,  242, 10,	210,
	    33,	 85,  144, 154, 168, 63,  26,  136, 61,	 227, 195, 119, 39,
	    215, 222, 184, 36,	110, 85,  167, 38,  62,	 18,  193, 57,	241,
	    176, 3,   163, 134, 59,  254, 217, 35,  42,	 3,   58,  24,	199,
	    161, 14,  37,  113, 139, 191, 193, 92,  70,	 250, 18,  126, 30,
	    80,	 28,  226, 37,	159, 159, 166, 98,  186, 202, 112, 33,	214,
	    86,	 54,  37,  102, 194, 203, 201, 0,   189, 199, 23,  49,	227,
	    175, 191, 109, 168, 146, 173, 183, 53,  252, 153, 181, 50,	65,
	    17,	 221, 142, 15,	9,   82,  161, 59,  213, 197, 125, 195, 122,
	    32,	 157, 55,  72,	15,  100, 248, 194, 95,	 127, 154, 103, 102,
	    66,	 6,   3,   152, 132, 178, 85,  162, 148, 140, 199, 216, 171,
	    240, 209, 198, 255, 144, 11,  177, 7,   228, 214, 51,  24,	138,
	    237, 236, 222, 108, 65,  161, 16,  255, 221, 94,  106, 233, 241,
	    243, 92,  79,  163, 84,  66,  160, 157, 42,	 17,  13,  127, 155,
	    9,	 248, 14,  214, 96,  193, 255, 69,  160, 223, 46,  114, 145,
	    2,	 32,  236, 41,	225, 14,  134, 15,  192, 174, 115, 169, 24,
	    224, 107, 53,  107, 34,  40,  119, 50,  15,	 90,  26,  16,	160,
	    44,	 76,  116, 136, 141, 96,  101, 117, 154, 98,  220, 36,	135,
	    23,	 32,  85,  171, 201, 123, 111, 122, 69,	 40,  123, 162, 152,
	    207, 222, 223, 166, 15,  253, 165, 178, 147, 124, 147, 128, 108,
	    190, 133, 99,  232, 21,  163, 145, 161, 123, 172, 53,  63,	59,
	    158, 181, 220, 192, 176, 2,	  37,  132, 61,	 247, 20,  89,	236,
	    123, 153, 41,  101, 139, 2,	  155, 211, 247, 117, 47,  137, 223,
	    72,	 198, 205, 247, 148, 34,  124, 213, 179, 178, 124, 196, 197,
	    94,	 183, 163, 255, 14,  231, 113, 93,  142, 184, 58,  40,	70,
	    74,	 0,   192, 96,	205, 204, 8,   73,  245, 155, 47,  71,	194,
	    198, 197, 182, 182, 232, 46,  45,  229, 254, 86,  80,  66,	34,
	    150, 44,  169, 173, 28,  245, 43,  19,  11,	 241, 65,  160, 97,
	    253, 217, 37,  125, 118, 75,  22,  107, 223, 165, 203, 75,	77,
	    221, 248, 227, 181, 61,  202, 107, 128, 97,	 127, 92,  5,	11,
	    134, 107, 200, 163, 92,  152, 121, 207, 88,	 223, 99,  148, 89,
	    124, 181, 128, 74,	255, 29,  199, 192, 79,	 106, 52,  239, 161,
	    66,	 134, 122, 57,	101, 24,  197, 18,  252, 186, 192, 61,	220,
	    87,	 126, 177, 9,	232, 144, 77,  173, 127, 221, 117, 81,	140,
	    164, 37,  39,  63,	1,   36,  255, 248, 73,	 113, 85,  72,	141,
	    115, 153, 40,  206, 1,   188, 73,  201, 114, 155, 51,  55,	3,
	    125, 38,  250, 143, 70,  136, 46,  239, 183, 166, 159, 244, 79,
	    201, 33,  30,  207, 195, 12,  172, 44,  79,	 135, 103, 193, 174,
	    143, 64,  48,  240, 251, 157, 200, 157, 45,	 203, 49,  70,	154,
	    173, 232, 97,  43,	187, 224, 251, 75,  1,	 27,  120, 209, 12,
	    196, 109, 5,   103, 230, 50,  251, 147, 111, 155, 71,  16,	122,
	    134, 56,  210, 54,	30,  117, 200, 167, 151, 154, 234, 176, 29,
	    80,	 88,  231, 179, 128, 107, 83,  102, 67,	 19,  35,  39,	117,
	    240, 78,  205, 221, 212, 112, 3,   160, 109, 141, 44,  60,	93,
	    137, 217, 135, 215, 12,  49,  238, 37,  70,	 129, 225, 197, 36,
	    132, 184, 76,  162, 70,  192, 193, 101, 152, 157, 37,  163, 158,
	    66,	 129, 12,  121, 191, 84,  48,  72,  60,	 216, 108, 242, 37,
	    11,	 80,  128, 190, 222, 81,  218, 68,  169, 134, 134, 185, 66,
	    139, 100, 47,  255, 143, 227, 33,  183, 169, 201, 251, 84,	237,
	    196, 135, 93,  122, 174, 107, 28,  98,  146, 104, 209, 25,	96,
	    69,	 69,  138, 195, 246, 31,  88,  76,  193, 23,  143, 84,	109,
	    107, 154, 150, 16,	200, 16,  47,  105, 166, 140, 46,  16,	185,
	    166, 118, 171, 46,	237, 107, 41,  55,  84,	 223, 16,  226, 25,
	    16,	 34,  253, 167, 144, 255, 24,  94,  172, 212, 108, 121, 22,
	    140, 192, 72,  22,	234, 14,  166, 12,  193, 211, 202, 164, 139,
	    151, 252, 64,  162, 85,  98,  63,  167, 207, 190, 148, 29,	185,
	    74,	 101, 213, 55,	166, 8,	  246, 49,  252, 108, 206, 88,	127,
	    130, 211, 223, 180, 39,  11,  49,  205, 68,	 55,  140, 127, 130,
	    95,	 100, 128, 170, 9,   229, 180, 149, 8,	 210, 168, 85,	193,
	    135, 11,  236, 138, 124, 147, 145, 147, 99,	 171, 164, 48,	65,
	    222, 130, 76,  171, 243, 131, 112, 235, 39,	 113, 134, 138, 24,
	    254, 241, 33,  142, 162, 132, 52,  173, 75,	 96,  89,  125, 124,
	    58,	 71,  26,  100, 24,  71,  68,  56,  58,	 194, 112, 58,	181,
	    37,	 159, 7,   55,	255, 14,  14,  223, 96,	 198, 254, 245, 33,
	    13,	 216, 72,  169, 34,  114, 248, 244, 178, 78,  158, 23,	48,
	    187, 196, 13,  172, 201, 143, 150, 120, 184, 54,  2,   8,	17,
	    87,	 8,   12,  108, 77,  54,  107, 172, 131, 189, 88,  68,	218,
	    123, 31,  165, 247, 59,  79,  161, 58,  76,	 34,  254, 144, 19,
	    99,	 187, 203, 29,	155, 193, 238, 13,  198, 113, 254, 81,	108,
	    18,	 44,  8,   62,	43,  128, 31,  223, 176, 153, 0,   86,	158,
	    162, 130, 210, 203, 156, 127, 168, 80,  20,	 141, 101, 153, 88,
	    124, 149, 234, 43,	89,  132, 232, 242, 226, 147, 84,  209, 74,
	    252, 69,  127, 113, 47,  240, 4,   165, 145, 124, 197, 182, 229,
	    47,	 34,  103, 151, 35,  91,  240, 17,  106, 18,  114, 165, 180,
	    208, 242, 7,   16,	171, 239, 155, 79,  51,	 239, 132, 223, 81,
	    0,	 253, 205, 22,	17,  138, 133, 143, 6,	 179, 159, 163, 186,
	    104, 59,  238, 208, 222, 177, 56,  151, 71,	 78,  115, 40,	170,
	    202, 248, 74,  221, 27,  163, 44,  176, 254, 227, 30,  90,	33,
	    121, 4,   254, 219, 39,  215, 69,  128, 118, 134, 3,   28,	52,
	    181, 108, 198, 195, 207, 73,  16,  13,  19,	 20,  52,  201, 164,
	    74,	 35,  145, 94,	188, 74,  69,  6,   78,	 33,  31,  240, 89,
	    229, 94,  6,   72,	134, 42,  67,  134, 48,	 58,  218, 133, 88,
	    219, 21,  233, 60,	17,  230, 38,  152, 72,	 7,   225, 64,	97,
	    169, 24,  226, 49,	212, 143, 32,  220, 48,	 232, 128, 24,	121,
	    41,	 188, 33,  184, 27,  198, 14,  43,  230, 249, 227, 88,	243,
	    12,	 83,  42,  225, 5,   148, 27,  111, 78,	 68,  87,  164, 72,
	    225, 37,  210, 252, 62,  85,  224, 118, 101, 233, 6,   206, 51,
	    15,	 100, 0,   249, 115, 248, 22,  114, 200, 219, 148, 13,	15,
	    53,	 248, 157, 163, 7,   61,  46,  247, 134, 23,  69,  25,	178,
	    236, 201, 86,  39,	152, 48,  206, 3,   101, 46,  81,  178, 109,
	    55,	 84,  219, 111, 119, 101, 177, 189, 194, 93,  179, 142, 225,
	    180, 243, 38,  81,	101, 212, 183, 216, 111, 144, 152, 140, 23,
	    231, 49,  17,  77,	1,   28,  75,  95,  224, 86,  121, 86,	174,
	    32,	 182, 2,   223, 142, 213, 168, 136, 36,	 84,  146, 197, 123,
	    76,	 214, 148, 178, 146, 173, 23,  165, 48,	 123, 166, 9,	210,
	    3,	 95,  194, 193, 8,   213, 165, 13,  201, 25,  82,  44,	255,
	    43,	 180, 224, 153, 52,  54,  249, 34,  171, 17,  57,  70,	197,
	    189, 142, 142, 74,	120, 167, 111, 147, 223, 99,  172, 100, 234,
	    211, 13,  91,  175, 206, 233, 134, 181, 201, 98,  48,  249, 248,
	    242, 205, 38,  156, 63,  211, 87,  98,  50,	 101, 254, 164, 39,
	    131, 231, 35,  228, 106, 242, 121, 174, 160, 184, 72,  150, 111,
	    168, 130, 29,  194, 240, 105, 213, 184, 235, 42,  201, 83,	43,
	    108, 25,  109, 70,	36,  151, 24,  92,  153, 99,  111, 234, 133,
	    227, 173, 97,  56,	94,  110, 139, 98,  182, 135, 106, 94,	4,
	    203, 207, 253, 44,	230, 229, 15,  129, 74,	 22,  2,   121, 218,
	    140, 9,   69,  191, 252, 56,  74,  117, 55,	 6,   36,  218, 246,
	    101, 191, 194, 152, 221, 221, 169, 144, 112, 62,  253, 236, 56,
	    21,	 1,   116, 0,	215, 48,  109, 3,   207, 73,  126, 29,	180,
	    232, 105, 178, 57,	223, 13,  227, 227, 166, 114, 223, 85,	53,
	    58,	 97,  252, 58,	224, 159, 144, 92,  246, 148, 171, 206, 224,
	    254, 235, 87,  189, 69,  137, 36,  137, 192, 156, 51,  251, 217,
	    32,	 75,  16,  35,	88,  16,  134, 11,  206, 18,  36,  52,	215,
	    17,	 60,  2,   10,	144, 68,  38,  248, 91,	 223, 134, 89,	47,
	    29,	 147, 151, 8,	244, 205, 124, 224, 35,	 238, 187, 253, 243,
	    43,	 192, 155, 194, 216, 154, 253, 46,  96,	 84,  207, 40,	54,
	    26,	 181, 129, 151, 53,  185, 166, 7,   50,	 251, 97,  193, 193,
	    11,	 53,  168, 172, 167, 220, 13,  171, 226, 62,  105, 38,	203,
	    11,	 85,  253, 193, 61,  96,  102, 199, 194, 29,  216, 154, 117,
	    232, 49,  144, 35,	25,  112, 15,  181, 5,	 225, 215, 127, 220,
	    7,	 73,  10,  221, 105, 242, 218, 148, 42,	 194, 123, 76,	214,
	    137, 194, 229, 37,	126, 217, 128, 41,  233, 60,  153, 87,	249,
	    175, 142, 234, 247, 147, 140, 11,  133, 26,	 74,  157, 66,	67,
	    102, 254, 51,  80,	121, 138, 15,  44,  38,	 5,   164, 198, 5,
	    148, 238, 217, 171, 16,  93,  47,  59,  161, 73,  185, 225, 234,
	    129, 122, 29,  41,	136, 128, 89,  31,  42,	 98,  160, 211, 199,
	    20,	 74,  196, 88,	224, 69,  255, 89,  45,	 246, 231, 60,	233,
	    36,	 23,  232, 237, 10,  148, 121, 73,  8,	 25,  73,  237, 199,
	    11,	 142, 215, 127, 28,  139, 208, 208, 87,	 20,  75,  231, 255,
	    32,	 69,  241, 223, 151, 3,	  21,  209, 228, 60,  70,  118, 89,
	    95,	 42,  251, 30,	90,  136, 33,  169, 189, 33,  242, 216, 108,
	    108, 51,  243, 192, 187, 6,	  139, 182, 51,	 13,  179, 218, 156,
	    36,	 215, 37,  170, 10,  150, 72,  27,  95,	 143, 82,  104, 253,
	    112, 172, 167, 83,	230, 91,  70,  214, 190, 26,  94,  152, 68,
	    7,	 73,  39,  210, 0,   196, 140, 164, 182, 150, 208, 214, 226,
	    13,	 151, 47,  128, 53,  216, 241, 43,  205, 43,  33,  177, 54,
	    125, 235, 217, 221, 80,  229, 238, 122, 44,	 222, 182, 28,	154,
	    154, 224, 26,  7,	247, 224, 81,  47,  165, 163, 130, 143, 78,
	    107, 157, 162, 109, 32,  91,  163, 155, 99,	 174, 17,  196, 226,
	    244, 116, 150, 106, 248, 41,  236, 252, 245, 116, 250, 32,	124,
	    79,	 120, 192, 159, 87,  127, 83,  169, 182, 2,   19,  31,	47,
	    67,	 84,  97,  129, 130, 132, 195, 200, 216, 221, 238, 240, 3,
	    14,	 23,  40,  64,	90,  98,  136, 159, 179, 224, 226, 232, 14,
	    32,	 44,  73,  119, 132, 136, 147, 151, 160, 187, 223, 248, 250,
	    19,	 60,  91,  94,	116, 123, 129, 150, 171, 206, 0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   16,	29,
	    43,	 53,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
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

