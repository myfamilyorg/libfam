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

#include <libfam/format.h>

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
	    134, 137, 226, 4,	103, 5,	  64,  28,  188, 16,  30,  150, 3,
	    21,	 116, 4,   2,	181, 15,  62,  142, 166, 101, 192, 48,	93,
	    137, 239, 230, 113, 203, 170, 49,  146, 243, 83,  79,  149, 228,
	    12,	 91,  189, 192, 241, 44,  209, 189, 14,	 46,  226, 44,	204,
	    198, 35,  59,  0,	224, 206, 127, 0,   128, 88,  94,  115, 182,
	    79,	 118, 70,  79,	159, 122, 185, 184, 196, 244, 238, 8,	230,
	    151, 149, 78,  63,	196, 155, 224, 175, 183, 94,  103, 218, 131,
	    167, 234, 212, 74,	111, 197, 165, 125, 27,	 143, 165, 245, 27,
	    152, 140, 245, 205, 203, 155, 26,  15,  153, 176, 211, 4,	198,
	    143, 236, 19,  54,	34,  37,  249, 157, 7,	 229, 3,   70,	43,
	    116, 73,  245, 217, 77,  93,  26,  21,  174, 129, 159, 142, 61,
	    173, 235, 149, 29,	203, 103, 155, 61,  164, 33,  188, 89,	236,
	    252, 239, 24,  3,	253, 37,  119, 50,  186, 239, 62,  203, 132,
	    44,	 27,  253, 213, 181, 161, 191, 85,  90,	 246, 75,  98,	112,
	    240, 209, 107, 248, 38,  187, 20,  210, 175, 65,  62,  5,	119,
	    24,	 10,  210, 219, 115, 224, 255, 3,   238, 155, 236, 118, 232,
	    152, 147, 221, 176, 122, 136, 21,  50,  176, 102, 245, 46,	144,
	    204, 200, 231, 62,	231, 81,  232, 224, 67,	 70,  113, 47,	250,
	    245, 116, 130, 64,	10,  219, 118, 107, 246, 111, 189, 59,	132,
	    64,	 80,  126, 6,	53,  87,  227, 243, 217, 243, 191, 208, 79,
	    223, 24,  176, 202, 86,  3,	  218, 178, 65,	 74,  6,   110, 74,
	    110, 191, 229, 182, 40,  85,  178, 204, 210, 203, 115, 225, 156,
	    122, 251, 119, 59,	182, 62,  159, 36,  56,	 149, 60,  46,	24,
	    125, 122, 168, 92,	250, 209, 231, 16,  244, 120, 89,  21,	44,
	    132, 212, 98,  145, 71,  96,  191, 9,   1,	 22,  212, 213, 157,
	    3,	 138, 29,  219, 15,  122, 105, 213, 39,	 70,  106, 46,	178,
	    72,	 15,  23,  28,	56,  64,  205, 20,  113, 182, 207, 86,	87,
	    102, 35,  147, 251, 177, 131, 49,  113, 87,	 126, 35,  18,	182,
	    242, 223, 217, 65,	124, 101, 180, 55,  117, 73,  232, 130, 171,
	    178, 76,  90,  183, 138, 203, 89,  38,  191, 39,  218, 35,	54,
	    98,	 20,  213, 113, 170, 245, 251, 111, 71,	 87,  43,  85,	27,
	    119, 211, 190, 98,	231, 227, 210, 41,  94,	 182, 145, 166, 219,
	    224, 173, 142, 24,	231, 229, 118, 45,  187, 142, 143, 202, 243,
	    190, 253, 39,  154, 46,  160, 66,  38,  180, 251, 234, 205, 67,
	    83,	 234, 209, 212, 191, 167, 35,  143, 58,	 44,  167, 62,	101,
	    36,	 233, 195, 156, 233, 40,  44,  172, 12,	 221, 129, 182, 108,
	    191, 248, 224, 74,	141, 11,  71,  35,  70,	 103, 46,  192, 26,
	    198, 1,   51,  193, 45,  93,  160, 239, 35,	 148, 69,  164, 112,
	    138, 89,  141, 97,	140, 11,  41,  177, 174, 157, 87,  70,	170,
	    66,	 201, 195, 143, 196, 186, 29,  245, 148, 36,  227, 131, 187,
	    98,	 69,  80,  200, 231, 80,  189, 195, 236, 79,  31,  218, 204,
	    110, 193, 27,  13,	232, 207, 167, 228, 158, 42,  47,  185, 149,
	    123, 137, 192, 85,	130, 201, 224, 201, 137, 213, 110, 191, 56,
	    234, 100, 229, 110, 71,  219, 15,  141, 8,	 160, 127, 252, 73,
	    59,	 204, 29,  99,	108, 186, 125, 148, 8,	 163, 68,  51,	89,
	    157, 136, 168, 126, 129, 106, 234, 164, 83,	 95,  76,  119, 53,
	    160, 186, 153, 151, 65,  249, 155, 90,  141, 96,  236, 247, 34,
	    87,	 80,  233, 174, 226, 93,  201, 197, 240, 113, 46,  201, 15,
	    61,	 13,  216, 91,	250, 88,  242, 172, 235, 25,  54,  176, 4,
	    221, 211, 95,  112, 4,   158, 96,  35,  157, 145, 240, 86,	36,
	    117, 12,  237, 55,	100, 209, 84,  237, 233, 186, 79,  71,	60,
	    22,	 79,  99,  42,	172, 47,  158, 102, 105, 138, 175, 222, 173,
	    222, 80,  104, 157, 137, 220, 241, 101, 59,	 122, 90,  253, 142,
	    235, 134, 255, 84,	85,  153, 50,  98,  129, 50,  129, 123, 172,
	    220, 67,  231, 130, 212, 202, 117, 99,  210, 165, 140, 214, 24,
	    254, 73,  177, 52,	37,  114, 178, 133, 47,	 123, 196, 34,	135,
	    244, 127, 234, 139, 60,  179, 215, 113, 81,	 12,  2,   62,	172,
	    78,	 161, 200, 204, 116, 142, 131, 73,  91,	 214, 127, 143, 19,
	    193, 128, 170, 211, 53,  255, 44,  242, 212, 37,  213, 150, 140,
	    213, 67,  162, 103, 84,  234, 18,  142, 103, 142, 47,  182, 204,
	    137, 5,   218, 161, 109, 50,  190, 249, 210, 162, 176, 58,	191,
	    155, 62,  29,  115, 221, 98,  134, 97,  2,	 29,  13,  160, 200,
	    193, 81,  253, 41,	18,  5,	  224, 68,  80,	 15,  74,  19,	14,
	    225, 88,  138, 229, 9,   55,  222, 142, 77,	 176, 37,  10,	221,
	    175, 144, 49,  192, 84,  248, 29,  135, 161, 226, 32,  197, 116,
	    82,	 159, 36,  249, 219, 154, 218, 113, 238, 73,  73,  161, 250,
	    149, 178, 175, 165, 16,  116, 234, 193, 175, 236, 186, 159, 223,
	    137, 147, 193, 16,	210, 222, 159, 107, 114, 16,  69,  34,	30,
	    142, 6,   177, 133, 132, 227, 174, 144, 114, 55,  190, 29,	84,
	    16,	 34,  234, 234, 52,  195, 234, 110, 115, 254, 94,  123, 59,
	    91,	 246, 78,  154, 66,  122, 184, 86,  59,	 49,  45,  246, 59,
	    158, 121, 206, 166, 149, 86,  24,  225, 121, 57,  247, 229, 75,
	    47,	 78,  214, 158, 141, 83,  101, 6,   200, 226, 128, 46,	102,
	    154, 34,  135, 145, 3,   63,  68,  40,  158, 223, 117, 132, 242,
	    147, 131, 182, 124, 147, 58,  48,  220, 105, 166, 193, 183, 141,
	    78,	 219, 29,  252, 142, 34,  162, 102, 178, 72,  96,  251, 34,
	    8,	 164, 152, 18,	6,   149, 33,  203, 106, 253, 206, 127, 92,
	    41,	 81,  218, 179, 187, 232, 192, 230, 137, 131, 106, 75,	83,
	    159, 170, 129, 174, 127, 83,  233, 13,  36,	 6,   32,  210, 104,
	    185, 113, 197, 16,	254, 106, 173, 155, 98,	 8,   86,  207, 137,
	    51,	 6,   184, 34,	70,  88,  219, 236, 17,	 73,  10,  121, 67,
	    129, 84,  128, 221, 60,  1,	  209, 7,   212, 96,  115, 154, 204,
	    122, 244, 43,  33,	98,  55,  246, 147, 227, 201, 21,  167, 153,
	    202, 230, 65,  110, 191, 9,	  152, 85,  228, 146, 19,  202, 83,
	    83,	 234, 47,  209, 135, 169, 8,   239, 236, 160, 167, 33,	182,
	    250, 248, 50,  120, 221, 183, 240, 234, 144, 5,   180, 139, 237,
	    93,	 94,  3,   27,	45,  27,  133, 53,  20,	 95,  24,  235, 82,
	    11,	 127, 83,  227, 1,   93,  163, 210, 53,	 248, 241, 140, 113,
	    152, 214, 250, 220, 69,  107, 110, 229, 216, 187, 14,  43,	219,
	    170, 126, 226, 127, 107, 243, 111, 27,  252, 104, 139, 27,	114,
	    124, 247, 166, 83,	158, 159, 218, 213, 63,	 8,   221, 77,	241,
	    140, 29,  116, 151, 93,  61,  76,  174, 157, 103, 224, 155, 47,
	    143, 182, 199, 17,	169, 24,  143, 209, 174, 188, 17,  234, 153,
	    248, 154, 79,  135, 206, 189, 234, 97,  23,	 170, 161, 34,	87,
	    192, 14,  201, 141, 148, 19,  32,  157, 188, 209, 159, 107, 145,
	    35,	 45,  39,  161, 129, 37,  130, 27,  183, 21,  94,  46,	176,
	    253, 248, 98,  205, 223, 236, 110, 4,   34,	 9,   12,  153, 202,
	    182, 66,  200, 22,	117, 235, 19,  35,  40,	 59,  165, 150, 134,
	    114, 12,  5,   88,	37,  237, 146, 8,   225, 238, 238, 122, 190,
	    1,	 150, 89,  67,	41,  8,	  99,  253, 211, 238, 218, 72,	246,
	    72,	 133, 100, 239, 80,  187, 173, 76,  10,	 128, 128, 69};
	u8 expected_sk[] = {
	    134, 137, 226, 4,	103, 5,	  64,  28,  188, 16,  30,  150, 3,
	    21,	 116, 4,   2,	181, 15,  62,  142, 166, 101, 192, 48,	93,
	    137, 239, 230, 113, 203, 170, 150, 16,  134, 98,  93,  95,	151,
	    72,	 162, 11,  71,	83,  182, 100, 179, 110, 49,  163, 9,	22,
	    173, 205, 137, 15,	170, 217, 93,  9,   45,	 46,  236, 0,	249,
	    249, 246, 182, 239, 219, 123, 38,  249, 118, 160, 102, 45,	238,
	    229, 74,  252, 78,	159, 234, 125, 51,  89,	 241, 18,  191, 102,
	    94,	 31,  85,  6,	66,  115, 212, 0,   9,	 124, 253, 198, 5,
	    190, 43,  236, 110, 84,  64,  238, 45,  20,	 207, 83,  249, 80,
	    84,	 46,  53,  240, 130, 196, 172, 201, 169, 168, 218, 139, 40,
	    37,	 84,  52,  9,	2,   131, 113, 202, 160, 80,  26,  132, 109,
	    228, 130, 36,  195, 6,   108, 89,  72,  5,	 73,  38,  1,	72,
	    194, 1,   16,  64,	65,  8,	  176, 96,  83,	 68,  82,  212, 8,
	    129, 217, 130, 129, 200, 180, 132, 163, 40,	 100, 33,  195, 9,
	    34,	 35,  82,  225, 22,  101, 96,  4,   48,	 138, 192, 32,	146,
	    8,	 68,  36,  199, 140, 219, 6,   9,   81,	 192, 96,  84,	194,
	    8,	 201, 152, 129, 217, 16,  102, 25,  38,	 138, 4,   153, 97,
	    147, 194, 65,  132, 2,   104, 19,  133, 48,	 27,  40,  136, 73,
	    66,	 33,  155, 52,	112, 20,  48,  142, 9,	 163, 13,  16,	16,
	    77,	 208, 40,  49,	226, 48,  141, 2,   133, 41,  24,  183, 4,
	    12,	 70,  129, 96,	34,  102, 25,  183, 136, 219, 168, 64,	35,
	    53,	 64,  156, 164, 140, 90,  144, 33,  16,	 148, 40,  80,	34,
	    81,	 160, 50,  97,	129, 2,	  77,  33,  198, 44,  160, 150, 100,
	    67,	 22,  112, 20,	69,  6,	  130, 16,  10,	 11,  196, 101, 224,
	    180, 77,  25,  134, 48,  225, 70,  110, 34,	 21,  77,  92,	182,
	    49,	 68,  66,  109, 97,  54,  137, 212, 160, 41,  196, 48,	78,
	    28,	 133, 4,   26,	72,  138, 64,  144, 108, 218, 178, 65,	210,
	    64,	 13,  144, 182, 101, 96,  40,  105, 32,	 0,   80,  32,	33,
	    104, 227, 144, 96,	225, 64,  136, 196, 136, 32,  73,  166, 133,
	    17,	 35,  9,   201, 150, 128, 19,  48,  104, 18,  34,  0,	19,
	    199, 109, 210, 162, 76,  67,  184, 9,   163, 200, 48,  203, 50,
	    114, 202, 66,  102, 89,  168, 141, 204, 0,	 112, 35,  23,	140,
	    16,	 133, 100, 192, 182, 36,  72,  38,  76,	 88,  192, 16,	91,
	    34,	 81,  10,  49,	98,  89,  24,  77,  68,	 20,  101, 145, 38,
	    133, 36,  165, 73,	8,   131, 141, 88,  200, 129, 160, 146, 37,
	    64,	 64,  81,  219, 22,  9,	  155, 128, 129, 164, 36,  81,	163,
	    70,	 130, 216, 50,	36,  218, 0,   44,  128, 8,   80,  156, 160,
	    133, 132, 196, 80,	144, 56,  109, 20,  73,	 112, 219, 16,	41,
	    209, 164, 9,   88,	24,  76,  67,  54,  104, 16,  41,  97,	28,
	    48,	 5,   145, 70,	145, 98,  0,   108, 11,	 36,  96,  25,	33,
	    140, 36,  20,  138, 27,  41,  109, 217, 166, 141, 18,  160, 129,
	    24,	 64,  108, 12,	23,  82,  227, 144, 140, 28,  0,   130, 132,
	    56,	 37,  155, 20,	134, 98,  18,  16,  96,	 54,  144, 162, 18,
	    42,	 24,  179, 100, 27,  64,  5,   137, 162, 16,  210, 54,	41,
	    32,	 38,  108, 66,	4,   40,  83,  184, 9,	 128, 164, 44,	20,
	    17,	 66,  28,  198, 49,  27,  196, 104, 132, 178, 0,   12,	57,
	    48,	 3,   199, 141, 204, 148, 64,  204, 180, 104, 4,   32,	81,
	    153, 20,  113, 17,	4,   130, 25,  200, 16,	 226, 150, 144, 80,
	    68,	 70,  161, 164, 1,   131, 184, 137, 74,	 8,   1,   3,	8,
	    136, 3,   4,   33,	154, 66,  70,  161, 180, 77,  88,  200, 32,
	    227, 182, 144, 144, 184, 64,  25,  167, 104, 208, 56,  8,	89,
	    0,	 97,  11,  55,	9,   34,  147, 81,  156, 178, 9,   75,	70,
	    128, 76,  4,   10,	136, 198, 17,  75,  68,	 32,  81,  134, 0,
	    132, 48,  0,   92,	20,  76,  26,  168, 140, 8,   151, 136, 34,
	    177, 109, 68,  198, 44,  73,  8,   76,  36,	 169, 109, 140, 24,
	    4,	 128, 32,  50,	34,  195, 45,  34,  54,	 77,  89,  162, 69,
	    216, 168, 45,  82,	162, 45,  89,  18,  80,	 76,  146, 137, 8,
	    72,	 128, 228, 152, 80,  164, 66,  73,  32,	 32,  65,  10,	16,
	    68,	 193, 150, 41,	12,  150, 77,  91,  54,	 145, 27,  21,	1,
	    74,	 148, 129, 16,	148, 128, 160, 68,  81,	 225, 0,   10,	145,
	    72,	 109, 161, 6,	73,  34,  194, 49,  12,	 18,  145, 74,	182,
	    72,	 11,  181, 128, 81,  66,  18,  227, 32,	 46,  148, 32,	33,
	    153, 54,  68,  145, 72,  101, 9,   201, 145, 36,  18,  13,	74,
	    6,	 14,  20,  181, 13,  194, 180, 65,  75,	 0,   104, 76,	48,
	    108, 10,  18,  48,	154, 192, 140, 17,  135, 81,  217, 40,	42,
	    76,	 56,  74,  75,	36,  112, 27,  2,   136, 88,  24,  100, 2,
	    193, 13,  32,  192, 48,  32,  2,   112, 3,	 8,   130, 36,	176,
	    8,	 0,   66,  66,	36,  200, 108, 136, 72,	 112, 217, 36,	42,
	    27,	 49,  129, 4,	51,  40,  25,  161, 97,	 91,  32,  48,	144,
	    190, 187, 177, 156, 133, 229, 141, 245, 193, 229, 1,   117, 118,
	    13,	 181, 103, 50,	71,  115, 15,  8,   79,	 8,   169, 108, 28,
	    245, 84,  118, 6,	188, 62,  63,  165, 159, 34,  113, 138, 52,
	    73,	 16,  127, 155, 19,  69,  65,  140, 101, 97,  30,  137, 166,
	    237, 250, 198, 183, 218, 65,  102, 30,  4,	 121, 108, 9,	79,
	    73,	 197, 183, 126, 91,  170, 19,  232, 29,	 214, 142, 22,	176,
	    177, 137, 138, 124, 227, 53,  170, 17,  27,	 237, 88,  160, 27,
	    73,	 187, 236, 235, 180, 215, 32,  101, 3,	 98,  40,  28,	219,
	    12,	 90,  249, 38,	247, 165, 5,   130, 114, 227, 13,  131, 47,
	    129, 52,  54,  41,	246, 162, 191, 111, 67,	 78,  1,   119, 88,
	    29,	 168, 195, 249, 27,  70,  15,  121, 210, 130, 55,  62,	63,
	    243, 153, 189, 182, 83,  201, 209, 143, 138, 4,   83,  227, 67,
	    22,	 32,  136, 184, 55,  234, 21,  104, 101, 104, 146, 219, 171,
	    247, 241, 231, 88,	32,  65,  68,  63,  41,	 210, 162, 94,	9,
	    102, 53,  252, 216, 80,  128, 57,  191, 152, 92,  147, 209, 147,
	    226, 203, 58,  130, 47,  39,  55,  133, 74,	 139, 218, 143, 212,
	    182, 179, 41,  202, 39,  25,  191, 230, 71,	 111, 105, 225, 44,
	    169, 240, 108, 116, 96,  75,  252, 101, 148, 100, 2,   125, 91,
	    60,	 132, 189, 192, 62,  58,  78,  201, 176, 152, 115, 3,	48,
	    211, 72,  22,  35,	34,  247, 198, 111, 164, 80,  142, 245, 49,
	    34,	 196, 38,  68,	163, 18,  129, 253, 137, 212, 20,  198, 162,
	    73,	 9,   126, 14,	224, 231, 91,  196, 214, 122, 122, 206, 191,
	    49,	 228, 165, 212, 136, 2,	  22,  75,  82,	 240, 89,  122, 215,
	    181, 158, 184, 252, 21,  15,  6,   130, 137, 225, 245, 131, 239,
	    68,	 55,  119, 10,	51,  201, 20,  122, 157, 202, 133, 62,	88,
	    238, 166, 95,  172, 107, 151, 88,  139, 251, 120, 194, 203, 57,
	    13,	 87,  241, 81,	91,  18,  12,  32,  39,	 36,  30,  11,	253,
	    87,	 53,  93,  83,	195, 26,  94,  21,  84,	 236, 188, 91,	189,
	    71,	 156, 150, 113, 64,  92,  53,  50,  190, 14,  54,  62,	23,
	    241, 85,  38,  190, 92,  211, 141, 103, 246, 5,   32,  89,	48,
	    105, 9,   76,  234, 63,  135, 8,   11,  91,	 61,  79,  152, 115,
	    152, 134, 139, 205, 112, 176, 236, 93,  82,	 101, 227, 151, 180,
	    108, 78,  88,  151, 21,  23,  122, 48,  89,	 254, 38,  114, 153,
	    90,	 220, 191, 127, 134, 145, 32,  81,  141, 91,  44,  131, 77,
	    88,	 239, 186, 245, 79,  248, 197, 222, 136, 183, 176, 195, 251,
	    113, 158, 4,   244, 226, 136, 21,  191, 9,	 0,   149, 166, 32,
	    211, 114, 75,  120, 83,  16,  2,   195, 129, 44,  79,  83,	34,
	    57,	 220, 120, 88,	45,  202, 48,  149, 227, 238, 197, 113, 72,
	    178, 62,  12,  121, 212, 70,  63,  146, 248, 217, 114, 222, 164,
	    197, 81,  65,  53,	180, 196, 206, 126, 196, 248, 88,  241, 137,
	    5,	 160, 67,  51,	129, 55,  176, 231, 214, 149, 65,  24,	234,
	    92,	 176, 201, 102, 188, 214, 4,   115, 181, 157, 93,  233, 78,
	    4,	 137, 15,  161, 36,  90,  247, 168, 3,	 197, 243, 157, 33,
	    201, 112, 165, 159, 5,   248, 12,  151, 213, 121, 159, 214, 99,
	    51,	 249, 153, 233, 153, 98,  241, 181, 94,	 218, 71,  107, 137,
	    95,	 168, 96,  244, 37,  230, 236, 123, 227, 154, 1,   9,	63,
	    158, 54,  196, 246, 9,   238, 93,  18,  222, 181, 50,  120, 116,
	    222, 120, 160, 19,	207, 209, 137, 216, 225, 6,   67,  163, 168,
	    132, 127, 135, 79,	205, 180, 0,   123, 214, 122, 169, 89,	252,
	    14,	 44,  192, 162, 181, 26,  144, 245, 241, 71,  156, 205, 94,
	    37,	 69,  76,  141, 8,   60,  14,  118, 169, 219, 24,  101, 238,
	    224, 97,  48,  11,	218, 55,  233, 65,  126, 7,   131, 237, 248,
	    132, 125, 79,  165, 125, 116, 135, 7,   96,	 224, 209, 243, 128,
	    109, 76,  65,  40,	21,  52,  150, 197, 232, 102, 31,  253, 243,
	    10,	 23,  132, 155, 79,  199, 177, 161, 28,	 102, 106, 250, 10,
	    196, 230, 10,  119, 27,  204, 198, 144, 191, 192, 167, 88,	233,
	    10,	 98,  239, 9,	94,  77,  85,  244, 142, 4,   114, 22,	77,
	    26,	 53,  187, 70,	98,  198, 106, 75,  197, 85,  192, 9,	120,
	    250, 5,   208, 184, 123, 53,  62,  234, 148, 143, 88,  165, 132,
	    248, 52,  18,  171, 85,  39,  56,  174, 196, 100, 223, 75,	249,
	    47,	 88,  56,  232, 54,  188, 103, 142, 182, 170, 125, 112, 135,
	    149, 250, 204, 116, 32,  165, 13,  40,  130, 203, 115, 169, 88,
	    213, 107, 230, 32,	21,  71,  103, 117, 115, 138, 168, 225, 180,
	    128, 191, 29,  129, 147, 130, 200, 221, 235, 98,  171, 182, 52,
	    242, 10,  41,  44,	223, 150, 101, 1,   142, 9,   61,  45,	47,
	    122, 44,  134, 220, 68,  179, 20,  27,  135, 158, 184, 29,	152,
	    85,	 81,  123, 91,	10,  25,  42,  8,   121, 245, 79,  97,	222,
	    225, 45,  40,  4,	47,  165, 28,  82,  184, 250, 67,  197, 88,
	    64,	 47,  144, 3,	131, 232, 121, 100, 28,	 25,  99,  11,	37,
	    15,	 187, 102, 79,	182, 109, 90,  123, 177, 233, 190, 32,	248,
	    203, 208, 168, 251, 194, 237, 197, 15,  98,	 240, 180, 18,	109,
	    120, 157, 201, 27,	174, 207, 53,  96,  241, 54,  134, 1,	253,
	    23,	 38,  5,   235, 94,  242, 232, 147, 119, 40,  85,  51,	240,
	    21,	 208, 115, 84,	201, 23,  242, 95,  214, 80,  169, 221, 24,
	    8,	 82,  184, 43,	231, 34,  135, 28,  23,	 97,  2,   140, 154,
	    8,	 105, 137, 1,	142, 96,  64,  124, 199, 116, 151, 77,	182,
	    89,	 54,  27,  253, 42,  130, 233, 11,  100, 163, 2,   104, 29,
	    237, 164, 202, 83,	157, 193, 141, 74,  231, 37,  110, 78,	182,
	    41,	 71,  150, 61,	148, 208, 207, 9,   41,	 82,  205, 107, 233,
	    21,	 104, 237, 117, 41,  3,	  43,  127, 7,	 22,  121, 128, 78,
	    103, 244, 34,  98,	79,  215, 241, 53,  201, 30,  141, 102, 123,
	    234, 40,  243, 34,	85,  237, 124, 102, 164, 109, 224, 246, 220,
	    243, 192, 6,   93,	142, 37,  174, 170, 135, 93,  16,  236, 48,
	    94,	 158, 117, 236, 107, 157, 80,  33,  217, 1,   91,  34,	71,
	    77,	 168, 173, 55,	243, 87,  212, 99,  169, 134, 32,  16,	209,
	    167, 35,  99,  80,	28,  104, 201, 153, 166, 101, 15,  223, 253,
	    247, 115, 19,  19,	249, 74,  101, 181, 229, 112, 205, 221, 88,
	    109, 5,   55,  146, 96,  191, 113, 246, 176, 203, 189, 224, 60,
	    161, 28,  134, 22,	61,  227, 135, 87,  111, 8,   186, 26,	65,
	    61,	 13,  125, 97,	3,   145, 83,  31,  19,	 216, 76,  108, 31,
	    221, 224, 20,  121, 35,  48,  71,  43,  64,	 0,   19,  4,	143,
	    151, 36,  143, 190, 167, 247, 81,  56,  198, 101, 214, 196, 211,
	    30,	 66,  29,  211, 169, 247, 63,  77,  156, 85,  163, 1,	68,
	    237, 156, 207, 85,	162, 57,  10,  60,  60,	 224, 167, 190, 171,
	    250, 121, 134, 68,	249, 164, 1,   89,  24,	 121, 178, 29,	184,
	    27,	 49,  12,  31,	210, 248, 244, 122, 49,	 254, 221, 53,	182,
	    183, 45,  65,  130, 226, 110, 41,  190, 87,	 75,  157, 8,	62,
	    218, 67,  156, 63,	243, 184, 147, 35,  78,	 144, 228, 115, 14,
	    173, 191, 114, 252, 197, 80,  2,   48,  148, 32,  220, 96,	80,
	    29,	 44,  230, 167, 249, 179, 42,  26,  108, 130, 173, 239, 82,
	    241, 171, 92,  101, 79,  162, 1,   1,   178, 47,  33,  120, 11,
	    11,	 201, 163, 31,	179, 109, 110, 253, 108, 161, 127, 167, 223,
	    162, 155, 100, 255, 176, 15,  154, 39,  174, 178, 109, 124, 231,
	    170, 175, 235, 112, 203, 99,  85,  79,  135, 240, 160, 178, 141,
	    11,	 232, 189, 248, 205, 158, 96,  106, 50,	 13,  115, 137, 155,
	    253, 159, 138, 233, 127, 57,  100, 53,  85,	 66,  221, 206, 118,
	    33,	 82,  121, 63,	39,  195, 172, 100, 160, 94,  186, 243, 36,
	    242, 184, 9,   149, 102, 214, 85,  105, 179, 198, 73,  249, 175,
	    80,	 14,  150, 54,	251, 77,  25,  71,  101, 141, 38,  229, 255,
	    255, 86,  140, 136, 96,  117, 190, 226, 150, 2,   48,  162, 104,
	    153, 189, 1,   141, 193, 209, 76,  111, 207, 34,  99,  146, 206,
	    221, 38,  72,  222, 216, 88,  34,  9,   50,	 125, 27,  158, 112,
	    231, 246, 115, 210, 34,  9,	  146, 131, 218, 255, 46,  254, 192,
	    196, 168, 252, 134, 39,  86,  112, 188, 180, 131, 103, 91,	233,
	    23,	 183, 234, 41,	117, 247, 146, 57,  199, 126, 113, 223, 68,
	    170, 109, 105, 231, 216, 141, 49,  197, 233, 91,  111, 66,	231,
	    227, 233, 52,  239, 114, 33,  238, 76,  253, 147, 227, 38,	121,
	    43,	 166, 33,  15,	61,  190, 235, 170, 158, 106, 183, 115, 202,
	    60,	 236, 118, 7,	173, 177, 52,  45,  12,	 134, 200, 170, 171,
	    188, 223, 240, 139, 133, 146, 48,  159, 181, 58,  175, 213, 62,
	    59,	 15,  228, 50,	88,  233, 46,  182, 137, 84,  136, 180, 222,
	    237, 189, 160, 248, 251, 149, 230, 231, 4,	 151, 3,   228, 42,
	    113, 244, 205, 2,	67,  124, 161, 64,  190, 125, 102, 33,	102,
	    218, 201, 70,  155, 253, 165, 245, 78,  21,	 150, 45,  244, 21,
	    44,	 172, 82,  59,	98,  198, 133, 226, 115, 82,  82,  224, 69,
	    163, 167, 7,   91,	228, 28,  2,   129, 63,	 66,  28,  120, 147,
	    39,	 213, 12,  221, 180, 244, 1,   243, 141, 19,  29,  239, 60,
	    174, 130, 75,  95,	14,  48,  129, 207, 152, 171, 211, 24};
	u8 expected_sig[] = {
	    208, 191, 220, 210, 104, 76,  47,  221, 99,	 210, 0,   51,	33,
	    211, 66,  198, 52,	44,  124, 141, 57,  216, 178, 196, 33,	236,
	    236, 125, 18,  206, 116, 170, 49,  5,   3,	 148, 60,  169, 31,
	    148, 65,  221, 71,	18,  249, 84,  89,  78,	 48,  29,  172, 28,
	    89,	 236, 198, 20,	252, 203, 215, 17,  11,	 154, 171, 93,	159,
	    138, 113, 180, 130, 79,  52,  157, 79,  230, 200, 24,  113, 178,
	    166, 151, 168, 175, 249, 160, 70,  173, 120, 140, 83,  62,	251,
	    5,	 229, 136, 29,	226, 68,  31,  73,  201, 143, 197, 215, 254,
	    98,	 40,  150, 55,	126, 129, 128, 161, 41,	 208, 8,   118, 37,
	    60,	 103, 250, 97,	11,  116, 103, 130, 186, 45,  103, 0,	221,
	    95,	 13,  139, 191, 229, 17,  104, 204, 57,	 104, 251, 100, 88,
	    42,	 225, 7,   130, 49,  192, 36,  242, 229, 171, 4,   102, 186,
	    174, 183, 240, 35,	127, 129, 126, 141, 227, 40,  91,  170, 22,
	    220, 159, 66,  222, 97,  93,  75,  131, 124, 31,  188, 169, 190,
	    197, 55,  220, 194, 5,   96,  126, 27,  23,	 90,  167, 110, 11,
	    96,	 156, 50,  154, 60,  33,  23,  236, 194, 247, 23,  169, 81,
	    235, 139, 20,  70,	49,  210, 87,  91,  11,	 33,  255, 249, 110,
	    191, 191, 244, 212, 11,  210, 151, 72,  234, 64,  117, 213, 36,
	    8,	 23,  112, 129, 203, 98,  144, 13,  187, 167, 66,  227, 92,
	    197, 49,  201, 223, 128, 103, 2,   136, 48,	 178, 185, 212, 110,
	    139, 204, 32,  234, 66,  107, 7,   39,  235, 217, 105, 202, 171,
	    141, 41,  57,  188, 206, 180, 167, 175, 184, 211, 12,  221, 1,
	    118, 14,  13,  25,	84,  25,  213, 72,  70,	 74,  159, 194, 150,
	    159, 194, 237, 199, 108, 87,  76,  145, 190, 8,   90,  176, 158,
	    165, 115, 101, 29,	196, 176, 142, 35,  146, 96,  75,  45,	170,
	    227, 195, 51,  76,	142, 124, 178, 111, 147, 225, 119, 230, 35,
	    200, 110, 149, 157, 129, 247, 250, 237, 0,	 239, 10,  44,	20,
	    178, 253, 27,  103, 59,  142, 2,   101, 228, 195, 28,  232, 133,
	    86,	 28,  173, 5,	180, 97,  70,  75,  117, 251, 24,  160, 97,
	    163, 38,  182, 221, 213, 1,	  157, 148, 209, 234, 221, 95,	151,
	    224, 135, 4,   112, 148, 155, 75,  56,  87,	 147, 71,  247, 129,
	    183, 102, 32,  73,	54,  203, 0,   117, 96,	 88,  69,  44,	142,
	    203, 169, 170, 123, 32,  77,  153, 198, 232, 18,  122, 159, 166,
	    58,	 68,  116, 195, 248, 236, 11,  148, 10,	 4,   208, 36,	62,
	    62,	 153, 123, 224, 10,  5,	  208, 79,  140, 89,  19,  132, 62,
	    152, 69,  127, 200, 64,  186, 38,  193, 69,	 62,  76,  93,	124,
	    18,	 123, 128, 69,	96,  174, 64,  164, 191, 19,  47,  11,	126,
	    35,	 117, 110, 104, 202, 45,  17,  232, 34,	 170, 180, 36,	202,
	    7,	 132, 150, 29,	129, 205, 90,  56,  31,	 135, 10,  194, 221,
	    81,	 89,  63,  119, 60,  249, 211, 64,  166, 254, 78,  147, 211,
	    195, 56,  60,  65,	237, 154, 230, 218, 180, 190, 45,  14,	173,
	    233, 244, 251, 110, 253, 108, 187, 190, 208, 151, 43,  81,	104,
	    65,	 97,  206, 171, 208, 224, 197, 136, 180, 229, 173, 190, 239,
	    173, 88,  163, 185, 29,  26,  217, 92,  229, 33,  246, 48,	150,
	    140, 85,  22,  185, 122, 159, 161, 45,  191, 100, 236, 162, 86,
	    27,	 228, 37,  189, 9,   68,  3,   9,   143, 125, 90,  126, 87,
	    116, 134, 177, 16,	41,  239, 173, 4,   156, 218, 0,   119, 172,
	    218, 161, 207, 146, 173, 58,  193, 120, 192, 100, 179, 186, 63,
	    178, 143, 26,  121, 19,  25,  95,  111, 35,	 9,   121, 185, 185,
	    178, 95,  86,  186, 15,  214, 104, 26,  122, 80,  39,  187, 237,
	    157, 29,  69,  71,	46,  138, 149, 80,  225, 142, 120, 195, 108,
	    175, 111, 67,  227, 200, 194, 116, 103, 106, 7,   116, 131, 30,
	    233, 225, 54,  196, 115, 243, 85,  224, 255, 153, 71,  188, 144,
	    21,	 94,  103, 50,	162, 58,  245, 50,  137, 15,  127, 197, 57,
	    195, 212, 124, 196, 254, 93,  191, 200, 174, 31,  30,  55,	244,
	    36,	 239, 146, 151, 67,  78,  251, 163, 19,	 57,  181, 189, 152,
	    242, 81,  245, 18,	21,  194, 110, 98,  36,	 41,  191, 191, 74,
	    113, 178, 104, 164, 250, 10,  23,  155, 119, 105, 163, 96,	40,
	    32,	 154, 109, 113, 85,  143, 71,  74,  214, 172, 230, 198, 148,
	    37,	 146, 97,  215, 134, 95,  243, 152, 134, 199, 167, 176, 9,
	    53,	 246, 35,  26,	101, 88,  229, 246, 43,	 180, 132, 76,	246,
	    132, 31,  108, 140, 32,  128, 31,  170, 16,	 154, 127, 55,	228,
	    205, 242, 127, 27,	128, 193, 23,  48,  55,	 95,  14,  154, 81,
	    38,	 199, 183, 180, 133, 205, 104, 69,  148, 243, 229, 184, 106,
	    83,	 184, 74,  141, 60,  92,  59,  132, 121, 97,  147, 228, 92,
	    197, 152, 19,  25,	192, 136, 6,   22,  183, 63,  190, 222, 42,
	    228, 9,   248, 89,	157, 76,  236, 203, 131, 86,  156, 156, 19,
	    53,	 139, 254, 192, 96,  240, 98,  144, 142, 78,  128, 17,	220,
	    248, 205, 100, 190, 122, 206, 84,  251, 211, 144, 196, 91,	206,
	    73,	 163, 180, 106, 182, 35,  30,  148, 103, 124, 199, 67,	32,
	    236, 203, 199, 77,	223, 47,  115, 82,  136, 41,  102, 117, 111,
	    94,	 72,  221, 34,	124, 168, 217, 21,  211, 119, 160, 111, 18,
	    152, 209, 218, 185, 234, 28,  38,  233, 87,	 185, 230, 117, 67,
	    138, 168, 53,  130, 39,  153, 214, 74,  56,	 65,  178, 186, 77,
	    64,	 105, 98,  51,	111, 51,  229, 168, 144, 167, 188, 196, 5,
	    89,	 157, 145, 182, 17,  145, 43,  216, 198, 65,  184, 134, 15,
	    88,	 112, 121, 140, 58,  203, 71,  42,  59,	 9,   206, 214, 61,
	    8,	 96,  17,  103, 138, 237, 15,  166, 34,	 134, 152, 183, 52,
	    34,	 29,  117, 49,	99,  88,  194, 37,  25,	 135, 154, 109, 6,
	    95,	 20,  170, 14,	33,  72,  97,  28,  219, 248, 216, 125, 3,
	    124, 71,  57,  47,	96,  253, 36,  71,  185, 97,  80,  35,	72,
	    99,	 181, 119, 213, 128, 102, 203, 182, 93,	 25,  117, 154, 134,
	    112, 220, 47,  33,	255, 97,  254, 2,   68,	 50,  26,  172, 0,
	    51,	 3,   121, 17,	217, 123, 246, 225, 30,	 181, 244, 181, 14,
	    66,	 40,  242, 145, 156, 59,  87,  111, 17,	 248, 163, 38,	111,
	    87,	 24,  131, 55,	232, 195, 221, 92,  120, 220, 17,  177, 88,
	    231, 13,  163, 60,	137, 40,  74,  53,  90,	 5,   179, 234, 3,
	    134, 161, 84,  22,	71,  118, 23,  138, 113, 87,  140, 198, 56,
	    17,	 198, 53,  140, 170, 108, 29,  153, 38,	 198, 19,  185, 159,
	    56,	 40,  2,   142, 240, 232, 203, 133, 177, 198, 91,  57,	159,
	    238, 195, 215, 116, 201, 221, 15,  194, 135, 169, 187, 210, 3,
	    130, 10,  250, 41,	1,   6,	  19,  13,  222, 104, 101, 121, 64,
	    37,	 246, 134, 39,	66,  194, 70,  74,  158, 91,  52,  92,	125,
	    55,	 100, 11,  97,	174, 245, 16,  185, 202, 246, 217, 67,	6,
	    41,	 207, 122, 53,	194, 148, 180, 17,  242, 156, 182, 208, 171,
	    172, 191, 135, 237, 88,  8,	  167, 175, 255, 71,  122, 139, 196,
	    200, 80,  196, 87,	172, 209, 113, 242, 147, 39,  229, 252, 243,
	    55,	 97,  155, 222, 215, 80,  57,  214, 58,	 21,  94,  104, 22,
	    85,	 106, 68,  106, 167, 146, 189, 255, 25,	 201, 27,  250, 151,
	    62,	 174, 57,  122, 123, 18,  236, 31,  116, 254, 27,  98,	69,
	    61,	 95,  212, 68,	162, 205, 165, 238, 73,	 235, 12,  75,	145,
	    228, 102, 104, 79,	115, 39,  253, 17,  84,	 74,  167, 186, 77,
	    134, 78,  142, 228, 157, 192, 237, 87,  35,	 252, 125, 243, 224,
	    142, 44,  38,  20,	86,  6,	  93,  226, 170, 41,  235, 185, 29,
	    87,	 209, 43,  136, 75,  178, 51,  75,  164, 189, 58,  50,	107,
	    152, 181, 52,  4,	253, 157, 0,   181, 105, 82,  19,  125, 117,
	    186, 179, 99,  210, 197, 212, 234, 165, 216, 124, 144, 251, 25,
	    3,	 219, 38,  177, 221, 90,  92,  56,  185, 135, 80,  99,	193,
	    200, 160, 216, 155, 251, 215, 236, 21,  44,	 191, 137, 121, 11,
	    164, 9,   89,  195, 159, 233, 101, 6,   68,	 172, 201, 243, 217,
	    0,	 53,  107, 74,	105, 156, 200, 3,   38,	 227, 95,  76,	109,
	    76,	 74,  186, 145, 157, 68,  123, 42,  132, 144, 113, 39,	160,
	    235, 107, 249, 249, 237, 22,  118, 78,  213, 17,  96,  251, 252,
	    147, 241, 121, 58,	107, 77,  218, 85,  156, 88,  169, 202, 143,
	    255, 58,  121, 26,	228, 195, 30,  158, 150, 132, 159, 176, 46,
	    110, 172, 229, 243, 93,  101, 103, 237, 191, 85,  91,  208, 159,
	    81,	 15,  189, 25,	55,  57,  185, 82,  218, 205, 124, 217, 233,
	    223, 80,  50,  179, 67,  171, 184, 62,  227, 61,  194, 46,	159,
	    27,	 20,  139, 152, 23,  8,	  83,  68,  87,	 104, 118, 74,	153,
	    123, 89,  136, 232, 196, 166, 52,  16,  91,	 51,  68,  110, 69,
	    224, 246, 37,  68,	119, 95,  199, 184, 182, 240, 63,  220, 92,
	    84,	 41,  90,  154, 170, 209, 208, 193, 100, 95,  115, 74,	87,
	    188, 149, 197, 175, 121, 163, 152, 152, 207, 225, 154, 226, 184,
	    245, 154, 189, 116, 75,  202, 230, 192, 220, 193, 64,  32,	14,
	    154, 185, 93,  165, 30,  67,  58,  75,  67,	 223, 111, 76,	197,
	    254, 49,  125, 23,	126, 206, 131, 142, 37,	 47,  2,   105, 227,
	    250, 112, 226, 248, 8,   130, 97,  96,  197, 15,  138, 132, 191,
	    6,	 161, 115, 162, 114, 169, 112, 231, 85,	 178, 168, 108, 207,
	    198, 69,  54,  26,	67,  128, 161, 55,  224, 79,  77,  238, 25,
	    70,	 93,  124, 10,	47,  248, 179, 249, 204, 18,  75,  115, 70,
	    227, 214, 214, 112, 24,  159, 251, 223, 30,	 151, 174, 89,	68,
	    131, 40,  150, 80,	245, 126, 252, 39,  29,	 236, 3,   97,	43,
	    138, 9,   238, 189, 72,  60,  119, 171, 82,	 63,  187, 53,	33,
	    172, 25,  155, 84,	39,  23,  149, 12,  240, 179, 193, 224, 225,
	    34,	 49,  95,  147, 109, 170, 177, 238, 68,	 190, 157, 221, 29,
	    242, 116, 37,  45,	45,  127, 170, 246, 207, 108, 30,  231, 43,
	    93,	 219, 157, 159, 111, 110, 87,  118, 140, 77,  199, 129, 123,
	    106, 36,  220, 29,	199, 187, 173, 154, 119, 198, 255, 203, 247,
	    208, 6,   8,   99,	111, 82,  146, 108, 226, 215, 102, 65,	236,
	    68,	 127, 229, 174, 211, 58,  93,  47,  254, 216, 117, 205, 206,
	    192, 196, 129, 60,	40,  174, 251, 7,   176, 14,  142, 117, 104,
	    174, 150, 63,  15,	43,  193, 133, 26,  245, 136, 209, 101, 107,
	    108, 240, 128, 122, 214, 137, 65,  5,   87,	 135, 33,  49,	168,
	    19,	 209, 194, 172, 183, 11,  96,  9,   89,	 17,  140, 188, 28,
	    210, 254, 28,  186, 83,  177, 77,  41,  84,	 140, 34,  252, 68,
	    99,	 78,  217, 105, 179, 10,  13,  84,  12,	 70,  73,  77,	68,
	    168, 216, 33,  30,	187, 121, 214, 194, 240, 246, 171, 140, 203,
	    214, 103, 37,  130, 79,  132, 84,  127, 139, 199, 249, 146, 17,
	    150, 183, 187, 13,	169, 244, 140, 122, 53,	 117, 226, 227, 37,
	    48,	 39,  218, 218, 191, 10,  114, 172, 211, 26,  155, 227, 127,
	    174, 51,  44,  239, 194, 51,  85,  165, 89,	 53,  48,  12,	104,
	    170, 52,  105, 57,	113, 40,  185, 188, 245, 99,  195, 176, 23,
	    136, 23,  212, 168, 184, 191, 158, 207, 58,	 188, 140, 115, 251,
	    133, 40,  250, 212, 84,  127, 50,  177, 200, 132, 242, 235, 110,
	    96,	 236, 200, 227, 0,   23,  142, 116, 97,	 84,  87,  158, 128,
	    123, 16,  29,  240, 73,  56,  15,  114, 44,	 46,  156, 150, 72,
	    34,	 244, 210, 175, 193, 8,	  163, 232, 42,	 53,  30,  221, 250,
	    138, 60,  174, 206, 181, 1,	  233, 27,  233, 242, 85,  42,	201,
	    102, 94,  195, 105, 242, 72,  253, 213, 51,	 249, 116, 217, 234,
	    198, 115, 215, 196, 53,  107, 50,  178, 140, 129, 103, 59,	158,
	    70,	 193, 195, 53,	249, 232, 147, 193, 151, 86,  233, 229, 86,
	    12,	 2,   25,  132, 106, 35,  100, 152, 50,	 110, 218, 58,	247,
	    144, 82,  191, 138, 4,   53,  25,  94,  124, 60,  155, 188, 171,
	    145, 205, 2,   110, 96,  88,  166, 76,  24,	 6,   128, 195, 125,
	    188, 151, 41,  240, 45,  187, 251, 116, 119, 92,  173, 212, 118,
	    192, 22,  164, 22,	161, 25,  42,  51,  28,	 194, 193, 89,	59,
	    112, 94,  44,  14,	207, 76,  83,  18,  255, 206, 97,  251, 62,
	    173, 205, 50,  52,	244, 167, 39,  140, 73,	 196, 96,  82,	31,
	    153, 149, 97,  116, 56,  101, 179, 180, 120, 237, 11,  75,	209,
	    17,	 15,  5,   154, 166, 11,  187, 91,  167, 145, 225, 150, 235,
	    245, 188, 42,  73,	247, 250, 70,  186, 137, 170, 109, 218, 117,
	    32,	 124, 108, 71,	31,  125, 112, 36,  193, 46,  110, 207, 108,
	    162, 107, 37,  109, 44,  47,  0,   208, 175, 110, 253, 83,	6,
	    206, 240, 41,  245, 143, 80,  91,  240, 56,	 203, 209, 101, 198,
	    163, 244, 18,  49,	175, 73,  154, 57,  210, 212, 207, 197, 117,
	    190, 43,  171, 90,	98,  210, 109, 187, 242, 168, 220, 109, 142,
	    126, 6,   20,  157, 99,  108, 71,  87,  14,	 243, 83,  129, 246,
	    144, 62,  115, 97,	144, 6,	  34,  132, 239, 111, 94,  103, 91,
	    176, 56,  198, 82,	202, 197, 165, 245, 17,	 214, 201, 4,	59,
	    217, 168, 174, 72,	218, 201, 81,  241, 241, 10,  53,  56,	67,
	    75,	 86,  90,  142, 184, 187, 215, 219, 228, 40,  69,  85,	99,
	    116, 138, 158, 161, 175, 176, 183, 193, 204, 211, 214, 227, 236,
	    245, 248, 255, 3,	25,  36,  38,  45,  49,	 66,  97,  104, 110,
	    120, 121, 135, 165, 171, 175, 178, 210, 218, 229, 247, 250, 37,
	    38,	 87,  90,  100, 101, 111, 115, 136, 147, 175, 208, 219, 255,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   13,	33,
	    55,	 69,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
	    0};
	ASSERT_EQ(verify(msg, &pk, &sig), 0, "verify");
	ASSERT(!memcmp(expected_sig, sig.data, sizeof(expected_sig)),
	       "expected sig");
	ASSERT(!memcmp(expected_sk, sk.data, sizeof(sk)), "expected sk");
	ASSERT(!memcmp(expected_pk, pk.data, sizeof(pk)), "expected pk");
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
	__attribute__((aligned(32))) u8 m[32];
	__attribute__((aligned(32))) u8 seed[32];

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

