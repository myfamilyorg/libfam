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
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ", sk.data[i]);
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
	    140, 158, 182, 185, 41,  64,  205, 107, 196, 133, 221, 251, 80,
	    107, 98,  154, 133, 244, 184, 99,  178, 187, 240, 202, 6,	154,
	    209, 5,   231, 124, 193, 186, 112, 178, 146, 12,  88,  53,	74,
	    58,	 89,  135, 117, 201, 177, 6,   46,  188, 50,  121, 8,	135,
	    161, 235, 116, 162, 134, 128, 98,  149, 179, 206, 242, 161, 39,
	    166, 40,  171, 151, 180, 31,  124, 113, 197, 215, 51,  54,	249,
	    204, 57,  140, 23,	126, 192, 6,   155, 214, 137, 59,  133, 135,
	    63,	 149, 135, 126, 243, 150, 58,  203, 145, 47,  56,  124, 51,
	    101, 128, 63,  23,	102, 232, 240, 37,  209, 41,  196, 22,	118,
	    34,	 206, 90,  130, 72,  99,  9,   165, 98,	 54,  204, 4,	121,
	    130, 197, 6,   3,	104, 38,  208, 27,  150, 137, 123, 17,	9,
	    178, 37,  68,  66,	11,  100, 82,  186, 117, 100, 23,  25,	186,
	    17,	 2,   216, 113, 194, 121, 173, 129, 146, 206, 152, 252, 7,
	    141, 154, 117, 114, 162, 58,  112, 161, 112, 131, 33,  163, 199,
	    73,	 76,  135, 250, 172, 129, 20,  175, 195, 232, 203, 149, 37,
	    191, 189, 152, 3,	247, 19,  103, 109, 1,	 200, 38,  76,	83,
	    82,	 251, 9,   153, 210, 144, 182, 226, 103, 65,  150, 80,	229,
	    179, 135, 63,  208, 192, 9,	  88,  187, 3,	 252, 86,  123, 38,
	    197, 132, 149, 148, 16,  0,	  68,  43,  153, 54,  42,  181, 59,
	    23,	 84,  13,  167, 100, 172, 176, 40,  164, 147, 122, 24,	173,
	    216, 36,  235, 101, 66,  80,  160, 1,   43,	 166, 77,  168, 16,
	    113, 122, 107, 123, 223, 147, 88,  207, 18,	 38,  6,   21,	76,
	    175, 23,  165, 128, 48,  111, 198, 217, 195, 114, 233, 146, 183,
	    252, 187, 241, 65,	77,  20,  210, 112, 245, 121, 17,  161, 105,
	    5,	 81,  67,  148, 71,  188, 158, 116, 85,	 88,  169, 59,	205,
	    251, 67,  145, 223, 231, 113, 4,   215, 119, 51,  55,  162, 116,
	    1,	 189, 161, 105, 92,  71,  20,  22,  88,	 50,  48,  227, 214,
	    73,	 2,   212, 141, 64,  225, 11,  196, 54,	 2,   123, 217, 78,
	    254, 233, 80,  159, 107, 166, 205, 151, 154, 200, 25,  160, 164,
	    5,	 29,  179, 84,	141, 48,  186, 195, 45,	 123, 156, 90,	105,
	    50,	 112, 181, 58,	180, 44,  177, 217, 34,	 161, 185, 58,	205,
	    66,	 234, 11,  98,	229, 96,  201, 176, 31,	 105, 120, 82,	12,
	    202, 187, 169, 224, 154, 13,  247, 75,  78,	 85,  17,  235, 147,
	    120, 20,  153, 31,	104, 131, 24,  242, 235, 167, 32,  82,	181,
	    125, 149, 46,  198, 167, 114, 95,  10,  54,	 143, 250, 38,	175,
	    39,	 153, 195, 156, 81,  97,  133, 144, 242, 105, 152, 165, 53,
	    14,	 144, 146, 174, 45,  147, 28,  58,  145, 170, 5,   118, 200,
	    49,	 22,  103, 188, 122, 70,  48,  181, 157, 165, 100, 25,	101,
	    56,	 103, 59,  241, 174, 52,  224, 63,  165, 50,  94,  253, 26,
	    67,	 49,  208, 193, 34,  73,  150, 73,  86,	 170, 11,  48,	131,
	    157, 210, 199, 81,	150, 82,  127, 197, 178, 219, 20,  130, 195,
	    6,	 85,  22,  9,	88,  143, 168, 53,  171, 247, 173, 65,	213,
	    70,	 143, 50,  121, 151, 54,  205, 195, 179, 126, 56,  165, 87,
	    17,	 167, 177, 86,	171, 78,  218, 136, 162, 190, 183, 197, 86,
	    76,	 174, 243, 178, 148, 38,  74,  169, 227, 64,  33,  22,	200,
	    138, 84,  0,   186, 180, 116, 11,  102, 104, 126, 137, 231, 202,
	    63,	 50,  100, 8,	114, 110, 67,  248, 198, 160, 26,  73,	39,
	    241, 69,  255, 147, 119, 159, 225, 21,  202, 121, 88,  135, 234,
	    142, 6,   196, 199, 193, 12,  185, 202, 28,	 186, 248, 131, 203,
	    134, 200, 39,  118, 179, 207, 120, 179, 160, 86,  244, 118, 183,
	    203, 128, 210, 138, 140, 87,  211, 3,   227, 54,  42,  107, 176,
	    97,	 227, 146, 161, 117, 91,  29,  254, 176, 36,  175, 20,	36,
	    126, 185, 104, 227, 133, 126, 49,  171, 88,	 181, 118, 96,	200,
	    105, 116, 12,  160, 66,  200, 188, 97,  156, 144, 177, 142, 53,
	    129, 70,  118, 105, 119, 76,  178, 50,  130, 114, 174, 108, 173,
	    40,	 180, 177, 131, 0,   97,  185, 236, 13,	 81,  209, 111, 169,
	    166, 88,  33,  25,	71,  245, 136, 77,  150, 2,   74,  56,	40,
	    147, 54,  164, 119, 153, 132, 130, 56,  166, 94,  185, 224, 29,
	    243, 97,  158, 236, 39,  19,  97,  100, 169, 186, 164, 43,	145,
	    80,	 201, 39,  241, 70,  121, 236, 164, 18,	 155, 159, 54,	24,
	    138, 111, 186, 132, 17,  201, 58,  125, 58,	 207, 220, 44,	105,
	    191, 3,   68,  91,	22,  92,  7,   161, 191, 168, 186, 195, 118,
	    241, 73,  143, 88,	172, 47,  108, 112, 167, 0,   24,  192, 112,
	    1,	 17,  116, 55,	224, 91,  26,  206, 136, 90,  123, 147, 201,
	    167, 103, 41,  211, 136, 166, 209, 50,  130, 173, 55,  19,	82,
	    100, 80,  26,  67,	26,  220, 87,  203, 184, 172, 182, 219, 120,
	    190, 70,  144, 14,	107, 18,  18,  156, 167, 152, 173, 204, 141,
	    234, 186, 65,  149, 100, 65,  28,  179, 127, 190, 54,  167, 95,
	    136, 130, 118, 51,	129, 118, 36,  100, 22,	 167, 20,  39,	220,
	    143, 17,  7,   88,	212, 54,  23,  163, 58,	 5,   133, 68,	181,
	    215, 91,  199, 76,	104, 22,  14,  16,  66,	 132, 98,  42,	65,
	    53,	 148, 73,  96,	189, 139, 112, 137, 81,	 113, 123, 170, 160,
	    74,	 11,  186, 107, 209, 22,  67,  153, 25,	 2,   234, 215, 25,
	    158, 198, 169, 86,	81,  67,  36,  108, 163, 226, 22,  37,	50,
	    137, 91,  58,  216, 145, 35,  102, 74,  52,	 172, 147, 94,	235,
	    71,	 229, 138, 165, 7,   226, 100, 70,  75,	 201, 242, 146, 172,
	    32,	 74,  92,  18,	213, 25,  206, 188, 174, 66,  211, 165, 74,
	    17,	 77,  160, 115, 58,  60,  56,  1,   7,	 49,  92,  115, 218,
	    11,	 97,  67,  9,	44,  232, 164, 228, 81,	 6,   100, 7,	179,
	    93,	 224, 172, 136, 154, 77,  176, 242, 77,	 142, 71,  141, 181,
	    83,	 75,  14,  116, 123, 79,  87,  102, 112, 38,  68,  194, 9,
	    98,	 163, 234, 199, 123, 19,  120, 51,  187, 12,  120, 252, 148,
	    68,	 172, 139, 225, 208, 112, 227, 200, 77,	 195, 59,  205, 93,
	    69,	 178, 53,  170, 113, 177, 168, 199, 59,	 144, 100, 229, 196,
	    206, 160, 241, 144, 93,  134, 201, 135, 204, 172, 52,  85,	191,
	    28,	 57,  82,  204, 68,  170, 105, 214, 93,	 188, 246, 116, 111,
	    219, 149, 42,  52,	176, 239, 40,  67,  18,	 232, 184, 191, 74,
	    187, 68,  132, 198, 68,  167, 59,  64,  22,	 57,  245, 24,	61,
	    85,	 214, 156, 185, 240, 127, 181, 188, 196, 23,  140, 207, 124,
	    38,	 174, 250, 30,	19,  136, 6,   35,  19,	 153, 114, 61,	42,
	    183, 70,  185, 223, 50,  0,	  13,  111, 183, 61,  118, 47,	189,
	    227, 89,  26,  152, 245, 247, 226, 81,  118, 187, 105, 46,	106,
	    254, 127, 233, 6,	101, 101, 71,  193, 226, 6,   111, 221, 81,
	    46,	 3,   170, 159, 206, 74,  103, 88,  225, 127, 94,  247, 32,
	    217, 192, 116, 83,	197, 110, 27,  236, 162, 217, 187, 31,	127,
	    6,	 241, 183, 237, 108, 237, 8,   120, 98,	 1,   193, 234, 24,
	    1,	 155, 246, 12,	197, 174, 171};
	u8 expected_pk[] = {
	    112, 181, 58,  180, 44,  177, 217, 34,  161, 185, 58,  205, 66,
	    234, 11,  98,  229, 96,  201, 176, 31,  105, 120, 82,  12,	202,
	    187, 169, 224, 154, 13,  247, 75,  78,  85,	 17,  235, 147, 120,
	    20,	 153, 31,  104, 131, 24,  242, 235, 167, 32,  82,  181, 125,
	    149, 46,  198, 167, 114, 95,  10,  54,  143, 250, 38,  175, 39,
	    153, 195, 156, 81,	97,  133, 144, 242, 105, 152, 165, 53,	14,
	    144, 146, 174, 45,	147, 28,  58,  145, 170, 5,   118, 200, 49,
	    22,	 103, 188, 122, 70,  48,  181, 157, 165, 100, 25,  101, 56,
	    103, 59,  241, 174, 52,  224, 63,  165, 50,	 94,  253, 26,	67,
	    49,	 208, 193, 34,	73,  150, 73,  86,  170, 11,  48,  131, 157,
	    210, 199, 81,  150, 82,  127, 197, 178, 219, 20,  130, 195, 6,
	    85,	 22,  9,   88,	143, 168, 53,  171, 247, 173, 65,  213, 70,
	    143, 50,  121, 151, 54,  205, 195, 179, 126, 56,  165, 87,	17,
	    167, 177, 86,  171, 78,  218, 136, 162, 190, 183, 197, 86,	76,
	    174, 243, 178, 148, 38,  74,  169, 227, 64,	 33,  22,  200, 138,
	    84,	 0,   186, 180, 116, 11,  102, 104, 126, 137, 231, 202, 63,
	    50,	 100, 8,   114, 110, 67,  248, 198, 160, 26,  73,  39,	241,
	    69,	 255, 147, 119, 159, 225, 21,  202, 121, 88,  135, 234, 142,
	    6,	 196, 199, 193, 12,  185, 202, 28,  186, 248, 131, 203, 134,
	    200, 39,  118, 179, 207, 120, 179, 160, 86,	 244, 118, 183, 203,
	    128, 210, 138, 140, 87,  211, 3,   227, 54,	 42,  107, 176, 97,
	    227, 146, 161, 117, 91,  29,  254, 176, 36,	 175, 20,  36,	126,
	    185, 104, 227, 133, 126, 49,  171, 88,  181, 118, 96,  200, 105,
	    116, 12,  160, 66,	200, 188, 97,  156, 144, 177, 142, 53,	129,
	    70,	 118, 105, 119, 76,  178, 50,  130, 114, 174, 108, 173, 40,
	    180, 177, 131, 0,	97,  185, 236, 13,  81,	 209, 111, 169, 166,
	    88,	 33,  25,  71,	245, 136, 77,  150, 2,	 74,  56,  40,	147,
	    54,	 164, 119, 153, 132, 130, 56,  166, 94,	 185, 224, 29,	243,
	    97,	 158, 236, 39,	19,  97,  100, 169, 186, 164, 43,  145, 80,
	    201, 39,  241, 70,	121, 236, 164, 18,  155, 159, 54,  24,	138,
	    111, 186, 132, 17,	201, 58,  125, 58,  207, 220, 44,  105, 191,
	    3,	 68,  91,  22,	92,  7,	  161, 191, 168, 186, 195, 118, 241,
	    73,	 143, 88,  172, 47,  108, 112, 167, 0,	 24,  192, 112, 1,
	    17,	 116, 55,  224, 91,  26,  206, 136, 90,	 123, 147, 201, 167,
	    103, 41,  211, 136, 166, 209, 50,  130, 173, 55,  19,  82,	100,
	    80,	 26,  67,  26,	220, 87,  203, 184, 172, 182, 219, 120, 190,
	    70,	 144, 14,  107, 18,  18,  156, 167, 152, 173, 204, 141, 234,
	    186, 65,  149, 100, 65,  28,  179, 127, 190, 54,  167, 95,	136,
	    130, 118, 51,  129, 118, 36,  100, 22,  167, 20,  39,  220, 143,
	    17,	 7,   88,  212, 54,  23,  163, 58,  5,	 133, 68,  181, 215,
	    91,	 199, 76,  104, 22,  14,  16,  66,  132, 98,  42,  65,	53,
	    148, 73,  96,  189, 139, 112, 137, 81,  113, 123, 170, 160, 74,
	    11,	 186, 107, 209, 22,  67,  153, 25,  2,	 234, 215, 25,	158,
	    198, 169, 86,  81,	67,  36,  108, 163, 226, 22,  37,  50,	137,
	    91,	 58,  216, 145, 35,  102, 74,  52,  172, 147, 94,  235, 71,
	    229, 138, 165, 7,	226, 100, 70,  75,  201, 242, 146, 172, 32,
	    74,	 92,  18,  213, 25,  206, 188, 174, 66,	 211, 165, 74,	17,
	    77,	 160, 115, 58,	60,  56,  1,   7,   49,	 92,  115, 218, 11,
	    97,	 67,  9,   44,	232, 164, 228, 81,  6,	 100, 7,   179, 93,
	    224, 172, 136, 154, 77,  176, 242, 77,  142, 71,  141, 181, 83,
	    75,	 14,  116, 123, 79,  87,  102, 112, 38,	 68,  194, 9,	98,
	    163, 234, 199, 123, 19,  120, 51,  187, 12,	 120, 252, 148, 68,
	    172, 139, 225, 208, 112, 227, 200, 77,  195, 59,  205, 93,	69,
	    178, 53,  170, 113, 177, 168, 199, 59,  144, 100, 229, 196, 206,
	    160, 241, 144, 93,	134, 201, 135, 204, 172, 52,  85,  191, 28,
	    57,	 82,  204, 68,	170, 105, 214, 93,  188, 246, 116, 111, 219,
	    149, 42,  52,  176, 239, 40,  67,  18,  232, 184, 191, 74,	187,
	    68,	 132, 198, 68,	167, 59,  64,  22,  57,	 245, 24,  61,	85,
	    214, 156, 185, 240, 127, 181, 188, 196, 23,	 140, 207, 124, 38,
	    174, 250, 30,  19,	136, 6,	  35,  19,  153, 114, 61,  42,	183,
	    70,	 185, 223, 50,	0,   13,  111, 183, 61,	 118, 47,  189, 227,
	    89,	 26,  152, 245, 247, 226, 81};

	ASSERT(!fastmemcmp(pk.data, expected_pk, sizeof(pk)), "pk");
	ASSERT(!fastmemcmp(sk.data, expected_sk, sizeof(sk)), "sk");
	enc(&ct, &ss_bob, &pk, &rng);
	u8 expected_ct[] = {
	    140, 36,  233, 95,	39,  194, 178, 79,  99,	 122, 192, 146, 238,
	    76,	 78,  28,  245, 38,  219, 181, 218, 247, 185, 146, 119, 44,
	    175, 44,  109, 131, 212, 195, 3,   32,  28,	 67,  174, 74,	177,
	    246, 73,  235, 225, 166, 181, 233, 163, 136, 160, 80,  165, 9,
	    25,	 182, 100, 234, 236, 180, 177, 54,  192, 227, 188, 85,	80,
	    167, 43,  94,  238, 55,  227, 238, 44,  37,	 126, 101, 122, 85,
	    113, 207, 78,  206, 114, 164, 15,  30,  221, 213, 90,  131, 59,
	    60,	 42,  189, 86,	242, 191, 34,  190, 97,	 43,  199, 48,	139,
	    90,	 239, 52,  150, 103, 65,  113, 14,  230, 135, 223, 253, 185,
	    207, 225, 224, 103, 19,  156, 11,  169, 59,	 146, 16,  192, 37,
	    94,	 194, 234, 240, 189, 177, 51,  120, 55,	 231, 103, 193, 99,
	    48,	 175, 128, 253, 253, 79,  107, 125, 220, 164, 203, 162, 194,
	    214, 80,  157, 135, 110, 128, 249, 223, 84,	 21,  30,  89,	210,
	    254, 35,  251, 23,	165, 248, 232, 128, 79,	 127, 254, 56,	108,
	    204, 153, 22,  86,	198, 59,  74,  140, 5,	 47,  107, 254, 231,
	    21,	 1,   133, 69,	195, 83,  57,  240, 122, 13,  60,  213, 92,
	    89,	 89,  241, 89,	153, 168, 164, 193, 124, 186, 96,  250, 58,
	    176, 198, 179, 244, 5,   137, 97,  16,  252, 98,  74,  82,	136,
	    155, 220, 20,  126, 118, 6,	  253, 34,  109, 147, 219, 83,	36,
	    214, 39,  7,   246, 241, 197, 177, 54,  57,	 44,  144, 234, 128,
	    67,	 49,  168, 67,	126, 63,  226, 177, 40,	 119, 204, 131, 0,
	    75,	 204, 97,  178, 158, 37,  239, 3,   216, 168, 216, 104, 207,
	    103, 108, 179, 25,	82,  94,  190, 237, 161, 186, 178, 197, 21,
	    239, 65,  80,  6,	124, 1,	  30,  168, 75,	 23,  181, 62,	65,
	    59,	 241, 197, 66,	119, 213, 128, 187, 201, 121, 241, 201, 12,
	    5,	 194, 81,  35,	107, 187, 252, 102, 198, 5,   122, 196, 157,
	    160, 75,  130, 87,	252, 50,  131, 41,  157, 114, 22,  173, 124,
	    241, 75,  6,   239, 1,   26,  158, 237, 81,	 229, 63,  8,	100,
	    69,	 231, 235, 14,	90,  51,  73,  203, 237, 187, 125, 115, 31,
	    12,	 190, 138, 83,	70,  176, 183, 74,  148, 111, 132, 236, 117,
	    109, 148, 67,  106, 39,  223, 49,  195, 232, 161, 24,  157, 154,
	    115, 4,   51,  112, 234, 3,	  240, 247, 137, 68,  18,  57,	17,
	    46,	 93,  117, 29,	138, 27,  202, 137, 190, 48,  66,  108, 248,
	    203, 164, 63,  150, 127, 240, 11,  187, 52,	 125, 92,  64,	154,
	    45,	 254, 204, 219, 210, 11,  87,  138, 132, 158, 44,  85,	186,
	    77,	 207, 33,  119, 158, 245, 224, 178, 4,	 122, 44,  158, 79,
	    61,	 238, 250, 1,	82,  39,  61,  147, 163, 224, 65,  248, 175,
	    196, 96,  34,  39,	230, 63,  159, 211, 199, 39,  129, 36,	212,
	    117, 6,   144, 71,	208, 190, 45,  7,   251, 209, 33,  26,	150,
	    83,	 75,  189, 179, 193, 170, 168, 200, 199, 179, 6,   149, 58,
	    233, 162, 94,  249, 224, 31,  13,  175, 53,	 72,  126, 238, 146,
	    102, 103, 21,  115, 104, 198, 13,  183, 17,	 104, 178, 38,	29,
	    254, 200, 110, 32,	121, 104, 108, 6,   108, 123, 120, 61,	215,
	    28,	 231, 69,  245, 100, 209, 195, 227, 37,	 26,  212, 105, 193,
	    71,	 207, 176, 147, 147, 96,  73,  139, 186, 31,  109, 238, 153,
	    78,	 212, 221, 251, 179, 69,  237, 143, 60,	 193, 194, 58,	6,
	    96,	 85,  63,  179, 242, 97,  210, 67,  26,	 79,  3,   129, 30,
	    48,	 185, 169, 13,	80,  1,	  90,  205, 104, 244, 11,  58,	68,
	    43,	 20,  213, 250, 123, 244, 137, 73,  43,	 119, 61,  22,	172,
	    150, 212, 49,  40,	169, 25,  56,  164, 44,	 70,  198, 241, 89,
	    116, 56,  58,  215, 225, 201, 166, 242, 4,	 162, 67,  203, 70,
	    137, 112, 76,  54,	236, 245, 235, 200, 176, 26,  93,  253, 40,
	    81,	 217, 19,  54,	217, 88,  192, 205, 228, 116, 223, 185, 242,
	    212, 187, 202, 231, 104, 224, 27,  52,  58,	 25,  167, 235, 13,
	    85,	 227, 122, 117, 156, 39,  35,  209, 218, 40,  254, 176, 244,
	    15,	 69,  157, 136, 120, 241, 190, 179, 240, 35,  68,  57,	231,
	    100, 220, 212, 224, 118, 44,  1,   156, 43,	 44,  217, 183, 124,
	    31,	 232, 86,  240, 190, 33,  243, 242, 169, 101, 142, 143, 180,
	    177, 213, 62,  195, 0,   235, 145, 241, 170, 43,  98,  159, 51,
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
	    200, 145, 3,   61,	87,  60,  161, 216, 163, 12,  187, 97,	20,
	    232, 81,  181, 109, 204, 160, 86,  84,  77,	 205, 77,  79,	64,
	    5,	 161, 211, 167, 60,  21,  4,   90,  85,	 219, 150, 164, 49,
	    145, 157, 248, 90,	115, 16,  146, 177, 32,	 200, 6,   107, 123,
	    73,	 179, 143, 117, 169, 133, 232, 155, 12,	 34,  46,  233, 151,
	    141, 159, 206, 29,	21,  122, 160, 118, 217, 21,  119, 167, 7,
	    163, 236, 10,  53,	146, 15,  34,  152, 10,	 224, 250, 141, 157,
	    106, 152, 45,  182, 232, 77,  116, 74,  210, 75,  159, 71,	59,
	    47,	 255, 81,  142, 85,  71,  78,  189, 215, 198, 230, 12,	240,
	    120, 253, 79,  80,	68,  64,  136, 231, 254, 23,  10,  162, 166,
	    213, 24,  137, 212, 14,  71,  7,   187, 122, 198, 227, 188, 162,
	    249, 8,   45,  159, 26,  206, 221, 132, 52,	 36,  76,  20,	50,
	    167, 81,  120, 92,	120, 111, 48,  166, 119, 227, 92,  80,	152,
	    91,	 178, 76,  118, 246, 185, 133, 175, 97,	 38,  172, 144, 26,
	    43,	 233, 177, 32,	129, 198, 123, 139, 195, 99,  52,  119, 231,
	    174, 96,  18,  213, 117, 217, 178, 200, 89,	 85,  232, 177, 172,
	    135, 37,  249, 113, 243, 11,  163, 62,  115, 202, 249, 83,	178,
	    89,	 86,  203, 211, 226, 120, 69,  42,  125, 74,  198, 103, 196,
	    125, 161, 208, 60,	100, 5,	  180, 85,  138, 233, 1,   249, 37,
	    230, 248, 81,  26,	140, 87,  174, 139, 164, 183, 27,  73,	12,
	    84,	 143, 117, 130, 241, 94,  72,  135, 69,	 226, 94,  194, 45,
	    78,	 156, 206, 37,	74,  171, 49,  163, 173, 172, 138, 232, 146,
	    139, 159, 56,  99,	213, 123, 88,  250, 225, 173, 16,  248, 21,
	    233, 22,  208, 232, 107, 172, 196, 163, 132, 251, 215, 94,	49,
	    153, 140, 1,   229, 170, 157, 49,  146, 123, 249, 41,  61,	62,
	    154, 24,  40,  140, 80,  184, 42,  196, 57,	 14,  56,  47,	48,
	    132, 222, 240, 10,	221, 16,  236, 26,  60,	 55,  185, 24,	235,
	    183, 128, 118, 136, 254, 48,  97,  128, 55,	 107, 36,  27,	10,
	    145, 117, 251, 87,	107, 83,  105, 210, 223, 206, 129, 77,	199,
	    41,	 11,  138, 208, 99,  215, 26,  106, 96,	 134, 108, 130, 234,
	    96,	 27,  188, 2,	155, 212, 11,  20,  121, 59,  247, 70,	182,
	    95,	 86,  222, 12,	60,  236, 130, 215, 4,	 37,  212, 203, 108,
	    145, 162, 116, 51,	51,  253, 39,  30,  78,	 60,  174, 191, 114,
	    131, 24,  108, 218, 116, 63,  75,  105, 46,	 41,  26,  78,	30,
	    114, 202, 23,  200, 178, 140, 233, 255, 223, 221, 90,  107, 203,
	    197, 41,  190, 166, 22,  155, 197, 192, 138, 44,  76,  159, 31,
	    176, 20,  99,  15,	139, 203, 85,  102, 124, 120, 160, 168, 44,
	    150, 97,  31,  120, 185, 211, 9,   162, 238, 183, 46,  142, 27,
	    183, 72,  215, 153, 180, 89,  152, 131, 213, 76,  172, 205, 158,
	    58,	 79,  67,  190, 109, 68,  105, 21,  38,	 85,  37,  146, 120,
	    217, 115, 245, 64,	96,  238, 139, 114, 66,	 153, 172, 221, 56,
	    114, 246, 190, 150, 242, 4,	  47,  64,  107, 187, 156, 146, 129,
	    233, 141, 37,  163, 180, 158, 45,  142, 123, 214, 233, 55,	161,
	    219, 27,  184, 237, 35,  95,  22,  170, 207, 132, 205, 155, 216,
	    211, 23,  196, 213, 173, 66,  172, 189, 44,	 123, 168, 150, 208,
	    64,	 119, 124, 72,	103, 237, 117, 236, 3,	 173, 103, 54,	114,
	    237, 123, 123, 239, 52,  221, 187, 177, 192, 121, 162, 163, 1,
	    172, 218, 140, 36,	245, 217, 119, 3,   81,	 57,  65,  32,	248,
	    15,	 152, 156, 78,	75,  189, 149, 29,  111, 206, 236, 110, 206,
	    76,	 52,  217, 28,	220, 32,  115, 255, 177, 184, 228, 170, 60,
	    152, 48,  133, 230, 230, 20,  232, 176, 155, 91,  158, 202, 155,
	    192, 77,  85,  153, 99,  248, 109, 213, 221, 205, 41,  69,	54,
	    93,	 149, 137, 221, 194, 198, 48,  80,  78,	 27,  80,  202, 37,
	    206, 205, 188, 154, 129, 47,  44,  176, 236, 254, 156, 125, 174,
	    231, 164, 56,  253, 174, 129, 6,   74,  100, 233, 91,  251, 4,
	    235, 199, 6,   142, 31,  219, 250, 81,  144, 159, 46,  191, 52,
	    241, 134, 82,  91,	216, 126, 69,  17,  194, 220, 73,  174, 177,
	    51,	 195, 118, 94,	187, 54,  34,  148, 115, 251, 252, 124, 30,
	    234, 97,  98,  66,	118, 237, 82,  94,  182, 143, 65,  36,	18,
	    95,	 6,   153, 8,	83,  75,  105, 136, 114, 132, 247, 155, 64,
	    243, 45,  236, 234, 92,  247, 111, 243, 99,	 81,  145, 99,	166,
	    234, 57,  236, 139, 16,  51,  0,   222, 119, 85,  95,  133, 189,
	    130, 242, 55,  124, 72,  199, 13,  242, 158, 42,  66,  245, 149,
	    247, 61,  154, 125, 123, 80,  166, 49,  82,	 69,  233, 180, 152,
	    163, 203, 127, 10,	216, 248, 64,  42,  222, 233, 16,  16,	52,
	    110, 82,  7,   25,	242, 98,  56,  2,   8,	 148, 60,  150, 211,
	    2,	 103, 119, 201, 15,  216, 79,  2,   95,	 44,  181, 211, 174,
	    211, 172, 208, 174, 180, 64,  155, 220, 222, 84,  62,  190, 170,
	    152, 14,  218, 45,	93,  145, 210, 6,   58,	 201, 199, 178, 25,
	    215, 114, 2,   170, 230, 73,  87,  143, 72,	 124, 250, 224, 70,
	    73,	 23,  201, 129, 214, 203, 196, 255, 6,	 166, 6,   115, 131,
	    131, 207, 177, 217, 56,  107, 164, 145, 9,	 79,  87,  245, 27,
	    183, 131, 225, 50,	30,  90,  28,  207, 201, 119, 207, 187, 220,
	    142, 55,  61,  55,	111, 57,  162, 51,  173, 132, 39,  132, 232,
	    180, 216, 4,   107, 203, 34,  108, 234, 149, 31,  123, 221, 87,
	    250, 157, 10,  150, 131, 240, 124, 143, 204, 92,  163, 204, 237,
	    27,	 87,  123, 153, 75,  210, 220, 137, 42,	 254, 25,  140, 114,
	    163, 160, 83,  212, 20,  101, 243, 242, 200, 50,  9,   97,	18,
	    98,	 179, 214, 85,	164, 28,  48,  196, 101, 32,  101, 216, 222,
	    252, 141, 253, 112, 70,  167, 231, 119, 96,	 213, 13,  180, 47,
	    200, 57,  153, 177, 50,  209, 69,  162, 26,	 140, 217, 122, 175,
	    202, 25,  216, 195, 186, 147, 0,   134, 231, 142, 206, 237, 232,
	    119, 109, 214, 191, 51,  15,  184, 2,   61,	 19,  242, 228, 181,
	    75,	 85,  216, 71,	69,  143, 44,  74,  86,	 77,  37,  224, 207,
	    43,	 67,  229, 215, 21,  204, 96,  171, 37,	 150, 54,  196, 52,
	    99,	 55,  200, 29,	63,  35,  78,  153, 127, 11,  28,  104, 235,
	    232, 47,  53,  145, 192, 218, 195, 197, 54,	 138, 50,  195, 172,
	    203, 55,  74,  52,	80,  18,  134, 18,  101, 127, 244, 39,	97,
	    69,	 188, 157, 4,	179, 219, 239, 80,  28,	 103, 19,  216, 124,
	    245, 220, 147, 186, 74,  66,  159, 227, 129, 134, 158, 20,	168,
	    173, 52,  254, 113, 21,  9,	  54,  245, 54,	 9,   209, 245, 138,
	    214, 73,  111, 171, 166, 126, 252, 243, 159, 61,  70,  242, 105,
	    83,	 146, 124, 228, 54,  74,  125, 17,  165, 128, 187, 126, 147,
	    209, 145, 59,  243, 161, 119, 112, 162, 64,	 212, 152, 173, 192,
	    216, 207, 95,  154, 244, 173, 179, 98,  35,	 5,   92,  10,	237,
	    222, 175, 132, 178, 236, 48,  205, 31,  232, 79,  254, 57,	5,
	    240, 11,  122, 97,	238, 21,  204, 225, 231, 97,  225, 33,	168,
	    225, 15,  127, 159, 221, 91,  181, 228, 4,	 198, 4,   157, 74,
	    19,	 222, 139, 110, 110, 249, 31,  237, 80,	 133, 0,   70};
	u8 expected_sk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  151, 92,  158, 208, 93,  24,	254,
	    98,	 1,   112, 135, 110, 0,	  165, 198, 67,	 97,  47,  44,	253,
	    189, 186, 200, 214, 199, 125, 87,  65,  19,	 157, 189, 100, 187,
	    228, 226, 37,  43,	22,  66,  54,  247, 244, 206, 34,  21,	95,
	    39,	 129, 101, 230, 87,  158, 3,   75,  150, 149, 188, 92,	8,
	    177, 191, 117, 20,	28,  118, 29,  224, 75,	 50,  144, 200, 9,
	    128, 139, 187, 124, 227, 247, 78,  25,  170, 161, 174, 23,	255,
	    247, 191, 255, 75,	111, 152, 154, 182, 180, 7,   94,  12,	70,
	    130, 219, 192, 81,	0,   168, 69,  145, 38,	 64,  11,  32,	129,
	    193, 196, 40,  2,	17,  65,  145, 66,  64,	 26,  198, 129, 67,
	    66,	 68,  24,  18,	128, 96,  132, 129, 1,	 9,   34,  76,	148,
	    97,	 9,   49,  96,	16,  67,  74,  138, 4,	 36,  3,   69,	114,
	    9,	 56,  69,  8,	0,   130, 128, 8,   46,	 9,   4,   4,	202,
	    68,	 2,   218, 150, 140, 220, 34,  2,   155, 200, 76,  33,	9,
	    76,	 83,  24,  10,	27,  128, 72,  156, 50,	 113, 18,  22,	12,
	    92,	 164, 65,  74,	54,  8,	  153, 150, 44,	 153, 38,  145, 11,
	    137, 113, 16,  67,	13,  33,  161, 97,  26,	 49,  106, 10,	19,
	    129, 18,  23,  134, 152, 54,  69,  2,   70,	 78,  33,  54,	34,
	    98,	 72,  73,  152, 168, 73,  200, 52,  8,	 75,  50,  82,	11,
	    178, 112, 8,   152, 132, 100, 40,  34,  2,	 9,   140, 225, 194,
	    44,	 144, 56,  138, 20,  180, 13,  140, 50,	 134, 34,  18,	32,
	    161, 70,  18,  98,	198, 133, 203, 144, 17,	 194, 130, 97,	27,
	    19,	 133, 65,  64,	32,  91,  66,  137, 33,	 179, 136, 19,	1,
	    80,	 17,  162, 144, 10,  3,	  144, 131, 52,	 144, 28,  128, 144,
	    211, 72,  101, 25,	180, 140, 210, 8,   73,	 3,   50,  129, 72,
	    22,	 45,  154, 68,	130, 33,  52,  37,  136, 4,   137, 25,	51,
	    141, 25,  133, 144, 98,  66,  45,  19,  24,	 1,   204, 56,	49,
	    73,	 136, 101, 228, 38,  14,  10,  73,  100, 10,  20,  32,	24,
	    19,	 42,  34,  193, 140, 152, 64,  144, 195, 72,  140, 26,	20,
	    68,	 97,  38,  132, 211, 18,  10,  84,  146, 33,  19,  18,	32,
	    72,	 0,   109, 19,	0,   144, 20,  137, 136, 97,  34,  106, 34,
	    162, 32,  76,  150, 128, 99,  6,   134, 203, 32,  50,  73,	144,
	    0,	 74,  2,   134, 26,  50,  106, 99,  50,	 68,  216, 182, 37,
	    219, 56,  80,  210, 178, 96,  204, 16,  42,	 211, 48,  45,	88,
	    144, 97,  89,  22,	140, 8,	  67,  98,  3,	 33,  109, 12,	8,
	    97,	 66,  54,  36,	97,  150, 72,  228, 134, 69,  8,   147, 49,
	    73,	 130, 4,   18,	164, 12,  152, 130, 65,	 164, 50,  105, 17,
	    41,	 49,  228, 0,	146, 1,	  17,  70,  9,	 34,  12,  220, 0,
	    5,	 28,  193, 113, 96,  52,  5,   18,  2,	 108, 1,   70,	141,
	    72,	 198, 145, 80,	68,  141, 227, 64,  113, 164, 64,  2,	68,
	    132, 9,   19,  19,	72,  67,  184, 68,  98,	 130, 104, 84,	16,
	    5,	 155, 24,  77,	96,  160, 33,  147, 70,	 9,   210, 38,	13,
	    18,	 180, 48,  12,	66,  2,	  28,  137, 45,	 225, 160, 136, 131,
	    162, 64,  25,  131, 32,  73,  0,   33,  75,	 18,  68,  1,	33,
	    40,	 99,  178, 32,	153, 18,  64,  131, 198, 97,  2,   50,	130,
	    16,	 65,  97,  132, 22,  133, 210, 194, 105, 203, 192, 44,	19,
	    17,	 64,  219, 128, 69,  80,  152, 96,  91,	 152, 41,  12,	55,
	    36,	 144, 34,  82,	225, 166, 73,  36,  20,	 101, 208, 180, 137,
	    16,	 20,  66,  32,	6,   134, 131, 196, 129, 68,  22,  129, 1,
	    181, 137, 220, 40,	129, 35,  182, 133, 90,	 148, 101, 20,	182,
	    12,	 137, 150, 96,	129, 50,  18,  32,  182, 9,   12,  36,	137,
	    144, 4,   46,  12,	196, 32,  98,  164, 9,	 36,  8,   96,	18,
	    40,	 12,  25,  51,	66,  194, 38,  136, 211, 50,  109, 136, 4,
	    134, 84,  16,  74,	18,  8,	  141, 73,  32,	 110, 34,  7,	128,
	    2,	 50,  46,  225, 132, 5,	  3,   7,   98,	 76,  146, 12,	152,
	    184, 37,  36,  201, 136, 132, 70,  132, 17,	 131, 112, 18,	17,
	    112, 65,  68,  14,	24,  176, 12,  24,  49,	 101, 82,  198, 68,
	    153, 128, 41,  25,	34,  13,  217, 0,   44,	 12,  137, 81,	36,
	    41,	 130, 28,  181, 76,  209, 50,  36,  73,	 52,  74,  147, 136,
	    9,	 1,   132, 141, 89,  6,	  142, 8,   137, 96,  12,  51,	40,
	    156, 200, 8,   138, 194, 137, 33,  21,  68,	 20,  145, 129, 65,
	    34,	 9,   201, 68,	97,  32,  38,  97,  89,	 66,  70,  32,	64,
	    13,	 3,   135, 5,	28,  7,	  50,  76,  20,	 37,  12,  7,	10,
	    217, 34,  16,  35,	48,  45,  212, 64,  129, 217, 66,  18,	147,
	    152, 17,  155, 72,	82,  164, 136, 9,   0,	 4,   1,   203, 0,
	    16,	 154, 70,  9,	132, 34,  8,   1,   3,	 1,   20,  70,	110,
	    1,	 151, 112, 1,	179, 108, 1,   133, 41,	 75,  70,  112, 42,
	    7,	 30,  245, 71,	158, 77,  157, 155, 140, 109, 79,  85,	224,
	    224, 218, 96,  184, 52,  123, 122, 57,  127, 78,  193, 94,	95,
	    54,	 172, 35,  88,	209, 99,  207, 253, 149, 159, 152, 240, 50,
	    91,	 45,  212, 197, 116, 221, 152, 108, 164, 88,  146, 174, 218,
	    25,	 205, 122, 224, 15,  26,  198, 115, 11,	 204, 222, 123, 108,
	    142, 114, 43,  114, 103, 234, 50,  20,  168, 191, 101, 157, 206,
	    4,	 28,  79,  253, 61,  254, 216, 241, 173, 166, 185, 105, 132,
	    104, 152, 193, 161, 111, 8,	  49,  13,  208, 185, 166, 154, 249,
	    20,	 104, 186, 105, 182, 34,  116, 237, 113, 141, 204, 133, 233,
	    89,	 201, 176, 12,	72,  251, 221, 69,  168, 58,  247, 76,	106,
	    216, 52,  57,  213, 216, 208, 135, 162, 154, 240, 19,  73,	244,
	    69,	 108, 239, 87,	198, 28,  97,  50,  130, 213, 186, 226, 174,
	    68,	 103, 251, 210, 116, 81,  92,  88,  37,	 25,  181, 23,	249,
	    228, 56,  175, 95,	244, 229, 190, 124, 112, 218, 132, 97,	36,
	    138, 78,  124, 244, 156, 46,  35,  202, 190, 162, 246, 145, 224,
	    149, 199, 235, 200, 194, 24,  57,  127, 179, 252, 112, 207, 229,
	    254, 50,  96,  217, 147, 192, 197, 181, 90,	 60,  189, 169, 211,
	    249, 120, 222, 165, 146, 104, 189, 240, 69,	 94,  189, 213, 29,
	    254, 225, 11,  102, 127, 229, 150, 136, 53,	 30,  127, 123, 251,
	    197, 80,  215, 23,	252, 100, 231, 230, 223, 245, 73,  34,	159,
	    184, 217, 111, 64,	250, 164, 135, 133, 246, 111, 69,  11,	136,
	    194, 90,  174, 166, 155, 123, 134, 180, 48,	 242, 230, 70,	71,
	    252, 210, 131, 2,	170, 28,  62,  87,  52,	 181, 96,  172, 83,
	    132, 144, 246, 142, 26,  119, 220, 33,  50,	 127, 144, 233, 236,
	    225, 252, 254, 105, 142, 141, 87,  31,  137, 124, 73,  145, 36,
	    9,	 93,  169, 28,	74,  194, 168, 131, 32,	 51,  101, 88,	50,
	    46,	 142, 119, 174, 177, 107, 179, 207, 22,	 239, 126, 124, 148,
	    27,	 151, 87,  147, 88,  178, 82,  198, 76,	 37,  52,  79,	61,
	    12,	 58,  178, 69,	53,  145, 136, 151, 47,	 162, 56,  174, 217,
	    91,	 156, 135, 138, 182, 73,  179, 90,  167, 29,  247, 176, 135,
	    23,	 76,  112, 160, 84,  166, 179, 189, 92,	 233, 82,  122, 51,
	    109, 35,  73,  118, 185, 93,  34,  223, 74,	 48,  219, 151, 243,
	    220, 213, 146, 84,	240, 255, 5,   79,  27,	 40,  179, 110, 2,
	    106, 145, 3,   204, 192, 157, 189, 154, 71,	 24,  197, 236, 217,
	    6,	 129, 157, 66,	83,  175, 80,  77,  23,	 2,   101, 232, 164,
	    179, 64,  86,  234, 188, 78,  59,  30,  205, 93,  10,  185, 37,
	    30,	 248, 155, 11,	117, 12,  222, 236, 226, 27,  134, 238, 189,
	    175, 131, 161, 223, 178, 196, 15,  13,  101, 90,  207, 241, 246,
	    224, 157, 32,  84,	36,  92,  233, 44,  92,	 231, 101, 185, 223,
	    4,	 45,  230, 186, 113, 253, 162, 123, 108, 208, 183, 59,	173,
	    98,	 161, 137, 212, 232, 126, 160, 107, 93,	 255, 147, 67,	251,
	    152, 178, 59,  108, 85,  125, 80,  190, 23,	 94,  109, 87,	224,
	    79,	 153, 175, 252, 157, 216, 56,  113, 16,	 85,  18,  138, 153,
	    60,	 78,  245, 94,	172, 31,  32,  27,  65,	 39,  246, 255, 23,
	    64,	 58,  251, 137, 234, 104, 66,  24,  28,	 161, 103, 154, 25,
	    196, 101, 40,  110, 122, 170, 188, 110, 134, 163, 255, 113, 90,
	    38,	 198, 154, 142, 189, 111, 151, 215, 3,	 166, 98,  29,	183,
	    89,	 184, 53,  132, 133, 178, 229, 208, 230, 158, 123, 194, 251,
	    151, 92,  119, 249, 197, 255, 153, 228, 137, 69,  191, 146, 130,
	    177, 226, 221, 198, 153, 236, 115, 31,  49,	 49,  244, 224, 15,
	    10,	 69,  84,  100, 93,  95,  240, 78,  1,	 8,   223, 204, 232,
	    101, 181, 146, 194, 144, 83,  195, 191, 177, 140, 16,  251, 65,
	    180, 8,   12,  138, 1,   68,  160, 26,  206, 228, 254, 84,	17,
	    137, 62,  117, 94,	91,  109, 211, 131, 154, 133, 146, 204, 8,
	    14,	 99,  42,  245, 142, 69,  179, 154, 89,	 12,  7,   197, 197,
	    40,	 166, 85,  222, 166, 67,  181, 3,   68,	 103, 105, 134, 17,
	    73,	 82,  124, 188, 111, 135, 236, 51,  196, 254, 64,  131, 5,
	    54,	 9,   145, 107, 77,  130, 201, 205, 156, 242, 249, 124, 123,
	    165, 114, 178, 100, 203, 141, 176, 185, 34,	 25,  194, 203, 220,
	    72,	 97,  243, 130, 60,  30,  75,  163, 195, 151, 235, 107, 116,
	    194, 44,  37,  14,	208, 230, 86,  12,  81,	 83,  65,  130, 215,
	    180, 117, 189, 199, 222, 107, 233, 149, 124, 98,  94,  198, 96,
	    51,	 83,  198, 57,	254, 206, 179, 180, 138, 39,  65,  0,	202,
	    26,	 57,  80,  80,	184, 239, 47,  111, 95,	 173, 127, 0,	68,
	    35,	 224, 42,  183, 75,  182, 210, 60,  207, 189, 160, 185, 75,
	    122, 133, 221, 154, 29,  241, 57,  204, 250, 74,  235, 53,	159,
	    180, 79,  176, 6,	85,  226, 76,  67,  115, 146, 35,  177, 133,
	    110, 69,  238, 25,	116, 48,  59,  14,  207, 4,   209, 173, 33,
	    135, 189, 146, 253, 98,  214, 202, 211, 87,	 159, 201, 158, 4,
	    79,	 76,  238, 71,	202, 225, 135, 22,  186, 143, 203, 141, 157,
	    8,	 67,  150, 189, 237, 21,  19,  162, 204, 44,  200, 120, 174,
	    117, 85,  174, 64,	99,  152, 105, 247, 37,	 181, 40,  217, 8,
	    47,	 57,  71,  31,	119, 192, 180, 150, 91,	 246, 191, 173, 53,
	    68,	 90,  64,  71,	87,  164, 229, 195, 164, 101, 113, 249, 212,
	    133, 162, 238, 99,	156, 244, 112, 109, 107, 146, 236, 180, 25,
	    130, 104, 15,  75,	82,  153, 137, 148, 24,	 234, 85,  178, 186,
	    48,	 71,  138, 48,	221, 188, 140, 35,  86,	 7,   29,  68,	241,
	    56,	 62,  232, 162, 212, 139, 120, 80,  165, 220, 165, 101, 20,
	    113, 85,  177, 176, 153, 25,  33,  159, 221, 75,  131, 202, 118,
	    122, 32,  180, 17,	200, 130, 94,  230, 157, 145, 226, 246, 86,
	    188, 177, 96,  67,	35,  55,  48,  193, 245, 102, 178, 99,	128,
	    6,	 135, 238, 30,	98,  82,  133, 227, 156, 86,  85,  154, 144,
	    141, 224, 95,  118, 91,  143, 110, 178, 11,	 183, 130, 108, 70,
	    179, 104, 242, 36,	190, 146, 50,  56,  226, 66,  1,   48,	200,
	    109, 97,  246, 75,	151, 227, 190, 184, 31,	 151, 152, 25,	140,
	    135, 122, 41,  147, 178, 40,  239, 131, 155, 143, 114, 220, 31,
	    127, 120, 115, 30,	225, 85,  181, 215, 97,	 14,  99,  168, 202,
	    127, 79,  239, 21,	109, 227, 56,  24,  116, 79,  201, 32,	30,
	    28,	 57,  205, 129, 250, 239, 211, 62,  74,	 131, 75,  213, 62,
	    32,	 183, 192, 160, 3,   137, 131, 55,  134, 74,  80,  113, 34,
	    122, 18,  78,  202, 223, 170, 179, 214, 120, 229, 20,  126, 93,
	    95,	 117, 45,  225, 39,  247, 239, 24,  133, 166, 59,  244, 237,
	    185, 221, 206, 174, 178, 5,	  21,  132, 124, 139, 148, 210, 97,
	    40,	 78,  16,  95,	189, 77,  9,   73,  220, 239, 162, 187, 233,
	    234, 220, 123, 203, 3,   63,  81,  80,  178, 22,  22,  178, 243,
	    233, 246, 243, 195, 252, 194, 137, 61,  33,	 253, 192, 0,	0,
	    103, 244, 20,  20,	140, 88,  104, 99,  26,	 5,   22,  11,	129,
	    35,	 209, 7,   116, 150, 62,  37,  159, 234, 24,  175, 242, 123,
	    61,	 154, 49,  109, 215, 252, 111, 155, 219, 242, 16,  40,	192,
	    202, 12,  22,  0,	6,   108, 220, 164, 184, 154, 137, 128, 11,
	    25,	 101, 72,  61,	214, 115, 254, 22,  85,	 229, 4,   186, 203,
	    52,	 8,   248, 29,	151, 102, 163, 135, 2,	 53,  3,   44,	145,
	    162, 88,  41,  194, 89,  67,  31,  219, 186, 95,  26,  47,	207,
	    161, 187, 245, 196, 121, 34,  148, 198, 76,	 227, 110, 227, 9,
	    169, 98,  21,  232, 168, 140, 204, 244, 173, 124, 183, 68,	90,
	    241, 13,  106, 45,	205, 146, 210, 207, 11,	 158, 209, 214, 220,
	    48,	 39,  211, 225, 192, 167, 102, 205, 169, 33,  112, 194, 238,
	    162, 254, 211, 13,	122, 193, 174, 171, 238, 100, 214, 62,	229,
	    208, 184, 1,   88,	193, 156, 28,  40,  225, 144, 51,  36,	232,
	    235, 61,  71,  254, 128, 172, 191, 228, 225, 84,  224, 80,	164,
	    2,	 212, 4,   204, 7,   140, 136, 87,  102, 195, 128, 44,	159,
	    94,	 71,  29,  116, 80,  216, 213, 130, 241, 159, 31,  100, 68,
	    141, 154, 179, 97,	167, 157, 32,  96,  43,	 170, 162, 176, 111,
	    56,	 154, 101, 56,	34,  196, 196, 25,  70,	 36,  181, 49,	140,
	    65,	 232, 201, 121, 192, 212, 58,  153, 111, 52,  222, 85,	42,
	    191, 19,  228, 253, 181, 191, 54,  94,  241, 146, 85,  49,	58,
	    146, 208, 38,  63,	245, 128, 230, 173, 67,	 131, 54,  75,	209,
	    171, 174, 7,   46,	11,  114, 209, 180, 255, 9,   62,  222, 164,
	    54,	 133, 208, 168, 180, 69,  76,  101, 214, 116, 63,  157, 183,
	    93,	 110, 70,  165, 146, 110, 240, 250, 31,	 250, 218, 36,	187,
	    56,	 80,  248, 247, 189, 16,  36,  54,  84,	 230, 68,  247, 197,
	    226, 211, 34,  242, 177, 27,  160, 248, 7,	 194, 172, 222, 219,
	    157, 194, 64,  75,	246, 140, 244, 2,   64,	 236, 27,  6,	18,
	    220, 71,  94,  165, 14,  212, 190, 94,  47,	 141, 78,  222, 188,
	    74,	 245, 32,  38,	185, 145, 153, 18,  114, 145, 168, 75,	174,
	    59,	 225, 54,  66,	194, 31,  42,  58,  121, 91,  174, 151, 50,
	    63,	 27,  166, 73,	208, 95,  140, 53,  98,	 163, 242, 204, 174,
	    222, 46,  97,  98,	224, 163, 78,  75,  161, 128, 166, 151};
	u8 expected_sig[] = {
	    16,	 26,  82,  238, 249, 53,  76,  241, 248, 25,  189, 199, 56,
	    23,	 69,  169, 241, 177, 144, 144, 169, 112, 26,  26,  212, 36,
	    186, 122, 73,  37,	107, 69,  239, 43,  223, 160, 13,  35,	244,
	    98,	 136, 59,  128, 163, 94,  222, 29,  243, 203, 33,  48,	38,
	    231, 107, 11,  201, 163, 150, 34,  186, 83,	 62,  3,   18,	221,
	    65,	 170, 15,  179, 134, 79,  242, 154, 36,	 201, 80,  238, 85,
	    240, 167, 252, 81,	242, 162, 76,  187, 176, 63,  95,  43,	230,
	    29,	 84,  161, 15,	67,  184, 176, 17,  38,	 191, 174, 145, 3,
	    24,	 221, 182, 0,	215, 18,  228, 94,  190, 253, 21,  33,	179,
	    187, 233, 32,  65,	159, 226, 120, 36,  123, 225, 237, 247, 205,
	    61,	 95,  33,  81,	160, 13,  228, 62,  101, 6,   2,   67,	110,
	    56,	 227, 159, 100, 14,  2,	  6,   174, 127, 223, 20,  79,	244,
	    235, 111, 140, 36,	170, 31,  225, 231, 24,	 207, 134, 127, 85,
	    34,	 43,  204, 66,	31,  130, 191, 98,  201, 104, 204, 181, 178,
	    248, 5,   124, 21,	153, 228, 170, 241, 233, 238, 26,  92,	216,
	    131, 131, 63,  113, 191, 158, 178, 175, 33,	 54,  22,  244, 60,
	    86,	 153, 79,  76,	166, 101, 174, 176, 101, 226, 250, 239, 77,
	    82,	 151, 88,  109, 131, 175, 171, 59,  105, 176, 76,  124, 61,
	    34,	 2,   135, 43,	19,  9,	  34,  90,  141, 14,  147, 166, 181,
	    49,	 1,   14,  221, 136, 155, 127, 138, 45,	 213, 80,  193, 3,
	    139, 221, 73,  118, 146, 27,  2,   38,  196, 202, 137, 120, 141,
	    111, 12,  97,  219, 98,  8,	  110, 224, 237, 216, 19,  96,	88,
	    169, 187, 92,  215, 223, 84,  26,  178, 219, 89,  204, 2,	235,
	    31,	 234, 56,  244, 206, 172, 184, 107, 172, 3,   91,  242, 227,
	    13,	 73,  17,  22,	214, 15,  134, 116, 199, 59,  152, 53,	7,
	    116, 159, 122, 213, 49,  176, 181, 194, 96,	 151, 175, 109, 187,
	    1,	 79,  149, 96,	228, 87,  183, 3,   209, 90,  155, 123, 92,
	    194, 215, 74,  214, 83,  47,  11,  166, 59,	 44,  210, 17,	94,
	    24,	 106, 202, 74,	73,  53,  106, 209, 136, 63,  231, 210, 4,
	    194, 53,  253, 180, 64,  40,  100, 191, 161, 17,  129, 141, 4,
	    173, 43,  52,  244, 118, 80,  189, 211, 215, 169, 170, 183, 145,
	    165, 127, 24,  251, 110, 123, 115, 126, 149, 200, 18,  113, 176,
	    66,	 185, 213, 181, 90,  10,  234, 15,  104, 142, 71,  154, 220,
	    240, 207, 99,  192, 139, 206, 62,  100, 110, 248, 15,  205, 85,
	    215, 39,  10,  80,	126, 57,  194, 232, 134, 224, 143, 129, 18,
	    36,	 36,  171, 0,	194, 63,  40,  145, 240, 136, 81,  141, 155,
	    216, 165, 121, 103, 170, 33,  146, 162, 218, 184, 185, 132, 20,
	    213, 54,  128, 77,	141, 219, 104, 206, 83,	 106, 33,  29,	96,
	    129, 65,  80,  199, 208, 146, 22,  54,  110, 176, 172, 203, 24,
	    235, 141, 247, 128, 182, 119, 103, 57,  7,	 119, 118, 230, 240,
	    73,	 199, 9,   51,	41,  179, 19,  233, 187, 70,  29,  238, 58,
	    114, 84,  129, 26,	88,  65,  196, 122, 237, 110, 11,  221, 57,
	    53,	 113, 189, 215, 138, 54,  25,  52,  74,	 25,  28,  61,	29,
	    80,	 107, 56,  8,	60,  178, 3,   142, 118, 45,  100, 229, 50,
	    218, 232, 196, 54,	101, 254, 175, 102, 185, 208, 183, 94,	239,
	    52,	 117, 124, 236, 137, 131, 99,  3,   203, 98,  209, 155, 152,
	    92,	 51,  165, 183, 105, 60,  77,  73,  137, 200, 2,   140, 97,
	    65,	 64,  252, 194, 237, 70,  61,  210, 206, 125, 185, 220, 239,
	    197, 248, 253, 112, 195, 231, 223, 1,   57,	 92,  227, 233, 233,
	    8,	 44,  184, 223, 34,  122, 11,  182, 234, 38,  77,  106, 124,
	    228, 184, 41,  135, 218, 218, 86,  102, 55,	 190, 127, 146, 67,
	    133, 225, 66,  40,	132, 101, 143, 44,  26,	 149, 35,  231, 74,
	    165, 161, 68,  205, 218, 75,  178, 91,  115, 108, 181, 74,	64,
	    43,	 33,  143, 75,	135, 8,	  189, 221, 54,	 129, 39,  204, 90,
	    255, 85,  148, 106, 10,  224, 205, 224, 223, 89,  95,  27,	88,
	    248, 22,  148, 29,	244, 121, 32,  77,  124, 90,  170, 146, 108,
	    22,	 43,  92,  178, 195, 131, 14,  204, 37,	 148, 225, 10,	102,
	    100, 247, 130, 134, 227, 40,  202, 22,  39,	 8,   207, 180, 234,
	    249, 142, 187, 54,	34,  87,  16,  221, 4,	 217, 48,  244, 211,
	    127, 52,  2,   69,	180, 63,  102, 170, 207, 195, 37,  100, 222,
	    254, 79,  217, 205, 25,  70,  166, 205, 212, 2,   97,  41,	146,
	    160, 243, 137, 6,	4,   19,  117, 109, 206, 77,  217, 235, 161,
	    217, 91,  96,  238, 41,  157, 221, 220, 142, 158, 212, 239, 197,
	    254, 172, 15,  118, 59,  36,  89,  185, 25,	 108, 106, 246, 221,
	    208, 180, 210, 39,	48,  95,  203, 162, 117, 187, 116, 187, 74,
	    202, 80,  25,  127, 191, 36,  156, 153, 32,	 231, 140, 80,	176,
	    109, 102, 16,  223, 217, 57,  145, 59,  88,	 99,  44,  114, 119,
	    90,	 12,  221, 34,	144, 132, 222, 41,  127, 8,   142, 88,	243,
	    165, 57,  166, 233, 38,  126, 169, 113, 85,	 85,  18,  40,	79,
	    211, 51,  69,  127, 32,  114, 238, 197, 98,	 95,  148, 220, 101,
	    37,	 194, 27,  106, 151, 186, 177, 79,  237, 150, 12,  13,	93,
	    115, 29,  120, 113, 53,  19,  218, 185, 145, 97,  222, 6,	167,
	    235, 76,  101, 171, 194, 120, 47,  81,  188, 248, 150, 3,	132,
	    178, 65,  36,  228, 239, 143, 142, 137, 198, 167, 54,  135, 95,
	    154, 231, 35,  225, 196, 164, 123, 196, 113, 190, 198, 65,	5,
	    196, 121, 157, 80,	249, 164, 100, 217, 100, 11,  245, 218, 97,
	    28,	 190, 140, 19,	157, 80,  97,  204, 111, 26,  173, 143, 25,
	    134, 46,  39,  91,	215, 1,	  68,  150, 113, 135, 146, 195, 230,
	    6,	 112, 195, 113, 95,  51,  48,  232, 106, 177, 25,  103, 136,
	    228, 189, 80,  246, 183, 200, 99,  129, 225, 36,  157, 150, 104,
	    235, 253, 12,  44,	124, 230, 240, 180, 91,	 218, 150, 184, 150,
	    216, 129, 139, 34,	167, 46,  46,  217, 4,	 72,  168, 181, 184,
	    56,	 67,  137, 252, 226, 184, 95,  123, 195, 94,  52,  146, 119,
	    3,	 139, 187, 238, 29,  123, 236, 122, 123, 48,  163, 144, 207,
	    247, 80,  170, 23,	42,  174, 74,  168, 78,	 10,  183, 32,	50,
	    106, 192, 137, 155, 50,  209, 6,   52,  3,	 236, 145, 98,	204,
	    38,	 7,   94,  44,	139, 146, 129, 96,  15,	 26,  190, 187, 46,
	    182, 96,  146, 86,	82,  180, 16,  35,  17,	 104, 111, 59,	137,
	    220, 246, 124, 30,	80,  164, 252, 225, 25,	 152, 244, 45,	49,
	    55,	 11,  213, 156, 87,  154, 61,  183, 164, 128, 104, 77,	214,
	    219, 92,  168, 63,	235, 196, 212, 61,  86,	 237, 188, 53,	237,
	    158, 127, 28,  221, 209, 227, 8,   11,  201, 179, 140, 253, 38,
	    179, 78,  9,   123, 209, 112, 16,  195, 80,	 49,  237, 107, 92,
	    16,	 201, 0,   68,	19,  99,  69,  75,  76,	 236, 212, 215, 87,
	    161, 148, 254, 157, 81,  159, 96,  163, 121, 22,  113, 53,	13,
	    226, 89,  245, 192, 85,  25,  215, 91,  166, 209, 142, 154, 81,
	    146, 40,  223, 113, 236, 131, 84,  31,  0,	 63,  63,  170, 241,
	    127, 113, 165, 10,	13,  50,  116, 73,  87,	 37,  116, 41,	141,
	    62,	 75,  68,  45,	166, 0,	  115, 130, 220, 238, 31,  114, 215,
	    93,	 235, 62,  172, 17,  206, 86,  185, 12,	 8,   139, 72,	220,
	    214, 56,  249, 225, 30,  253, 137, 24,  224, 21,  79,  244, 25,
	    127, 23,  202, 191, 94,  243, 241, 225, 245, 179, 32,  127, 36,
	    163, 84,  74,  47,	76,  219, 93,  108, 129, 120, 226, 203, 21,
	    23,	 117, 134, 231, 110, 75,  10,  51,  138, 86,  166, 187, 228,
	    249, 246, 145, 87,	125, 192, 19,  3,   194, 130, 218, 36,	244,
	    91,	 251, 18,  241, 159, 202, 237, 146, 149, 77,  75,  132, 46,
	    99,	 167, 207, 239, 253, 93,  125, 8,   61,	 135, 174, 13,	184,
	    138, 223, 145, 206, 47,  22,  153, 25,  45,	 20,  28,  3,	17,
	    1,	 119, 16,  193, 243, 140, 16,  195, 15,	 213, 190, 58,	181,
	    43,	 162, 76,  5,	216, 149, 165, 139, 53,	 165, 55,  0,	209,
	    39,	 84,  75,  148, 208, 5,	  224, 61,  27,	 107, 33,  109, 70,
	    102, 127, 86,  37,	230, 29,  115, 38,  38,	 59,  98,  8,	126,
	    237, 226, 16,  169, 253, 228, 125, 50,  166, 121, 116, 196, 242,
	    7,	 231, 136, 234, 167, 165, 170, 196, 221, 22,  55,  152, 215,
	    228, 38,  175, 110, 179, 203, 45,  161, 188, 135, 136, 168, 167,
	    223, 36,  171, 197, 44,  158, 79,  181, 37,	 249, 184, 19,	43,
	    31,	 146, 7,   247, 224, 156, 160, 176, 86,	 173, 241, 193, 197,
	    216, 237, 22,  40,	207, 106, 101, 3,   129, 98,  161, 201, 96,
	    55,	 29,  125, 221, 241, 104, 138, 53,  21,	 97,  72,  252, 64,
	    226, 114, 4,   174, 57,  111, 39,  60,  126, 24,  21,  141, 208,
	    210, 232, 26,  84,	41,  233, 83,  187, 9,	 179, 193, 14,	125,
	    174, 75,  173, 204, 67,  27,  192, 115, 19,	 246, 60,  5,	106,
	    53,	 169, 224, 224, 6,   180, 120, 181, 70,	 161, 88,  4,	96,
	    123, 167, 123, 70,	93,  17,  141, 142, 118, 138, 212, 175, 8,
	    85,	 220, 213, 20,	203, 200, 156, 173, 153, 105, 148, 51,	134,
	    80,	 151, 92,  88,	147, 89,  134, 228, 237, 234, 93,  22,	157,
	    246, 13,  61,  176, 134, 182, 93,  124, 243, 202, 11,  19,	3,
	    17,	 112, 223, 206, 3,   197, 177, 4,   99,	 114, 33,  153, 108,
	    195, 176, 209, 91,	170, 63,  246, 86,  150, 111, 4,   16,	79,
	    137, 42,  107, 103, 233, 37,  75,  56,  5,	 92,  54,  179, 201,
	    241, 79,  115, 198, 173, 211, 122, 66,  76,	 228, 110, 185, 69,
	    101, 184, 230, 172, 5,   191, 114, 155, 172, 50,  14,  57,	253,
	    115, 242, 47,  188, 112, 239, 72,  36,  180, 80,  203, 73,	78,
	    163, 128, 149, 247, 236, 78,  5,   194, 140, 131, 80,  56,	200,
	    151, 134, 220, 66,	211, 182, 134, 185, 21,	 104, 91,  18,	215,
	    201, 28,  159, 46,	170, 125, 160, 99,  83,	 111, 41,  174, 167,
	    200, 156, 238, 233, 58,  229, 13,  235, 213, 212, 225, 224, 70,
	    135, 230, 133, 120, 129, 137, 67,  106, 206, 84,  145, 24,	146,
	    119, 91,  62,  64,	85,  174, 124, 5,   117, 29,  6,   122, 19,
	    23,	 80,  245, 102, 10,  37,  101, 166, 94,	 16,  124, 30,	106,
	    70,	 221, 174, 2,	55,  218, 71,  49,  54,	 191, 227, 20,	39,
	    177, 184, 55,  252, 244, 57,  174, 222, 9,	 225, 4,   166, 39,
	    65,	 14,  119, 221, 240, 68,  6,   243, 197, 142, 221, 59,	181,
	    131, 248, 17,  64,	48,  136, 181, 238, 219, 214, 246, 143, 105,
	    233, 70,  146, 23,	172, 240, 50,  200, 255, 183, 106, 228, 46,
	    6,	 110, 99,  250, 210, 79,  65,  149, 84,	 135, 35,  77,	90,
	    54,	 182, 84,  72,	213, 68,  46,  184, 128, 18,  1,   28,	23,
	    111, 128, 40,  36,	192, 126, 81,  170, 180, 190, 208, 150, 61,
	    133, 117, 255, 64,	168, 82,  145, 127, 63,	 109, 144, 11,	122,
	    168, 242, 113, 97,	242, 145, 132, 26,  107, 212, 166, 226, 8,
	    239, 75,  12,  159, 255, 68,  178, 120, 88,	 194, 111, 53,	102,
	    154, 149, 166, 83,	199, 156, 250, 188, 206, 66,  108, 137, 73,
	    227, 153, 211, 215, 66,  176, 88,  32,  134, 143, 90,  214, 246,
	    130, 25,  170, 144, 53,  170, 46,  142, 87,	 153, 220, 54,	39,
	    17,	 10,  33,  174, 222, 143, 140, 204, 115, 109, 34,  145, 234,
	    27,	 168, 116, 60,	23,  32,  105, 24,  73,	 149, 225, 15,	141,
	    220, 168, 216, 22,	206, 80,  52,  132, 163, 83,  85,  223, 244,
	    29,	 197, 132, 34,	58,  148, 191, 192, 80,	 15,  113, 63,	34,
	    127, 65,  241, 210, 254, 52,  218, 17,  225, 177, 149, 157, 203,
	    220, 235, 168, 166, 215, 153, 159, 6,   176, 251, 127, 223, 186,
	    55,	 207, 136, 105, 144, 117, 179, 136, 108, 167, 114, 152, 6,
	    160, 109, 120, 179, 127, 251, 64,  133, 239, 3,   248, 51,	180,
	    181, 9,   222, 53,	153, 233, 184, 232, 115, 81,  113, 135, 195,
	    34,	 79,  226, 247, 96,  128, 59,  164, 124, 197, 42,  226, 235,
	    98,	 111, 116, 180, 172, 73,  44,  169, 42,	 102, 175, 46,	20,
	    79,	 32,  0,   125, 54,  165, 116, 230, 186, 123, 195, 209, 24,
	    232, 27,  129, 7,	123, 36,  211, 24,  14,	 111, 101, 93,	172,
	    95,	 179, 174, 197, 202, 29,  170, 240, 91,	 96,  239, 1,	206,
	    4,	 55,  210, 87,	112, 15,  252, 133, 229, 33,  60,  42,	25,
	    59,	 197, 219, 173, 75,  104, 182, 78,  8,	 37,  154, 154, 31,
	    198, 157, 41,  189, 2,   255, 9,   45,  218, 103, 186, 111, 72,
	    177, 223, 200, 183, 157, 189, 224, 66,  149, 90,  51,  82,	98,
	    80,	 63,  97,  157, 51,  18,  194, 128, 9,	 220, 205, 165, 157,
	    191, 184, 187, 195, 47,  191, 63,  119, 22,	 237, 132, 110, 253,
	    244, 5,   75,  116, 36,  244, 138, 86,  226, 52,  219, 130, 35,
	    18,	 49,  111, 251, 208, 92,  249, 153, 61,	 238, 184, 28,	115,
	    204, 9,   205, 157, 40,  142, 115, 168, 204, 235, 217, 108, 48,
	    214, 137, 187, 3,	92,  45,  181, 98,  203, 26,  182, 227, 43,
	    209, 174, 128, 209, 100, 254, 207, 255, 217, 89,  236, 153, 102,
	    61,	 14,  227, 111, 30,  153, 228, 167, 59,	 29,  36,  46,	48,
	    63,	 64,  82,  83,	103, 107, 140, 150, 157, 161, 167, 194, 239,
	    242, 8,   9,   27,	43,  70,  121, 124, 128, 146, 157, 183, 184,
	    190, 192, 194, 202, 225, 237, 244, 43,  61,	 63,  97,  125, 169,
	    186, 213, 237, 17,	30,  31,  57,  68,  70,	 96,  105, 134, 147,
	    172, 174, 177, 201, 207, 222, 230, 233, 0,	 0,   0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   18,	37,
	    46,	 64,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
	    0};
	ASSERT_EQ(verify(msg, &pk, &sig), 0, "verify");
	ASSERT(!memcmp(expected_pk, pk.data, sizeof(pk)), "expected pk");
	ASSERT(!memcmp(expected_sk, sk.data, sizeof(sk)), "expected sk");
	ASSERT(!memcmp(expected_sig, sig.data, sizeof(expected_sig)),
	       "expected sig");

	(void)expected_pk;
	(void)expected_sk;
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

