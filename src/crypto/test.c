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
	    200, 145, 3,   61,	87,  60,  139, 66,  235, 1,   12,  35,	186,
	    113, 26,  224, 222, 178, 230, 181, 13,  249, 242, 76,  80,	236,
	    169, 171, 150, 167, 152, 52,  51,  241, 124, 125, 56,  121, 247,
	    14,	 185, 221, 14,	149, 237, 16,  3,   183, 161, 8,   1,	96,
	    159, 203, 49,  239, 187, 138, 160, 102, 208, 254, 40,  221, 118,
	    176, 143, 180, 216, 40,  5,	  102, 130, 241, 244, 245, 148, 102,
	    113, 58,  127, 209, 51,  165, 26,  205, 206, 56,  43,  142, 27,
	    214, 85,  232, 204, 153, 73,  12,  122, 165, 18,  60,  50,	245,
	    112, 207, 254, 110, 92,  52,  170, 183, 200, 233, 166, 152, 193,
	    223, 48,  65,  182, 42,  149, 169, 107, 229, 94,  57,  131, 14,
	    143, 197, 203, 180, 97,  206, 90,  0,   43,	 4,   90,  174, 125,
	    144, 73,  230, 81,	108, 243, 85,  17,  226, 138, 109, 202, 171,
	    218, 159, 91,  229, 228, 238, 38,  119, 146, 142, 164, 68,	9,
	    122, 123, 8,   93,	92,  207, 170, 37,  228, 188, 46,  62,	66,
	    49,	 113, 88,  207, 113, 156, 189, 84,  119, 223, 144, 238, 254,
	    5,	 252, 37,  111, 38,  141, 137, 160, 116, 229, 74,  198, 31,
	    223, 49,  143, 166, 13,  209, 99,  57,  228, 136, 119, 34,	200,
	    175, 75,  188, 251, 180, 78,  39,  137, 3,	 29,  105, 226, 98,
	    154, 221, 151, 86,	10,  28,  191, 179, 139, 218, 29,  145, 218,
	    150, 77,  198, 190, 222, 57,  66,  235, 213, 208, 240, 85,	122,
	    149, 61,  234, 9,	114, 111, 82,  127, 222, 48,  141, 158, 24,
	    197, 240, 115, 65,	180, 200, 179, 224, 243, 161, 0,   182, 108,
	    151, 14,  160, 206, 233, 174, 214, 94,  192, 242, 100, 184, 179,
	    27,	 131, 19,  44,	247, 191, 28,  127, 199, 60,  145, 121, 82,
	    184, 102, 100, 72,	74,  47,  92,  18,  248, 154, 230, 74,	65,
	    49,	 13,  145, 53,	16,  239, 216, 136, 18,	 212, 11,  120, 17,
	    156, 91,  36,  160, 41,  213, 115, 93,  106, 195, 114, 14,	193,
	    168, 111, 106, 253, 7,   245, 16,  170, 33,	 2,   177, 55,	144,
	    92,	 246, 112, 227, 139, 207, 24,  112, 46,	 208, 64,  95,	176,
	    63,	 74,  136, 241, 20,  174, 215, 58,  119, 114, 162, 95,	132,
	    18,	 7,   241, 53,	53,  58,  254, 156, 209, 160, 210, 205, 29,
	    210, 50,  28,  15,	106, 114, 162, 213, 52,	 198, 155, 165, 81,
	    249, 135, 93,  209, 12,  214, 83,  90,  160, 83,  55,  18,	28,
	    69,	 175, 144, 57,	210, 224, 32,  148, 191, 142, 210, 234, 221,
	    230, 4,   21,  168, 109, 16,  182, 226, 12,	 3,   50,  157, 68,
	    253, 4,   189, 214, 42,  121, 175, 54,  60,	 49,  79,  253, 159,
	    120, 59,  194, 132, 213, 132, 25,  139, 130, 23,  92,  108, 48,
	    252, 174, 231, 251, 93,  186, 70,  33,  106, 83,  225, 64,	12,
	    67,	 21,  31,  212, 242, 15,  244, 8,   177, 226, 118, 76,	87,
	    201, 99,  245, 231, 143, 222, 195, 149, 5,	 210, 88,  227, 40,
	    180, 185, 86,  73,	127, 6,	  132, 83,  117, 35,  49,  235, 152,
	    68,	 146, 70,  232, 114, 103, 163, 237, 22,	 213, 233, 97,	186,
	    255, 69,  91,  207, 66,  129, 255, 254, 4,	 123, 216, 247, 172,
	    115, 90,  176, 103, 88,  45,  176, 247, 138, 61,  46,  84,	4,
	    248, 245, 192, 49,	35,  75,  34,  60,  79,	 250, 71,  196, 63,
	    40,	 227, 99,  186, 85,  18,  86,  238, 40,	 230, 138, 137, 79,
	    73,	 113, 26,  191, 197, 116, 0,   3,   141, 92,  86,  50,	11,
	    50,	 142, 35,  40,	74,  103, 156, 155, 176, 94,  109, 31,	235,
	    77,	 162, 2,   206, 83,  99,  76,  169, 216, 126, 104, 74,	127,
	    85,	 43,  212, 84,	247, 97,  93,  187, 122, 243, 163, 171, 212,
	    219, 113, 10,  83,	237, 187, 14,  12,  136, 49,  243, 148, 71,
	    160, 86,  88,  119, 164, 210, 137, 148, 40,	 192, 7,   61,	19,
	    210, 86,  50,  159, 41,  182, 152, 93,  235, 122, 124, 110, 18,
	    33,	 138, 72,  28,	157, 250, 99,  105, 216, 5,   151, 249, 118,
	    236, 233, 1,   21,	20,  139, 2,   249, 210, 52,  188, 167, 71,
	    194, 231, 135, 159, 105, 96,  10,  183, 232, 115, 36,  129, 228,
	    185, 94,  198, 64,	246, 157, 65,  231, 218, 7,   40,  97,	31,
	    8,	 23,  218, 156, 57,  171, 6,   190, 113, 107, 235, 200, 135,
	    112, 24,  177, 193, 169, 172, 152, 118, 196, 51,  66,  29,	34,
	    105, 245, 197, 29,	18,  238, 1,   84,  216, 50,  234, 212, 9,
	    208, 190, 184, 146, 28,  89,  76,  131, 4,	 26,  80,  112, 174,
	    237, 47,  247, 102, 128, 229, 139, 130, 30,	 47,  233, 10,	92,
	    69,	 26,  252, 143, 70,  125, 42,  41,  147, 69,  23,  183, 89,
	    159, 122, 53,  172, 209, 204, 150, 104, 50,	 187, 232, 141, 125,
	    198, 91,  228, 86,	206, 68,  180, 51,  54,	 252, 133, 23,	61,
	    198, 72,  41,  101, 35,  67,  166, 16,  146, 42,  134, 139, 219,
	    118, 71,  234, 170, 97,  192, 237, 88,  69,	 184, 103, 50,	162,
	    166, 21,  88,  2,	191, 40,  17,  7,   185, 105, 46,  58,	210,
	    44,	 150, 116, 37,	65,  48,  158, 177, 247, 195, 20,  232, 241,
	    177, 10,  20,  36,	106, 28,  243, 76,  103, 211, 50,  236, 236,
	    66,	 162, 165, 184, 240, 182, 77,  237, 242, 102, 230, 106, 115,
	    179, 244, 58,  29,	201, 201, 117, 98,  138, 148, 134, 233, 11,
	    47,	 35,  158, 210, 162, 85,  63,  138, 233, 80,  141, 122, 81,
	    38,	 211, 175, 103, 45,  132, 240, 86,  208, 15,  248, 89,	128,
	    29,	 29,  108, 210, 223, 239, 26,  87,  143, 46,  68,  91,	185,
	    165, 7,   171, 234, 107, 51,  55,  25,  95,	 73,  116, 61,	166,
	    32,	 151, 123, 246, 78,  99,  140, 61,  244, 243, 98,  146, 13,
	    76,	 211, 214, 90,	143, 230, 15,  66,  239, 228, 74,  15,	48,
	    42,	 144, 59,  22,	60,  200, 44,  101, 46,	 195, 105, 98,	186,
	    9,	 220, 40,  205, 15,  198, 77,  194, 70,	 105, 212, 165, 97,
	    224, 40,  214, 77,	247, 193, 191, 231, 15,	 178, 63,  111, 177,
	    210, 192, 138, 158, 145, 209, 80,  174, 102, 231, 79,  133, 58,
	    162, 101, 24,  233, 36,  104, 167, 217, 116, 139, 232, 177, 124,
	    180, 105, 135, 132, 168, 11,  1,   217, 135, 209, 116, 76,	55,
	    119, 253, 122, 70,	187, 42,  169, 189, 48,	 213, 128, 249, 193,
	    66,	 10,  94,  12,	206, 92,  195, 38,  209, 45,  18,  98,	41,
	    228, 208, 198, 137, 112, 198, 58,  54,  178, 84,  167, 173, 24,
	    77,	 149, 14,  46,	191, 173, 91,  26,  101, 207, 58,  174, 78,
	    14,	 38,  192, 48,	129, 44,  211, 180, 99,	 114, 24,  231, 161,
	    73,	 65,  154, 177, 66,  118, 77,  97,  235, 213, 219, 139, 144,
	    245, 188, 255, 88,	175, 101, 158, 201, 42,	 34,  40,  180, 21,
	    157, 98,  208, 202, 248, 243, 212, 138, 147, 34,  112, 8,	157,
	    50,	 243, 186, 117, 39,  186, 121, 151, 225, 58,  210, 46,	95,
	    241, 14,  82,  120, 134, 146, 172, 49,  57,	 140, 176, 184, 48,
	    197, 115, 109, 207, 14,  180, 66,  134, 8,	 20,  189, 234, 201,
	    58,	 180, 60,  234, 62,  109, 225, 211, 154, 200, 101, 26,	102,
	    71,	 235, 63,  135, 212, 12,  80,  131, 194, 196, 175, 63,	117,
	    233, 223, 216, 47,	185, 195, 35,  28,  80,	 203, 74,  210, 13,
	    150, 36,  136, 98,	192, 217, 163, 33,  38,	 30,  128, 198};
	u8 expected_sk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  151, 92,  158, 208, 93,  24,	254,
	    98,	 1,   112, 135, 110, 0,	  165, 198, 67,	 97,  47,  44,	253,
	    189, 186, 200, 214, 199, 125, 87,  65,  19,	 157, 189, 100, 174,
	    59,	 55,  91,  245, 149, 147, 50,  146, 80,	 74,  213, 110, 41,
	    108, 208, 200, 147, 75,  237, 6,   109, 212, 51,  34,  235, 33,
	    109, 25,  162, 148, 137, 133, 190, 230, 3,	 84,  238, 156, 119,
	    100, 86,  174, 37,	108, 167, 200, 67,  87,	 216, 223, 21,	30,
	    63,	 64,  170, 8,	202, 236, 134, 3,   30,	 37,  122, 220, 176,
	    112, 196, 38,  32,	140, 70,  41,  145, 164, 145, 2,   25,	110,
	    33,	 21,  70,  67,	176, 13,  148, 166, 32,	 32,  48,  1,	33,
	    181, 132, 204, 162, 72,  24,  6,   144, 64,	 72,  113, 25,	5,
	    10,	 97,  136, 48,	36,  7,	  108, 202, 22,	 49,  24,  53,	2,
	    225, 8,   140, 27,	21,  69,  195, 34,  112, 140, 66,  102, 196,
	    4,	 110, 80,  168, 104, 25,  49,  140, 3,	 56,  96,  27,	4,
	    32,	 68,  52,  96,	33,  201, 96,  76,  184, 109, 211, 184, 97,
	    10,	 166, 68,  9,	70,  110, 90,  150, 97,	 144, 162, 97,	82,
	    148, 141, 9,   194, 17,  8,	  22,  16,  28,	 199, 105, 90,	6,
	    113, 220, 2,   2,	219, 16,  69,  154, 130, 49,  12,  178, 69,
	    137, 6,   1,   139, 34,  78,  36,  195, 44,	 131, 162, 49,	136,
	    0,	 132, 27,  38,	133, 27,  178, 33,  138, 136, 12,  137, 146,
	    101, 226, 66,  106, 8,   52,  141, 28,  195, 65,  11,  167, 36,
	    25,	 144, 109, 33,	180, 72,  146, 40,  50,	 19,  64,  14,	27,
	    177, 64,  8,   8,	36,  161, 196, 97,  212, 70,  36,  148, 18,
	    78,	 9,   132, 13,	27,  39,  113, 33,  198, 5,   26,  50,	141,
	    75,	 166, 105, 16,	0,   134, 144, 134, 68,	 16,  65,  110, 26,
	    54,	 70,  32,  177, 97,  88,  180, 9,   25,	 167, 37,  16,	38,
	    4,	 128, 196, 104, 100, 180, 100, 97,  54,	 104, 145, 54,	50,
	    28,	 40,  98,  202, 194, 73,  26,  136, 109, 84,  56,  77,	20,
	    66,	 144, 26,  49,	140, 11,  5,   112, 28,	 64,  64,  224, 134,
	    129, 228, 24,  32,	140, 144, 12,  28,  64,	 4,   128, 148, 108,
	    200, 0,   140, 132, 56,  18,  140, 8,   34,	 162, 146, 41,	164,
	    2,	 102, 9,   36,	73,  35,  137, 48,  146, 130, 77,  145, 20,
	    145, 8,   68,  36,	26,  53,  110, 25,  71,	 112, 155, 192, 48,
	    195, 198, 104, 28,	18,  114, 1,   166, 41,	 12,  39,  16,	16,
	    18,	 37,  9,   168, 108, 3,	  130, 45,  155, 176, 80,  162, 130,
	    36,	 137, 6,   141, 218, 16,  142, 145, 132, 105, 74,  24,	102,
	    98,	 54,  114, 100, 162, 105, 3,   147, 104, 148, 6,   10,	26,
	    70,	 68,  139, 196, 68,  147, 8,   40,  17,	 55,  1,   128, 6,
	    144, 35,  7,   134, 18,  36,  13,  138, 0,	 8,   20,  161, 100,
	    202, 150, 81,  152, 38,  105, 76,  196, 68,	 34,  22,  102, 195,
	    200, 80,  160, 134, 64,  196, 180, 145, 194, 192, 137, 34,	9,
	    138, 81,  144, 77,	72,  56,  133, 144, 0,	 6,   132, 18,	146,
	    73,	 72,  46,  97,	166, 80,  97,  176, 96,	 80,  178, 37,	99,
	    72,	 105, 74,  56,	64,  203, 68,  8,   19,	 16,  2,   147, 160,
	    41,	 163, 200, 96,	218, 16,  142, 216, 32,	 137, 219, 34,	138,
	    4,	 161, 104, 27,	167, 69,  84,  22,  141, 2,   180, 17,	92,
	    66,	 128, 140, 20,	76,  140, 166, 140, 131, 52,  10,  226, 168,
	    113, 202, 198, 72,	9,   177, 73,  0,   149, 65,  161, 160, 40,
	    147, 38,  98,  16,	69,  128, 1,   176, 69,	 160, 4,   80,	196,
	    132, 80,  81,  160, 80,  219, 146, 129, 75,	 130, 145, 18,	54,
	    38,	 10,  35,  101, 97,  6,	  8,   204, 0,	 78,  10,  67,	101,
	    210, 48,  112, 228, 48,  137, 99,  22,  141, 144, 16,  44,	0,
	    18,	 9,   1,   22,	68,  35,  135, 132, 200, 70,  10,  2,	36,
	    128, 228, 146, 5,	88,  50,  14,  217, 6,	 42,  156, 32,	100,
	    164, 56,  66,  227, 50,  14,  225, 148, 37,	 99,  150, 97,	136,
	    0,	 68,  17,  56,	80,  225, 166, 44,  27,	 148, 73,  74,	166,
	    69,	 27,  69,  14,	0,   165, 80,  226, 40,	 1,   0,   50,	98,
	    137, 6,   96,  19,	51,  98,  34,  71,  144, 204, 176, 8,	17,
	    192, 113, 201, 36,	77,  200, 128, 0,   156, 194, 4,   148, 200,
	    100, 92,  16,  113, 35,  67,  68,  9,   23,	 104, 1,   144, 4,
	    34,	 134, 49,  66,	168, 4,	  164, 182, 136, 144, 6,   6,	160,
	    16,	 38,  65,  48,	65,  148, 128, 49,  19,	 129, 77,  75,	168,
	    37,	 3,   3,   0,	161, 152, 37,  194, 24,	 1,   3,   37,	1,
	    27,	 5,   141, 226, 40,  9,	  34,  69,  32,	 219, 16,  142, 153,
	    70,	 72,  195, 50,	69,  154, 20,  64,  3,	 197, 65,  19,	195,
	    132, 19,  16,  73,	35,  192, 69,  26,  73,	 109, 82,  48,	140,
	    219, 196, 109, 33,	35,  82,  66,  0,   18,	 192, 70,  138, 218,
	    228, 171, 43,  246, 102, 174, 209, 56,  49,	 165, 18,  32,	22,
	    46,	 83,  174, 18,	41,  73,  125, 135, 151, 10,  118, 73,	40,
	    253, 172, 69,  182, 90,  1,	  40,  248, 31,	 210, 195, 17,	45,
	    238, 38,  75,  157, 141, 234, 55,  96,  32,	 184, 156, 38,	190,
	    3,	 222, 130, 110, 6,   24,  243, 13,  49,	 221, 10,  37,	214,
	    222, 12,  181, 207, 35,  111, 98,  144, 218, 43,  13,  6,	160,
	    78,	 187, 252, 181, 1,   131, 130, 115, 125, 65,  199, 86,	249,
	    179, 37,  124, 88,	148, 115, 150, 5,   199, 163, 135, 244, 196,
	    237, 254, 128, 143, 44,  86,  115, 111, 42,	 164, 188, 51,	109,
	    68,	 113, 52,  173, 106, 210, 24,  160, 77,	 119, 34,  60,	187,
	    104, 211, 166, 211, 211, 214, 179, 25,  232, 25,  64,  187, 91,
	    206, 122, 65,  88,	5,   104, 128, 171, 23,	 136, 110, 255, 145,
	    52,	 213, 110, 115, 213, 245, 0,   8,   164, 141, 34,  45,	199,
	    194, 117, 141, 126, 139, 174, 235, 211, 180, 199, 104, 203, 156,
	    110, 167, 86,  249, 137, 202, 168, 245, 23,	 112, 73,  133, 221,
	    229, 221, 50,  33,	72,  224, 114, 254, 139, 128, 29,  99,	28,
	    222, 190, 5,   56,	20,  34,  138, 101, 116, 238, 168, 56,	155,
	    158, 165, 23,  10,	152, 155, 129, 224, 1,	 94,  180, 241, 108,
	    207, 135, 77,  196, 220, 245, 233, 174, 252, 38,  28,  242, 121,
	    223, 142, 204, 58,	118, 137, 91,  126, 211, 252, 126, 235, 227,
	    143, 106, 195, 210, 83,  254, 242, 158, 150, 174, 153, 170, 203,
	    145, 106, 48,  194, 22,  238, 151, 145, 186, 32,  173, 234, 93,
	    250, 118, 21,  120, 11,  195, 184, 27,  65,	 168, 64,  89,	127,
	    56,	 196, 87,  98,	218, 71,  155, 89,  54,	 132, 38,  167, 51,
	    233, 25,  7,   126, 113, 125, 74,  121, 39,	 125, 139, 121, 121,
	    91,	 12,  100, 198, 19,  56,  201, 88,  55,	 208, 43,  6,	133,
	    111, 143, 47,  62,	180, 102, 160, 124, 200, 210, 70,  203, 87,
	    17,	 168, 255, 227, 73,  78,  91,  13,  63,	 136, 179, 12,	60,
	    181, 47,  176, 219, 42,  188, 7,   141, 164, 205, 6,   162, 171,
	    24,	 52,  200, 93,	245, 254, 103, 67,  64,	 178, 68,  181, 30,
	    236, 192, 168, 213, 169, 157, 219, 12,  191, 171, 135, 130, 135,
	    25,	 240, 183, 200, 4,   240, 220, 215, 123, 100, 208, 82,	17,
	    14,	 32,  214, 195, 238, 3,	  109, 182, 247, 186, 231, 217, 219,
	    182, 233, 128, 105, 239, 3,	  217, 230, 42,	 93,  207, 221, 53,
	    5,	 5,   232, 198, 224, 195, 116, 181, 15,	 176, 17,  83,	87,
	    205, 153, 245, 218, 215, 195, 29,  235, 24,	 55,  76,  229, 219,
	    230, 252, 120, 52,	113, 45,  225, 76,  205, 161, 244, 211, 50,
	    34,	 99,  37,  106, 201, 14,  54,  61,  2,	 86,  31,  166, 245,
	    99,	 62,  140, 246, 169, 14,  175, 167, 22,	 51,  242, 102, 13,
	    211, 106, 199, 165, 80,  119, 152, 166, 197, 110, 100, 150, 112,
	    107, 12,  13,  64,	91,  78,  157, 50,  139, 104, 83,  119, 94,
	    38,	 66,  230, 25,	216, 48,  69,  193, 229, 249, 130, 149, 155,
	    107, 1,   80,  253, 78,  148, 34,  122, 191, 188, 221, 89,	198,
	    9,	 136, 56,  111, 115, 170, 98,  202, 49,	 85,  54,  40,	86,
	    42,	 144, 84,  107, 47,  179, 222, 227, 1,	 26,  124, 86,	8,
	    193, 191, 30,  146, 56,  8,	  142, 169, 57,	 27,  214, 145, 220,
	    200, 190, 35,  39,	101, 20,  155, 158, 167, 97,  232, 84,	110,
	    198, 146, 7,   147, 188, 49,  247, 74,  249, 134, 219, 61,	71,
	    180, 55,  182, 157, 76,  11,  214, 172, 110, 232, 189, 217, 51,
	    70,	 13,  25,  34,	145, 93,  39,  26,  72,	 65,  44,  232, 227,
	    172, 190, 16,  98,	18,  25,  148, 159, 238, 132, 158, 91,	224,
	    115, 136, 6,   158, 51,  84,  1,   207, 209, 159, 126, 156, 158,
	    226, 63,  164, 179, 89,  233, 79,  20,  33,	 251, 162, 59,	161,
	    93,	 135, 231, 161, 166, 244, 25,  131, 219, 47,  196, 142, 226,
	    246, 88,  233, 211, 12,  141, 195, 220, 85,	 149, 50,  168, 249,
	    230, 3,   255, 187, 121, 117, 213, 71,  214, 206, 87,  18,	222,
	    239, 143, 77,  217, 14,  91,  147, 26,  56,	 18,  125, 57,	163,
	    99,	 211, 1,   255, 39,  15,  77,  219, 37,	 83,  179, 59,	71,
	    255, 144, 140, 189, 16,  212, 161, 231, 223, 122, 78,  186, 20,
	    219, 191, 49,  244, 34,  88,  49,  241, 243, 216, 117, 204, 172,
	    218, 255, 237, 211, 31,  100, 41,  209, 31,	 128, 184, 213, 228,
	    180, 165, 31,  134, 128, 51,  143, 34,  146, 1,   178, 50,	106,
	    202, 34,  200, 29,	39,  201, 188, 71,  20,	 228, 125, 135, 15,
	    234, 57,  35,  123, 96,  246, 151, 139, 213, 51,  198, 251, 14,
	    226, 27,  141, 28,	170, 70,  233, 122, 172, 221, 240, 56,	172,
	    87,	 197, 50,  217, 120, 27,  114, 45,  102, 106, 88,  223, 202,
	    217, 62,  242, 129, 15,  147, 35,  246, 205, 108, 181, 209, 168,
	    223, 200, 253, 105, 155, 243, 118, 153, 3,	 159, 82,  92,	70,
	    236, 24,  213, 234, 68,  154, 128, 130, 53,	 221, 254, 61,	32,
	    81,	 130, 117, 107, 133, 90,  247, 25,  165, 228, 125, 64,	132,
	    33,	 92,  196, 192, 199, 195, 245, 179, 143, 106, 116, 137, 69,
	    206, 220, 104, 14,	240, 2,	  120, 201, 74,	 127, 46,  200, 110,
	    52,	 106, 104, 30,	202, 56,  86,  30,  75,	 239, 114, 194, 190,
	    119, 98,  242, 26,	37,  155, 203, 118, 172, 164, 244, 148, 0,
	    145, 76,  202, 3,	208, 25,  255, 142, 79,	 151, 23,  62,	111,
	    55,	 66,  34,  171, 229, 21,  76,  214, 168, 119, 99,  22,	34,
	    61,	 128, 146, 186, 126, 68,  155, 225, 221, 242, 68,  103, 30,
	    30,	 68,  127, 18,	174, 110, 237, 94,  94,	 119, 222, 14,	36,
	    29,	 48,  180, 250, 189, 140, 123, 145, 93,	 219, 69,  95,	5,
	    232, 131, 203, 19,	72,  144, 152, 8,   66,	 136, 139, 71,	125,
	    173, 195, 132, 247, 178, 230, 221, 29,  31,	 158, 21,  184, 210,
	    0,	 39,  104, 31,	212, 157, 183, 35,  104, 233, 56,  80,	115,
	    112, 48,  24,  174, 170, 122, 236, 82,  114, 136, 32,  118, 204,
	    71,	 251, 97,  166, 11,  78,  47,  137, 210, 217, 41,  103, 198,
	    85,	 188, 127, 181, 94,  2,	  33,  227, 35,	 78,  182, 153, 73,
	    78,	 192, 134, 62,	62,  207, 155, 176, 106, 187, 31,  170, 137,
	    199, 111, 168, 140, 110, 157, 177, 127, 170, 107, 15,  238, 83,
	    102, 141, 236, 180, 9,   33,  37,  82,  106, 198, 157, 64,	255,
	    91,	 80,  62,  251, 45,  156, 142, 36,  220, 59,  33,  90,	55,
	    78,	 117, 241, 145, 27,  186, 124, 13,  205, 89,  51,  84,	161,
	    211, 137, 74,  36,	179, 131, 82,  236, 93,	 3,   228, 100, 219,
	    241, 130, 188, 199, 234, 38,  71,  11,  148, 240, 0,   88,	38,
	    245, 61,  98,  140, 165, 53,  155, 138, 239, 20,  35,  66,	28,
	    236, 89,  44,  30,	136, 119, 225, 20,  52,	 63,  24,  42,	224,
	    239, 44,  245, 117, 96,  91,  146, 8,   179, 206, 28,  17,	122,
	    234, 152, 54,  39,	30,  154, 11,  6,   97,	 136, 175, 224, 142,
	    17,	 81,  197, 51,	52,  207, 193, 253, 156, 179, 155, 65,	169,
	    19,	 180, 243, 180, 197, 225, 13,  61,  35,	 183, 82,  52,	160,
	    198, 58,  143, 54,	6,   174, 150, 56,  27,	 45,  190, 120, 10,
	    235, 18,  104, 19,	112, 229, 149, 207, 26,	 192, 20,  90,	82,
	    125, 42,  14,  171, 166, 179, 21,  225, 2,	 172, 89,  93,	84,
	    41,	 240, 221, 182, 92,  55,  139, 93,  139, 107, 72,  130, 67,
	    187, 162, 14,  25,	104, 101, 156, 96,  17,	 154, 237, 194, 108,
	    70,	 32,  137, 61,	65,  209, 236, 236, 212, 230, 245, 136, 202,
	    171, 112, 23,  37,	12,  113, 119, 112, 90,	 74,  187, 195, 53,
	    8,	 17,  84,  79,	109, 80,  184, 244, 39,	 209, 87,  72,	86,
	    44,	 91,  50,  148, 44,  94,  214, 181, 166, 251, 191, 59,	153,
	    218, 248, 188, 124, 136, 167, 79,  106, 172, 186, 149, 125, 178,
	    78,	 98,  51,  143, 90,  165, 26,  180, 161, 208, 219, 69,	21,
	    239, 232, 244, 146, 60,  192, 69,  72,  139, 71,  103, 67,	141,
	    29,	 56,  160, 134, 163, 237, 112, 174, 21,	 153, 244, 117, 227,
	    250, 122, 95,  136, 103, 94,  0,   221, 184, 239, 168, 143, 133,
	    49,	 140, 213, 66,	164, 223, 122, 188, 18,	 119, 17,  137, 110,
	    13,	 252, 96,  140, 134, 225, 129, 37,  225, 31,  24,  53,	166,
	    227, 170, 198, 108, 50,  198, 3,   45,  161, 196, 143, 120, 83,
	    26,	 4,   211, 226, 161, 167, 123, 103, 6,	 169, 187, 125, 192,
	    96,	 6,   132, 115, 70,  170, 178, 181, 111, 199, 152, 11,	89,
	    32,	 242, 130, 187, 62,  192, 205, 9,   164, 122, 125, 128, 4,
	    235, 23,  204, 81,	123, 220, 171, 250, 221, 9,   104, 175, 157,
	    52,	 0,   175, 33,	229, 102, 225, 101, 39,	 161, 226, 215, 230,
	    135, 114, 186, 196, 21,  39,  28,  23,  137, 242, 96,  107, 158,
	    105, 125, 249, 102, 195, 182, 17,  235, 145, 144, 84,  65,	77,
	    136, 89,  35,  25,	226, 145, 42,  222, 150, 176, 48,  127, 213,
	    66,	 12,  162, 224, 248, 23,  26,  102, 211, 80,  97,  186, 132,
	    0,	 102, 10,  49,	170, 208, 64,  232, 141, 248, 165, 92,	166,
	    89,	 168, 172, 235, 181, 251, 43,  119, 169, 176, 36,  71,	253,
	    12,	 38,  197, 41,	161, 147, 158, 237, 47,	 24,  43,  76,	126,
	    53,	 172, 191, 12,	170, 196, 144, 89,  79,	 190, 153, 136};
	u8 expected_sig[] = {
	    108, 214, 117, 89,	67,  56,  98,  249, 206, 100, 221, 137, 204,
	    21,	 242, 84,  255, 26,  93,  155, 113, 16,	 135, 126, 204, 97,
	    222, 183, 192, 230, 72,  204, 150, 231, 105, 34,  152, 152, 219,
	    164, 172, 145, 112, 60,  115, 32,  136, 119, 242, 79,  93,	106,
	    234, 220, 178, 75,	32,  253, 219, 198, 183, 196, 255, 4,	241,
	    81,	 158, 63,  125, 143, 119, 133, 243, 120, 213, 189, 186, 73,
	    228, 216, 224, 164, 109, 110, 149, 205, 253, 183, 162, 126, 186,
	    208, 62,  93,  187, 197, 24,  130, 1,   50,	 165, 168, 141, 122,
	    76,	 239, 61,  198, 103, 242, 153, 142, 64,	 253, 167, 26,	230,
	    28,	 110, 206, 76,	124, 163, 19,  62,  13,	 152, 79,  9,	161,
	    238, 48,  15,  165, 216, 100, 199, 94,  227, 118, 192, 104, 9,
	    200, 5,   110, 223, 118, 211, 196, 44,  195, 116, 31,  98,	152,
	    159, 204, 248, 64,	224, 33,  143, 5,   35,	 219, 36,  189, 73,
	    228, 60,  104, 98,	79,  143, 38,  180, 33,	 24,  228, 124, 198,
	    124, 192, 45,  212, 24,  26,  120, 81,  168, 40,  94,  221, 80,
	    92,	 246, 123, 81,	235, 40,  215, 250, 159, 35,  106, 160, 216,
	    163, 151, 200, 15,	178, 124, 72,  151, 179, 240, 137, 200, 242,
	    78,	 112, 223, 244, 2,   173, 206, 3,   88,	 166, 136, 148, 98,
	    191, 216, 80,  66,	113, 195, 39,  23,  63,	 42,  152, 19,	209,
	    208, 165, 56,  120, 66,  144, 63,  106, 122, 29,  97,  248, 132,
	    155, 100, 153, 97,	0,   8,	  205, 113, 144, 205, 58,  14,	10,
	    94,	 97,  177, 142, 231, 106, 82,  80,  251, 118, 170, 134, 77,
	    124, 244, 147, 178, 8,   13,  94,  118, 148, 95,  126, 125, 99,
	    191, 118, 176, 220, 213, 60,  175, 150, 242, 7,   160, 182, 5,
	    139, 25,  127, 189, 124, 223, 218, 127, 209, 52,  190, 102, 221,
	    164, 67,  115, 2,	76,  203, 238, 26,  60,	 125, 209, 118, 71,
	    119, 26,  52,  70,	44,  151, 251, 117, 231, 42,  117, 214, 108,
	    141, 13,  103, 120, 227, 15,  185, 244, 204, 152, 56,  53,	184,
	    15,	 22,  92,  143, 211, 77,  88,  212, 56,	 180, 98,  147, 20,
	    225, 84,  112, 150, 59,  129, 231, 92,  164, 255, 64,  171, 32,
	    57,	 184, 28,  113, 134, 109, 149, 0,   95,	 240, 207, 31,	30,
	    249, 177, 8,   249, 163, 155, 244, 185, 160, 195, 113, 111, 125,
	    227, 112, 228, 212, 196, 233, 77,  169, 241, 155, 54,  136, 94,
	    233, 134, 74,  223, 97,  224, 11,  136, 4,	 133, 77,  62,	193,
	    13,	 1,   213, 188, 250, 52,  93,  28,  6,	 119, 133, 139, 241,
	    74,	 116, 125, 185, 197, 192, 237, 30,  113, 234, 166, 67,	246,
	    31,	 202, 121, 135, 174, 19,  233, 124, 102, 59,  24,  166, 147,
	    204, 127, 59,  34,	154, 133, 241, 140, 145, 104, 184, 178, 240,
	    86,	 133, 183, 207, 92,  241, 188, 149, 167, 105, 58,  250, 221,
	    216, 147, 114, 122, 204, 179, 46,  117, 179, 148, 141, 134, 29,
	    145, 221, 82,  160, 99,  226, 43,  251, 46,	 172, 227, 92,	226,
	    102, 253, 201, 144, 229, 118, 33,  87,  194, 173, 36,  13,	73,
	    66,	 127, 40,  17,	83,  251, 111, 208, 253, 75,  245, 177, 86,
	    52,	 140, 13,  37,	179, 115, 195, 86,  82,	 45,  97,  171, 62,
	    32,	 211, 164, 78,	213, 130, 191, 66,  15,	 175, 55,  129, 244,
	    243, 62,  159, 1,	108, 33,  51,  254, 232, 31,  199, 251, 188,
	    137, 75,  23,  218, 167, 14,  147, 117, 83,	 89,  52,  221, 10,
	    169, 97,  194, 209, 74,  91,  91,  90,  176, 88,  16,  234, 149,
	    22,	 156, 54,  110, 235, 157, 52,  92,  232, 111, 9,   149, 145,
	    171, 106, 67,  50,	60,  191, 176, 97,  130, 5,   184, 231, 36,
	    219, 60,  221, 249, 66,  97,  38,  251, 209, 231, 219, 13,	121,
	    198, 234, 51,  58,	67,  214, 2,   25,  39,	 16,  126, 173, 103,
	    252, 244, 90,  105, 11,  177, 96,  145, 104, 148, 107, 149, 233,
	    84,	 176, 137, 8,	174, 146, 239, 240, 156, 21,  96,  113, 104,
	    250, 167, 252, 111, 200, 169, 246, 199, 52,	 200, 203, 215, 67,
	    181, 251, 230, 46,	95,  107, 89,  235, 19,	 28,  175, 124, 213,
	    239, 175, 255, 152, 1,   69,  89,  166, 235, 113, 171, 182, 178,
	    176, 171, 93,  8,	102, 78,  197, 189, 141, 36,  60,  84,	108,
	    162, 242, 204, 142, 53,  249, 185, 158, 101, 62,  33,  175, 218,
	    100, 227, 103, 29,	198, 250, 250, 30,  129, 133, 78,  221, 254,
	    135, 188, 144, 228, 18,  90,  201, 60,  8,	 22,  25,  192, 216,
	    211, 19,  21,  138, 3,   207, 220, 43,  249, 74,  249, 31,	229,
	    20,	 142, 81,  214, 214, 145, 87,  224, 220, 245, 177, 205, 238,
	    66,	 248, 248, 150, 35,  1,	  132, 233, 52,	 170, 32,  27,	0,
	    104, 153, 13,  191, 80,  129, 72,  106, 232, 27,  93,  124, 108,
	    246, 222, 90,  174, 74,  178, 195, 190, 202, 191, 202, 182, 159,
	    21,	 115, 242, 17,	141, 104, 137, 22,  197, 127, 163, 22,	55,
	    11,	 203, 196, 214, 250, 121, 4,   201, 1,	 179, 48,  192, 183,
	    217, 20,  4,   36,	94,  141, 162, 222, 243, 94,  3,   60,	41,
	    182, 237, 173, 124, 197, 141, 42,  222, 25,	 60,  3,   187, 151,
	    130, 105, 190, 183, 188, 138, 233, 202, 1,	 236, 173, 191, 84,
	    194, 47,  163, 19,	94,  179, 3,   93,  190, 71,  125, 79,	152,
	    4,	 154, 221, 135, 199, 181, 194, 85,  17,	 185, 36,  127, 107,
	    225, 227, 16,  12,	113, 71,  30,  67,  112, 144, 89,  51,	7,
	    250, 169, 70,  245, 214, 62,  209, 16,  12,	 71,  216, 61,	14,
	    228, 158, 41,  252, 57,  116, 206, 173, 82,	 227, 164, 35,	126,
	    252, 221, 182, 210, 235, 247, 55,  249, 218, 155, 83,  38,	87,
	    77,	 205, 115, 247, 227, 210, 126, 99,  89,	 50,  4,   121, 85,
	    203, 119, 55,  91,	101, 51,  144, 94,  202, 104, 70,  131, 225,
	    31,	 174, 74,  95,	182, 27,  161, 137, 77,	 191, 63,  212, 202,
	    225, 174, 224, 226, 11,  172, 199, 58,  144, 59,  108, 1,	211,
	    78,	 130, 185, 175, 216, 207, 163, 117, 18,	 227, 46,  240, 99,
	    212, 88,  153, 53,	26,  212, 81,  243, 126, 215, 206, 89,	215,
	    38,	 19,  115, 204, 81,  190, 98,  103, 54,	 150, 254, 145, 88,
	    181, 189, 120, 200, 136, 32,  166, 241, 179, 227, 183, 31,	5,
	    92,	 115, 170, 44,	214, 119, 70,  202, 36,	 36,  220, 230, 206,
	    203, 176, 239, 19,	216, 93,  127, 106, 85,	 161, 4,   27,	31,
	    249, 252, 210, 117, 101, 233, 117, 52,  153, 49,  39,  56,	232,
	    148, 114, 55,  58,	213, 209, 139, 5,   101, 176, 82,  8,	212,
	    230, 210, 116, 59,	75,  167, 138, 7,   5,	 118, 224, 109, 204,
	    193, 101, 124, 61,	64,  175, 55,  182, 54,	 227, 180, 229, 232,
	    126, 17,  109, 54,	39,  53,  25,  217, 170, 110, 85,  76,	132,
	    131, 86,  63,  237, 239, 165, 197, 5,   234, 6,   180, 177, 221,
	    187, 255, 195, 113, 187, 32,  155, 132, 62,	 144, 127, 253, 125,
	    41,	 144, 153, 147, 139, 236, 46,  129, 0,	 246, 79,  26,	76,
	    225, 63,  115, 131, 65,  69,  112, 84,  242, 176, 194, 123, 209,
	    62,	 28,  118, 53,	168, 15,  156, 211, 222, 126, 71,  255, 187,
	    84,	 171, 251, 84,	89,  219, 15,  208, 170, 17,  140, 109, 85,
	    126, 230, 197, 64,	99,  41,  243, 37,  80,	 22,  140, 142, 116,
	    254, 115, 244, 161, 153, 206, 108, 118, 40,	 61,  127, 233, 233,
	    103, 21,  149, 168, 41,  5,	  56,  225, 253, 213, 168, 17,	42,
	    27,	 168, 250, 181, 254, 242, 229, 84,  72,	 96,  123, 238, 188,
	    180, 131, 203, 75,	14,  60,  133, 118, 158, 20,  171, 238, 143,
	    245, 12,  164, 19,	101, 170, 228, 160, 61,	 66,  43,  117, 114,
	    124, 100, 100, 89,	20,  13,  80,  188, 35,	 215, 235, 164, 20,
	    34,	 29,  138, 103, 128, 72,  13,  185, 93,	 167, 185, 227, 230,
	    121, 231, 180, 36,	165, 129, 53,  36,  230, 249, 125, 252, 103,
	    245, 213, 93,  94,	114, 224, 122, 41,  234, 177, 50,  225, 72,
	    180, 114, 210, 223, 168, 151, 70,  66,  227, 135, 123, 86,	189,
	    106, 219, 177, 183, 100, 94,  33,  144, 96,	 212, 54,  7,	95,
	    246, 180, 240, 147, 167, 62,  73,  34,  225, 128, 133, 9,	33,
	    15,	 133, 55,  182, 207, 106, 141, 99,  46,	 93,  34,  100, 28,
	    255, 102, 54,  29,	1,   160, 244, 133, 170, 157, 153, 6,	2,
	    190, 109, 107, 11,	68,  250, 146, 184, 254, 97,  203, 126, 200,
	    29,	 187, 27,  203, 204, 217, 231, 251, 25,	 59,  82,  42,	151,
	    124, 157, 150, 127, 44,  154, 95,  7,   131, 205, 107, 97,	111,
	    48,	 81,  90,  65,	145, 25,  70,  182, 45,	 99,  202, 245, 57,
	    120, 181, 195, 168, 43,  226, 206, 179, 101, 173, 65,  165, 137,
	    105, 208, 42,  107, 242, 67,  15,  77,  106, 160, 36,  223, 180,
	    212, 148, 137, 41,	176, 83,  248, 97,  203, 244, 198, 77,	73,
	    183, 92,  150, 150, 52,  240, 192, 43,  51,	 88,  255, 196, 58,
	    200, 210, 57,  146, 24,  112, 70,  22,  128, 73,  249, 33,	47,
	    111, 206, 242, 37,	63,  122, 87,  180, 92,	 31,  188, 169, 205,
	    7,	 103, 115, 182, 14,  113, 87,  161, 127, 3,   195, 31,	0,
	    26,	 240, 141, 196, 59,  17,  216, 141, 81,	 34,  250, 160, 55,
	    205, 108, 203, 144, 228, 152, 206, 31,  31,	 42,  177, 44,	151,
	    175, 239, 194, 253, 30,  64,  7,   254, 85,	 17,  84,  9,	98,
	    252, 225, 233, 199, 92,  221, 58,  78,  168, 125, 215, 124, 37,
	    183, 114, 225, 128, 143, 255, 229, 173, 151, 161, 219, 179, 249,
	    76,	 109, 33,  194, 8,   223, 209, 100, 33,	 97,  23,  149, 83,
	    232, 56,  71,  12,	179, 108, 143, 122, 9,	 117, 110, 92,	14,
	    51,	 108, 56,  139, 166, 136, 37,  9,   198, 138, 67,  33,	212,
	    215, 94,  6,   54,	190, 83,  194, 145, 135, 15,  170, 143, 99,
	    50,	 66,  125, 173, 103, 128, 54,  200, 78,	 211, 36,  64,	218,
	    18,	 249, 179, 241, 23,  215, 33,  231, 113, 148, 194, 151, 156,
	    174, 68,  9,   57,	99,  188, 29,  201, 23,	 29,  250, 120, 109,
	    92,	 164, 45,  193, 107, 129, 222, 211, 174, 186, 118, 33,	162,
	    26,	 122, 188, 94,	156, 206, 112, 59,  252, 196, 131, 1,	107,
	    105, 128, 164, 140, 51,  191, 245, 247, 38,	 157, 30,  50,	169,
	    180, 97,  21,  156, 106, 57,  165, 83,  14,	 9,   99,  236, 230,
	    118, 203, 7,   177, 215, 233, 107, 86,  97,	 171, 34,  111, 204,
	    98,	 248, 134, 255, 202, 15,  104, 142, 68,	 46,  133, 153, 120,
	    61,	 94,  8,   6,	93,  81,  6,   170, 69,	 210, 122, 170, 42,
	    28,	 3,   17,  67,	99,  57,  173, 122, 245, 200, 47,  12,	1,
	    168, 245, 89,  242, 137, 60,  38,  215, 102, 158, 70,  154, 76,
	    158, 69,  91,  77,	59,  178, 172, 233, 240, 107, 134, 77,	73,
	    200, 6,   210, 102, 154, 135, 38,  186, 133, 36,  195, 152, 144,
	    236, 142, 117, 7,	7,   81,  224, 126, 16,	 115, 175, 193, 168,
	    216, 116, 204, 136, 230, 41,  131, 92,  246, 146, 113, 90,	156,
	    9,	 250, 233, 150, 15,  74,  138, 160, 55,	 175, 199, 124, 28,
	    237, 81,  64,  183, 220, 0,	  18,  163, 196, 104, 42,  91,	19,
	    4,	 96,  199, 86,	153, 254, 178, 204, 166, 152, 79,  208, 165,
	    176, 62,  169, 183, 225, 99,  65,  254, 114, 160, 110, 36,	237,
	    106, 70,  138, 113, 34,  230, 90,  64,  245, 37,  114, 93,	87,
	    182, 128, 129, 144, 72,  126, 162, 157, 141, 221, 127, 108, 194,
	    184, 118, 83,  209, 107, 102, 97,  75,  125, 114, 122, 19,	39,
	    29,	 68,  22,  164, 184, 219, 59,  42,  155, 159, 91,  137, 213,
	    77,	 132, 30,  113, 152, 250, 233, 210, 184, 142, 45,  40,	13,
	    112, 83,  234, 213, 221, 205, 234, 12,  211, 213, 157, 126, 197,
	    112, 172, 147, 170, 23,  156, 221, 87,  194, 22,  84,  37,	90,
	    12,	 206, 224, 155, 171, 78,  142, 163, 75,	 146, 86,  214, 11,
	    173, 83,  208, 67,	167, 154, 165, 40,  97,	 91,  14,  157, 71,
	    123, 245, 41,  233, 127, 144, 175, 226, 69,	 144, 151, 56,	97,
	    101, 13,  95,  158, 13,  177, 65,  3,   212, 218, 182, 253, 197,
	    170, 162, 174, 188, 227, 224, 192, 160, 219, 74,  223, 127, 204,
	    229, 145, 44,  231, 233, 125, 232, 201, 183, 245, 24,  93,	174,
	    121, 46,  96,  64,	105, 106, 75,  66,  173, 62,  57,  53,	138,
	    139, 230, 238, 130, 252, 17,  246, 104, 210, 89,  49,  35,	171,
	    163, 1,   188, 34,	79,  84,  233, 65,  166, 9,   3,   138, 191,
	    66,	 91,  184, 5,	138, 179, 230, 59,  241, 208, 113, 14,	102,
	    114, 5,   71,  127, 247, 255, 198, 155, 158, 229, 95,  27,	143,
	    172, 177, 174, 139, 186, 121, 107, 220, 5,	 203, 255, 5,	172,
	    51,	 97,  97,  193, 113, 227, 228, 124, 110, 206, 165, 250, 223,
	    68,	 181, 9,   113, 45,  17,  196, 15,  161, 59,  166, 140, 217,
	    159, 102, 23,  64,	240, 245, 84,  73,  228, 32,  182, 244, 86,
	    84,	 43,  140, 20,	93,  218, 150, 35,  77,	 166, 110, 3,	241,
	    8,	 67,  2,   120, 209, 230, 59,  79,  237, 114, 114, 27,	106,
	    178, 3,   175, 31,	7,   69,  184, 253, 161, 27,  101, 159, 98,
	    230, 17,  254, 110, 82,  246, 198, 129, 133, 235, 123, 243, 198,
	    175, 69,  155, 172, 212, 136, 32,  114, 8,	 2,   13,  19,	33,
	    37,	 62,  68,  70,	71,  86,  92,  99,  116, 129, 171, 177, 205,
	    216, 229, 251, 8,	13,  19,  41,  48,  82,	 83,  87,  105, 125,
	    200, 5,   38,  54,	67,  88,  95,  96,  97,	 98,  101, 114, 122,
	    133, 154, 181, 199, 204, 207, 208, 212, 229, 33,  38,  88,	136,
	    137, 139, 156, 171, 183, 192, 209, 212, 239, 244, 0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   20,	31,
	    52,	 66,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
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

