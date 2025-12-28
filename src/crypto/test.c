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
	    200, 145, 3,   61,	87,  60,  230, 62,  98,	 251, 248, 205, 62,
	    250, 64,  247, 214, 7,   60,  47,  119, 91,	 11,  200, 237, 148,
	    174, 45,  247, 205, 119, 216, 120, 62,  68,	 164, 83,  216, 249,
	    46,	 191, 10,  130, 206, 193, 193, 52,  82,	 19,  28,  129, 176,
	    165, 175, 222, 220, 71,  177, 61,  32,  132, 23,  14,  127, 150,
	    54,	 146, 206, 215, 220, 237, 236, 138, 137, 172, 3,   103, 50,
	    134, 205, 202, 89,	137, 137, 171, 206, 68,	 92,  55,  35,	6,
	    209, 67,  1,   2,	38,  161, 159, 46,  133, 132, 239, 123, 229,
	    18,	 69,  95,  26,	248, 161, 9,   185, 101, 242, 61,  163, 219,
	    228, 253, 207, 49,	60,  107, 56,  134, 93,	 219, 84,  61,	212,
	    2,	 224, 135, 239, 236, 161, 115, 64,  12,	 154, 70,  76,	247,
	    73,	 26,  9,   4,	131, 192, 231, 12,  249, 52,  226, 159, 66,
	    127, 5,   69,  2,	130, 171, 16,  62,  5,	 81,  123, 43,	213,
	    107, 90,  230, 92,	80,  220, 175, 214, 124, 240, 109, 32,	34,
	    163, 116, 109, 25,	133, 188, 83,  95,  72,	 236, 231, 164, 250,
	    76,	 194, 173, 19,	194, 86,  156, 9,   158, 126, 30,  124, 0,
	    70,	 232, 6,   154, 166, 106, 0,   55,  65,	 95,  129, 124, 32,
	    91,	 145, 185, 168, 14,  142, 202, 173, 70,	 6,   89,  68,	1,
	    223, 23,  165, 242, 33,  46,  161, 114, 97,	 108, 234, 228, 87,
	    58,	 196, 239, 237, 225, 91,  248, 211, 209, 51,  150, 209, 152,
	    201, 221, 64,  205, 39,  132, 192, 223, 98,	 98,  85,  218, 57,
	    61,	 23,  208, 47,	45,  10,  227, 202, 50,	 0,   72,  94,	158,
	    84,	 109, 140, 111, 164, 191, 80,  129, 165, 30,  169, 9,	187,
	    124, 42,  227, 57,	253, 53,  181, 164, 84,	 185, 53,  247, 23,
	    171, 164, 193, 84,	77,  61,  0,   48,  132, 111, 55,  166, 81,
	    53,	 71,  30,  117, 190, 68,  156, 118, 244, 162, 99,  165, 84,
	    242, 205, 39,  166, 12,  17,  121, 165, 96,	 246, 249, 32,	161,
	    147, 86,  76,  244, 142, 8,	  253, 16,  229, 64,  235, 21,	124,
	    152, 207, 66,  45,	69,  253, 73,  156, 141, 37,  98,  181, 85,
	    50,	 103, 104, 194, 239, 170, 222, 223, 179, 209, 39,  241, 39,
	    244, 148, 209, 96,	92,  54,  150, 114, 16,	 24,  66,  90,	36,
	    33,	 208, 85,  87,	165, 115, 66,  77,  27,	 234, 144, 60,	131,
	    4,	 110, 249, 224, 165, 52,  158, 94,  40,	 161, 64,  241, 212,
	    150, 254, 193, 2,	152, 150, 129, 249, 222, 17,  229, 165, 89,
	    62,	 125, 136, 182, 134, 112, 235, 145, 104, 200, 224, 2,	103,
	    217, 87,  232, 53,	10,  101, 162, 69,  52,	 119, 59,  71,	129,
	    248, 139, 109, 100, 174, 167, 7,   198, 143, 124, 239, 162, 244,
	    89,	 148, 232, 147, 97,  5,	  128, 13,  195, 44,  190, 139, 46,
	    180, 240, 222, 61,	29,  219, 125, 55,  211, 237, 214, 194, 131,
	    68,	 213, 57,  15,	148, 30,  118, 36,  107, 217, 157, 41,	253,
	    236, 141, 235, 136, 63,  130, 241, 254, 91,	 233, 78,  154, 36,
	    198, 183, 165, 17,	168, 69,  130, 172, 193, 227, 48,  92,	162,
	    13,	 5,   213, 8,	214, 196, 209, 253, 11,	 117, 155, 224, 97,
	    202, 224, 56,  108, 48,  162, 143, 94,  80,	 231, 170, 91,	65,
	    220, 181, 255, 168, 122, 172, 215, 122, 199, 18,  37,  201, 197,
	    177, 194, 40,  166, 91,  47,  252, 77,  65,	 215, 68,  81,	135,
	    61,	 88,  141, 171, 66,  160, 187, 18,  136, 61,  191, 212, 1,
	    65,	 76,  117, 147, 200, 163, 202, 252, 222, 204, 183, 29,	255,
	    171, 226, 164, 126, 0,   225, 96,  22,  254, 71,  103, 63,	199,
	    135, 100, 244, 173, 162, 37,  125, 54,  234, 74,  77,  216, 97,
	    204, 36,  73,  146, 22,  159, 23,  104, 60,	 59,  240, 107, 149,
	    91,	 72,  156, 157, 249, 4,	  33,  98,  69,	 172, 212, 31,	82,
	    178, 15,  205, 108, 251, 230, 51,  245, 72,	 132, 212, 149, 71,
	    80,	 222, 134, 112, 95,  114, 22,  92,  235, 162, 61,  128, 30,
	    239, 243, 251, 38,	105, 41,  202, 18,  12,	 8,   3,   144, 97,
	    96,	 212, 53,  31,	186, 211, 204, 41,  189, 228, 233, 120, 218,
	    67,	 61,  202, 253, 50,  34,  58,  82,  229, 173, 109, 67,	136,
	    192, 22,  37,  6,	85,  254, 133, 201, 133, 2,   42,  165, 37,
	    95,	 98,  230, 133, 139, 71,  173, 87,  105, 231, 167, 56,	233,
	    195, 134, 109, 59,	182, 84,  250, 242, 177, 244, 130, 45,	190,
	    172, 194, 96,  46,	72,  69,  220, 70,  169, 241, 232, 204, 135,
	    105, 100, 61,  235, 54,  27,  89,  131, 107, 73,  103, 255, 208,
	    65,	 219, 0,   67,	215, 7,	  223, 150, 143, 152, 225, 121, 114,
	    205, 159, 108, 14,	63,  60,  134, 11,  22,	 87,  187, 148, 211,
	    193, 120, 216, 114, 28,  93,  175, 147, 113, 153, 20,  45,	120,
	    26,	 79,  241, 201, 24,  242, 186, 232, 138, 121, 236, 182, 39,
	    211, 7,   51,  139, 223, 191, 93,  18,  46,	 108, 66,  26,	119,
	    161, 181, 180, 112, 216, 116, 194, 67,  185, 174, 99,  107, 15,
	    41,	 53,  249, 146, 10,  113, 184, 31,  95,	 254, 180, 177, 37,
	    118, 119, 235, 21,	123, 112, 125, 67,  152, 2,   92,  126, 38,
	    189, 203, 204, 125, 10,  243, 4,   118, 28,	 53,  55,  252, 84,
	    215, 221, 213, 0,	219, 247, 83,  180, 3,	 58,  77,  111, 158,
	    211, 93,  78,  104, 22,  6,	  121, 157, 106, 83,  106, 39,	3,
	    60,	 22,  23,  46,	231, 23,  29,  33,  39,	 229, 140, 1,	158,
	    60,	 190, 153, 129, 231, 42,  18,  89,  246, 172, 229, 170, 187,
	    49,	 88,  54,  80,	37,  106, 82,  127, 59,	 143, 2,   77,	17,
	    216, 175, 149, 213, 228, 21,  56,  241, 166, 153, 125, 132, 240,
	    6,	 167, 255, 207, 90,  80,  144, 235, 224, 202, 40,  214, 120,
	    124, 22,  2,   110, 177, 35,  6,   161, 156, 98,  205, 110, 110,
	    224, 251, 247, 138, 232, 72,  96,  90,  38,	 241, 233, 44,	37,
	    215, 140, 201, 85,	116, 80,  174, 234, 142, 192, 158, 64,	159,
	    195, 38,  153, 199, 43,  79,  222, 22,  48,	 133, 131, 185, 109,
	    119, 32,  26,  208, 168, 191, 157, 93,  72,	 254, 246, 159, 3,
	    194, 199, 5,   178, 171, 62,  136, 15,  38,	 133, 9,   63,	142,
	    110, 119, 1,   59,	236, 171, 84,  43,  54,	 153, 84,  3,	253,
	    50,	 2,   227, 59,	51,  170, 29,  21,  248, 90,  140, 166, 162,
	    28,	 193, 65,  252, 119, 151, 130, 4,   123, 142, 184, 35,	192,
	    183, 69,  169, 63,	109, 120, 228, 120, 202, 41,  173, 165, 175,
	    245, 21,  76,  91,	219, 54,  23,  149, 192, 77,  224, 166, 248,
	    48,	 25,  221, 81,	9,   177, 178, 31,  157, 150, 146, 249, 41,
	    131, 225, 155, 18,	158, 254, 15,  62,  198, 87,  138, 225, 238,
	    235, 100, 197, 15,	170, 246, 112, 231, 40,	 52,  92,  194, 92,
	    157, 100, 192, 74,	104, 120, 155, 103, 89,	 94,  156, 166, 147,
	    3,	 130, 147, 128, 95,  141, 63,  129, 237, 2,   81,  196, 105,
	    29,	 229, 255, 153, 72,  36,  194, 241, 221, 233, 53,  194, 255,
	    98,	 238, 149, 222, 88,  95,  167, 139, 183, 119, 212, 99,	85,
	    87,	 245, 60,  24,	99,  208, 224, 189, 237, 153, 21,  40,	46,
	    42,	 110, 119, 12,	42,  71,  172, 74,  29,	 233, 158, 120, 132,
	    65,	 75,  255, 104, 68,  115, 89,  158, 211, 211, 77,  72};
	u8 expected_sk[] = {
	    120, 160, 26,  249, 126, 128, 73,  119, 247, 146, 172, 145, 109,
	    5,	 140, 7,   193, 149, 163, 127, 54,  230, 201, 42,  89,	235,
	    200, 145, 3,   61,	87,  60,  151, 92,  158, 208, 93,  24,	254,
	    98,	 1,   112, 135, 110, 0,	  165, 198, 67,	 97,  47,  44,	253,
	    189, 186, 200, 214, 199, 125, 87,  65,  19,	 157, 189, 100, 37,
	    230, 76,  40,  128, 169, 198, 1,   72,  90,	 226, 223, 112, 30,
	    216, 145, 119, 94,	135, 119, 83,  67,  236, 54,  150, 229, 135,
	    103, 192, 199, 74,	199, 31,  130, 107, 102, 49,  147, 168, 171,
	    41,	 77,  226, 20,	140, 43,  212, 194, 48,	 150, 191, 81,	176,
	    249, 100, 200, 9,	182, 198, 125, 101, 0,	 66,  188, 220, 176,
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
	    219, 196, 109, 33,	35,  82,  66,  0,   18,	 192, 70,  138, 180,
	    83,	 127, 153, 47,	173, 28,  110, 101, 110, 118, 109, 123, 110,
	    151, 207, 234, 57,	164, 129, 160, 113, 30,	 77,  156, 64,	70,
	    11,	 89,  176, 42,	202, 121, 108, 251, 5,	 45,  254, 120, 216,
	    25,	 19,  118, 16,	157, 65,  165, 201, 248, 109, 108, 176, 26,
	    182, 75,  233, 154, 52,  220, 96,  198, 111, 98,  85,  20,	113,
	    118, 42,  176, 48,	51,  229, 30,  197, 225, 105, 108, 178, 176,
	    207, 138, 222, 252, 210, 179, 105, 92,  23,	 188, 97,  175, 173,
	    104, 54,  166, 44,	86,  34,  102, 242, 216, 196, 237, 249, 85,
	    14,	 5,   146, 180, 46,  188, 189, 16,  241, 199, 141, 153, 226,
	    68,	 140, 89,  194, 76,  212, 234, 139, 87,	 45,  25,  16,	199,
	    94,	 172, 124, 28,	155, 88,  61,  159, 91,	 250, 16,  151, 123,
	    7,	 238, 219, 231, 162, 198, 63,  207, 135, 208, 39,  182, 81,
	    119, 179, 16,  141, 35,  7,	  88,  17,  177, 202, 121, 105, 5,
	    36,	 239, 128, 90,	129, 231, 187, 188, 181, 76,  116, 42,	50,
	    219, 210, 240, 223, 19,  243, 74,  63,  42,	 154, 211, 91,	175,
	    248, 20,  15,  76,	249, 180, 39,  31,  218, 254, 143, 212, 39,
	    124, 204, 52,  218, 112, 208, 145, 129, 73,	 120, 79,  33,	177,
	    92,	 38,  159, 239, 101, 253, 32,  221, 223, 195, 27,  6,	132,
	    94,	 23,  37,  251, 199, 244, 183, 121, 239, 219, 83,  65,	71,
	    145, 51,  18,  53,	196, 192, 46,  116, 201, 184, 222, 81,	27,
	    18,	 156, 25,  148, 234, 34,  121, 195, 15,	 21,  197, 131, 58,
	    94,	 100, 254, 6,	244, 163, 134, 207, 3,	 153, 250, 77,	178,
	    33,	 221, 18,  57,	53,  236, 99,  222, 82,	 255, 133, 129, 128,
	    88,	 180, 96,  159, 86,  118, 92,  242, 55,	 204, 182, 238, 127,
	    61,	 104, 6,   1,	233, 14,  194, 52,  239, 110, 5,   103, 43,
	    47,	 241, 193, 167, 108, 82,  90,  23,  77,	 170, 225, 151, 198,
	    72,	 251, 226, 169, 98,  203, 139, 113, 146, 227, 222, 3,	20,
	    29,	 163, 202, 58,	149, 229, 41,  179, 81,	 72,  75,  54,	172,
	    240, 187, 238, 144, 88,  216, 183, 161, 94,	 76,  25,  224, 42,
	    165, 58,  159, 133, 11,  128, 8,   198, 55,	 243, 200, 198, 79,
	    189, 88,  10,  195, 3,   172, 3,   73,  29,	 159, 102, 161, 38,
	    183, 26,  48,  53,	153, 166, 198, 54,  6,	 198, 131, 216, 62,
	    4,	 45,  239, 127, 156, 220, 126, 61,  151, 159, 35,  127, 38,
	    177, 7,   182, 111, 37,  224, 255, 137, 21,	 64,  146, 50,	211,
	    246, 251, 64,  144, 90,  43,  106, 250, 19,	 95,  67,  198, 32,
	    238, 237, 32,  79,	69,  191, 220, 98,  178, 216, 107, 111, 102,
	    189, 179, 221, 132, 28,  75,  172, 169, 2,	 212, 55,  213, 89,
	    2,	 252, 18,  211, 160, 41,  193, 122, 135, 167, 149, 172, 174,
	    66,	 255, 35,  58,	88,  218, 47,  232, 240, 194, 173, 190, 121,
	    221, 51,  24,  168, 220, 143, 67,  34,  32,	 126, 188, 159, 35,
	    177, 56,  80,  54,	11,  51,  8,   91,  153, 24,  134, 64,	24,
	    128, 116, 211, 173, 246, 15,  84,  212, 247, 15,  116, 243, 249,
	    3,	 224, 12,  249, 112, 231, 96,  137, 35,	 77,  112, 248, 42,
	    127, 102, 250, 192, 142, 183, 232, 248, 83,	 177, 209, 188, 115,
	    111, 128, 250, 248, 4,   156, 231, 61,  15,	 133, 156, 30,	227,
	    78,	 247, 61,  73,	175, 58,  159, 110, 142, 223, 143, 218, 213,
	    113, 196, 33,  84,	76,  99,  37,  34,  231, 165, 241, 192, 43,
	    186, 71,  80,  70,	214, 106, 236, 232, 251, 217, 101, 220, 204,
	    95,	 249, 30,  115, 155, 254, 139, 189, 94,	 152, 52,  215, 132,
	    192, 230, 151, 26,	168, 113, 113, 207, 141, 26,  244, 69,	44,
	    138, 63,  10,  142, 115, 92,  225, 250, 101, 21,  197, 103, 86,
	    71,	 217, 12,  248, 226, 214, 107, 235, 190, 214, 146, 5,	123,
	    83,	 60,  171, 196, 160, 55,  232, 191, 238, 146, 59,  54,	206,
	    144, 238, 157, 209, 135, 23,  167, 228, 70,	 129, 54,  25,	99,
	    137, 48,  30,  49,	7,   119, 93,  6,   101, 8,   231, 48,	122,
	    53,	 194, 86,  109, 179, 171, 1,   178, 11,	 171, 53,  79,	2,
	    90,	 56,  111, 211, 90,  23,  241, 162, 109, 8,   19,  110, 128,
	    207, 113, 28,  126, 199, 74,  178, 47,  169, 18,  77,  94,	80,
	    223, 30,  212, 173, 115, 210, 191, 49,  47,	 34,  78,  172, 95,
	    231, 81,  185, 65,	29,  81,  43,  28,  192, 23,  185, 20,	160,
	    115, 46,  113, 25,	222, 56,  141, 53,  43,	 33,  185, 112, 215,
	    70,	 42,  208, 14,	236, 47,  211, 226, 58,	 206, 3,   9,	6,
	    221, 250, 98,  87,	7,   65,  10,  137, 213, 120, 50,  172, 82,
	    215, 242, 133, 84,	172, 199, 13,  151, 190, 18,  57,  228, 57,
	    12,	 194, 172, 175, 182, 59,  203, 254, 116, 112, 181, 50,	1,
	    122, 130, 56,  90,	74,  1,	  197, 15,  204, 215, 172, 171, 98,
	    215, 12,  167, 127, 40,  127, 8,   104, 57,	 98,  97,  89,	105,
	    88,	 91,  17,  93,	206, 53,  22,  233, 136, 144, 176, 74,	127,
	    158, 177, 152, 21,	251, 57,  250, 254, 88,	 237, 193, 166, 211,
	    45,	 68,  218, 41,	202, 60,  77,  99,  245, 119, 48,  19,	249,
	    211, 52,  17,  102, 50,  39,  105, 211, 73,	 176, 24,  140, 139,
	    242, 215, 20,  1,	106, 189, 19,  207, 227, 96,  137, 5,	142,
	    197, 191, 96,  232, 251, 79,  76,  213, 146, 25,  254, 197, 211,
	    130, 129, 220, 194, 121, 250, 193, 106, 212, 32,  165, 157, 229,
	    86,	 84,  37,  131, 222, 211, 255, 239, 104, 208, 156, 211, 249,
	    69,	 145, 164, 24,	248, 75,  27,  44,  90,	 4,   158, 17,	136,
	    40,	 128, 173, 174, 66,  116, 202, 33,  197, 205, 99,  188, 162,
	    4,	 135, 193, 161, 8,   237, 91,  48,  31,	 124, 129, 249, 205,
	    30,	 4,   29,  6,	198, 226, 121, 97,  80,	 89,  240, 79,	130,
	    140, 122, 2,   65,	255, 57,  237, 164, 5,	 94,  60,  139, 61,
	    238, 53,  39,  216, 56,  85,  85,  180, 63,	 62,  107, 233, 223,
	    156, 91,  93,  60,	209, 91,  224, 131, 224, 254, 44,  1,	170,
	    198, 198, 207, 127, 214, 105, 115, 81,  178, 11,  23,  231, 132,
	    140, 122, 146, 77,	136, 178, 144, 227, 246, 45,  187, 91,	108,
	    3,	 192, 155, 80,	111, 80,  231, 99,  207, 128, 161, 203, 147,
	    190, 129, 65,  152, 100, 152, 139, 131, 67,	 77,  240, 218, 158,
	    47,	 32,  145, 221, 116, 121, 128, 75,  107, 175, 233, 57,	234,
	    234, 117, 114, 251, 3,   74,  185, 42,  33,	 80,  184, 77,	146,
	    174, 116, 32,  178, 103, 152, 155, 182, 128, 191, 0,   83,	237,
	    55,	 192, 186, 185, 186, 90,  131, 12,  68,	 118, 204, 182, 50,
	    169, 138, 189, 209, 183, 125, 132, 33,  165, 140, 88,  109, 119,
	    152, 64,  1,   234, 146, 212, 214, 199, 38,	 195, 243, 26,	92,
	    161, 84,  40,  137, 229, 211, 178, 121, 30,	 213, 199, 165, 187,
	    171, 52,  139, 204, 68,  213, 7,   161, 99,	 238, 32,  45,	14,
	    200, 49,  97,  62,	217, 71,  222, 148, 169, 165, 43,  12,	27,
	    193, 159, 54,  144, 250, 201, 87,  120, 167, 162, 32,  222, 104,
	    66,	 48,  208, 155, 102, 119, 155, 222, 232, 206, 46,  127, 189,
	    124, 85,  16,  204, 36,  79,  204, 245, 59,	 2,   181, 5,	195,
	    51,	 121, 58,  169, 132, 36,  83,  75,  220, 77,  15,  108, 234,
	    12,	 199, 239, 221, 22,  35,  184, 15,  147, 219, 106, 132, 215,
	    37,	 62,  225, 222, 172, 128, 242, 166, 63,	 191, 152, 189, 176,
	    175, 78,  209, 85,	116, 66,  26,  220, 58,	 113, 20,  41,	116,
	    7,	 239, 98,  152, 231, 229, 150, 229, 22,	 27,  189, 240, 241,
	    167, 120, 24,  107, 213, 1,	  244, 207, 124, 198, 160, 117, 142,
	    47,	 16,  239, 232, 22,  61,  139, 177, 101, 39,  221, 170, 7,
	    102, 196, 30,  50,	19,  53,  35,  147, 219, 165, 145, 156, 101,
	    18,	 172, 93,  170, 153, 222, 27,  182, 149, 186, 200, 185, 32,
	    144, 182, 191, 205, 145, 7,	  111, 199, 84,	 131, 98,  95,	58,
	    145, 79,  86,  224, 88,  175, 153, 153, 225, 114, 126, 251, 71,
	    101, 7,   165, 83,	254, 84,  140, 233, 13,	 15,  85,  116, 54,
	    197, 84,  98,  176, 79,  48,  247, 184, 78,	 220, 81,  175, 126,
	    141, 223, 171, 16,	129, 220, 187, 127, 151, 8,   105, 45,	174,
	    226, 17,  158, 45,	160, 80,  250, 142, 209, 122, 88,  231, 42,
	    194, 64,  136, 39,	193, 253, 196, 181, 155, 64,  154, 200, 87,
	    83,	 67,  165, 214, 103, 20,  250, 127, 63,	 142, 203, 240, 50,
	    184, 80,  32,  57,	201, 171, 254, 111, 128, 82,  106, 237, 104,
	    77,	 72,  193, 186, 91,  77,  186, 1,   81,	 37,  4,   223, 217,
	    226, 169, 237, 213, 24,  112, 125, 113, 237, 158, 101, 112, 218,
	    147, 192, 232, 39,	41,  87,  150, 40,  4,	 192, 163, 43,	113,
	    85,	 107, 48,  14,	242, 62,  33,  199, 229, 206, 84,  219, 16,
	    84,	 226, 206, 54,	171, 72,  68,  40,  43,	 22,  4,   121, 103,
	    149, 181, 128, 148, 207, 206, 224, 56,  56,	 249, 33,  123, 149,
	    61,	 203, 211, 75,	97,  162, 45,  80,  248, 122, 122, 236, 209,
	    46,	 52,  125, 8,	76,  210, 156, 173, 220, 27,  101, 155, 14,
	    156, 109, 146, 33,	182, 247, 238, 191, 56,	 169, 57,  65,	218,
	    23,	 66,  243, 122, 57,  195, 174, 200, 133, 6,   226, 157, 192,
	    15,	 178, 190, 198, 19,  212, 42,  224, 155, 241, 15,  20,	199,
	    160, 152, 107, 154, 204, 59,  50,  139, 32,	 145, 177, 187};
	u8 expected_sig[] = {
	    50,	 99,  158, 18,	199, 171, 134, 62,  250, 101, 86,  239, 12,
	    232, 105, 143, 110, 71,  213, 174, 206, 177, 243, 138, 228, 191,
	    91,	 194, 102, 237, 81,  20,  246, 190, 51,	 52,  111, 13,	24,
	    87,	 205, 117, 138, 169, 30,  202, 79,  101, 213, 188, 75,	165,
	    66,	 189, 130, 225, 169, 163, 252, 84,  246, 143, 202, 203, 205,
	    62,	 151, 66,  9,	20,  87,  116, 105, 120, 190, 136, 121, 222,
	    145, 48,  9,   38,	99,  165, 137, 254, 232, 148, 144, 94,	174,
	    150, 153, 124, 97,	228, 194, 67,  24,  191, 223, 166, 125, 147,
	    28,	 15,  35,  69,	249, 229, 160, 53,  185, 86,  164, 4,	222,
	    204, 150, 222, 7,	217, 52,  232, 122, 132, 75,  243, 94,	131,
	    93,	 67,  19,  31,	33,  168, 32,  31,  117, 209, 148, 247, 116,
	    220, 248, 79,  96,	205, 71,  202, 152, 94,	 2,   149, 142, 215,
	    166, 16,  80,  75,	28,  82,  21,  255, 130, 103, 63,  59,	133,
	    229, 215, 157, 155, 31,  212, 178, 111, 70,	 120, 181, 152, 79,
	    16,	 9,   207, 120, 234, 48,  20,  79,  103, 193, 254, 206, 194,
	    197, 135, 166, 142, 52,  252, 244, 52,  126, 62,  46,  134, 110,
	    31,	 184, 91,  145, 11,  158, 89,  18,  26,	 98,  135, 143, 140,
	    138, 99,  79,  158, 71,  246, 167, 16,  110, 191, 2,   85,	62,
	    115, 124, 127, 101, 2,   108, 26,  77,  190, 100, 127, 149, 38,
	    57,	 103, 160, 42,	72,  223, 242, 233, 187, 43,  135, 162, 156,
	    132, 109, 236, 247, 200, 186, 203, 151, 239, 99,  37,  243, 20,
	    229, 153, 196, 177, 239, 201, 216, 41,  240, 226, 117, 79,	135,
	    255, 182, 250, 67,	45,  184, 78,  85,  72,	 71,  123, 9,	172,
	    189, 57,  151, 116, 106, 236, 211, 132, 216, 95,  45,  29,	243,
	    80,	 212, 214, 192, 236, 25,  48,  127, 200, 221, 31,  216, 158,
	    67,	 96,  179, 42,	105, 4,	  136, 113, 59,	 131, 190, 60,	117,
	    203, 130, 176, 84,	38,  166, 253, 154, 209, 238, 92,  115, 90,
	    126, 85,  214, 32,	252, 215, 140, 129, 22,	 73,  60,  107, 173,
	    40,	 209, 7,   245, 98,  33,  128, 94,  86,	 50,  171, 33,	108,
	    217, 59,  45,  206, 83,  183, 248, 39,  69,	 99,  216, 111, 2,
	    226, 7,   174, 64,	94,  255, 250, 143, 107, 40,  9,   80,	102,
	    53,	 217, 153, 224, 254, 47,  123, 114, 55,	 144, 239, 11,	117,
	    83,	 209, 214, 247, 54,  174, 148, 184, 1,	 165, 47,  13,	48,
	    247, 139, 217, 225, 124, 160, 247, 117, 253, 212, 5,   10,	77,
	    27,	 92,  24,  42,	208, 167, 185, 61,  218, 58,  4,   226, 108,
	    159, 228, 59,  105, 227, 123, 18,  15,  157, 242, 251, 71,	170,
	    250, 82,  225, 48,	47,  193, 252, 80,  51,	 177, 65,  182, 102,
	    192, 88,  62,  185, 136, 217, 52,  229, 138, 9,   249, 184, 100,
	    172, 120, 20,  187, 159, 95,  208, 224, 67,	 70,  71,  24,	191,
	    156, 79,  60,  115, 117, 206, 180, 50,  248, 110, 38,  234, 157,
	    216, 54,  157, 51,	222, 249, 81,  32,  75,	 195, 151, 32,	151,
	    141, 208, 255, 166, 105, 54,  39,  254, 57,	 61,  220, 80,	207,
	    41,	 81,  68,  107, 72,  61,  201, 129, 67,	 111, 253, 243, 145,
	    116, 120, 80,  239, 109, 158, 186, 239, 147, 101, 83,  116, 178,
	    245, 211, 122, 66,	239, 5,	  64,  160, 12,	 133, 145, 7,	236,
	    99,	 130, 91,  130, 200, 34,  225, 227, 94,	 144, 162, 197, 0,
	    163, 100, 216, 153, 91,  6,	  126, 164, 147, 120, 114, 47,	78,
	    114, 141, 176, 62,	244, 250, 124, 11,  56,	 129, 68,  19,	3,
	    86,	 139, 4,   137, 65,  127, 53,  224, 248, 170, 100, 215, 124,
	    113, 174, 188, 13,	84,  252, 254, 179, 112, 242, 7,   120, 91,
	    38,	 206, 116, 190, 164, 230, 98,  66,  206, 190, 66,  151, 124,
	    220, 64,  224, 200, 51,  114, 134, 102, 23,	 82,  123, 109, 168,
	    163, 68,  175, 65,	63,  155, 196, 150, 221, 167, 109, 131, 252,
	    246, 122, 241, 215, 113, 169, 50,  83,  34,	 22,  222, 36,	170,
	    104, 143, 2,   67,	10,  60,  112, 68,  120, 212, 115, 192, 206,
	    232, 198, 93,  123, 10,  69,  27,  80,  59,	 193, 87,  40,	66,
	    44,	 155, 45,  138, 200, 120, 188, 203, 184, 131, 71,  40,	254,
	    77,	 184, 5,   107, 89,  31,  208, 144, 180, 169, 187, 194, 150,
	    0,	 209, 35,  199, 180, 220, 143, 88,  163, 251, 43,  90,	157,
	    98,	 154, 100, 204, 4,   189, 224, 21,  142, 101, 92,  60,	73,
	    81,	 251, 114, 143, 51,  176, 228, 170, 95,	 236, 22,  35,	176,
	    4,	 47,  44,  165, 7,   114, 129, 249, 51,	 52,  236, 64,	244,
	    198, 168, 204, 135, 127, 144, 153, 89,  115, 105, 165, 69,	155,
	    155, 103, 242, 180, 15,  69,  24,  7,   82,	 94,  186, 225, 193,
	    64,	 172, 217, 115, 74,  104, 60,  247, 55,	 237, 121, 215, 144,
	    163, 186, 67,  129, 137, 195, 30,  55,  102, 195, 100, 39,	131,
	    31,	 57,  248, 7,	241, 84,  104, 26,  42,	 207, 189, 43,	171,
	    27,	 26,  142, 72,	34,  16,  135, 90,  225, 4,   192, 29,	61,
	    172, 73,  76,  41,	179, 17,  238, 152, 84,	 247, 76,  151, 33,
	    27,	 64,  149, 32,	161, 129, 216, 113, 35,	 178, 10,  134, 125,
	    15,	 62,  169, 55,	69,  178, 225, 208, 34,	 48,  14,  107, 93,
	    202, 18,  137, 50,	54,  120, 8,   221, 238, 171, 230, 89,	144,
	    177, 160, 248, 44,	252, 113, 153, 113, 226, 122, 71,  29,	100,
	    16,	 244, 55,  197, 53,  145, 167, 63,  53,	 184, 52,  38,	199,
	    31,	 170, 248, 218, 80,  250, 51,  8,   74,	 197, 243, 57,	193,
	    190, 144, 165, 190, 79,  163, 187, 17,  28,	 115, 172, 57,	242,
	    188, 252, 49,  91,	180, 110, 228, 2,   110, 8,   143, 26,	105,
	    91,	 49,  160, 237, 247, 176, 221, 167, 35,	 57,  146, 195, 150,
	    170, 182, 81,  204, 8,   113, 201, 175, 163, 66,  213, 174, 151,
	    201, 44,  179, 52,	32,  37,  48,  105, 108, 130, 25,  22,	150,
	    251, 92,  121, 45,	5,   246, 37,  165, 203, 81,  82,  166, 98,
	    82,	 82,  114, 113, 212, 100, 79,  21,  11,	 226, 204, 4,	38,
	    21,	 141, 246, 220, 8,   213, 169, 168, 196, 40,  101, 85,	205,
	    158, 220, 235, 37,	32,  45,  110, 33,  203, 105, 206, 28,	143,
	    223, 172, 200, 117, 44,  196, 172, 177, 175, 254, 208, 5,	75,
	    101, 208, 163, 71,	201, 24,  163, 202, 141, 92,  83,  46,	150,
	    186, 53,  15,  187, 197, 100, 96,  55,  99,	 49,  72,  130, 104,
	    37,	 156, 161, 128, 117, 81,  194, 32,  194, 197, 86,  109, 62,
	    45,	 169, 56,  125, 43,  79,  200, 214, 149, 88,  172, 228, 37,
	    229, 248, 142, 61,	205, 113, 78,  48,  149, 142, 130, 63,	159,
	    106, 161, 222, 232, 226, 61,  119, 186, 104, 210, 189, 40,	195,
	    177, 215, 163, 168, 69,  94,  20,  39,  116, 4,   99,  2,	244,
	    197, 212, 187, 140, 218, 20,  37,  22,  175, 120, 208, 23,	58,
	    107, 135, 186, 208, 41,  143, 211, 187, 155, 166, 244, 4,	95,
	    8,	 80,  65,  149, 200, 129, 90,  72,  144, 155, 224, 16,	27,
	    224, 28,  48,  187, 145, 114, 147, 115, 237, 78,  197, 111, 172,
	    205, 24,  123, 234, 74,  93,  233, 223, 141, 141, 226, 191, 119,
	    182, 31,  125, 235, 239, 150, 106, 131, 157, 201, 14,  160, 13,
	    176, 97,  145, 232, 153, 249, 218, 90,  233, 135, 36,  198, 52,
	    113, 39,  114, 76,	176, 3,	  219, 17,  102, 49,  190, 254, 17,
	    238, 67,  210, 165, 216, 95,  123, 42,  63,	 79,  82,  70,	248,
	    106, 49,  11,  209, 54,  93,  199, 242, 205, 170, 202, 70,	61,
	    49,	 15,  9,   220, 134, 251, 233, 201, 168, 97,  238, 132, 41,
	    243, 254, 10,  127, 209, 235, 229, 145, 116, 40,  239, 85,	183,
	    184, 162, 95,  75,	174, 40,  16,  116, 174, 89,  131, 198, 40,
	    136, 157, 184, 19,	205, 187, 43,  37,  81,	 238, 164, 163, 116,
	    48,	 27,  129, 154, 29,  132, 238, 137, 148, 151, 104, 52,	113,
	    203, 33,  178, 117, 100, 125, 184, 252, 37,	 199, 105, 35,	67,
	    228, 239, 105, 103, 134, 93,  94,  30,  59,	 193, 120, 90,	14,
	    223, 179, 197, 178, 193, 94,  64,  71,  241, 53,  33,  119, 195,
	    164, 33,  73,  213, 6,   108, 21,  229, 65,	 220, 161, 1,	38,
	    86,	 193, 63,  88,	80,  198, 143, 171, 99,	 182, 103, 128, 197,
	    2,	 204, 184, 22,	163, 72,  66,  139, 181, 194, 213, 2,	94,
	    190, 175, 225, 13,	169, 125, 64,  38,  126, 65,  189, 133, 209,
	    83,	 0,   135, 96,	91,  1,	  4,   245, 125, 77,  152, 174, 104,
	    126, 1,   249, 165, 214, 175, 154, 117, 74,	 96,  13,  20,	226,
	    1,	 99,  13,  206, 53,  20,  5,   151, 94,	 228, 77,  15,	116,
	    79,	 251, 129, 202, 253, 14,  75,  203, 163, 73,  150, 180, 227,
	    146, 230, 100, 175, 15,  181, 30,  225, 190, 92,  184, 139, 195,
	    82,	 131, 107, 126, 143, 95,  83,  109, 196, 221, 121, 208, 126,
	    214, 188, 207, 47,	241, 130, 86,  129, 132, 48,  50,  77,	12,
	    32,	 207, 211, 105, 15,  72,  204, 12,  91,	 58,  65,  182, 105,
	    152, 145, 66,  57,	166, 122, 110, 112, 161, 105, 194, 103, 61,
	    11,	 152, 176, 222, 154, 78,  65,  88,  64,	 23,  102, 193, 161,
	    38,	 172, 154, 129, 131, 76,  73,  220, 54,	 62,  248, 127, 36,
	    210, 20,  206, 86,	144, 101, 144, 81,  249, 130, 136, 47,	208,
	    22,	 89,  196, 2,	220, 250, 76,  202, 3,	 163, 183, 106, 123,
	    235, 187, 33,  185, 197, 78,  198, 38,  166, 231, 42,  163, 174,
	    182, 40,  248, 243, 72,  85,  142, 68,  237, 220, 217, 227, 31,
	    86,	 73,  84,  113, 225, 221, 47,  6,   225, 219, 223, 0,	14,
	    74,	 224, 69,  51,	101, 111, 191, 90,  51,	 50,  110, 255, 249,
	    92,	 45,  173, 19,	164, 161, 143, 175, 190, 176, 220, 53,	29,
	    37,	 231, 5,   144, 17,  46,  79,  95,  17,	 33,  146, 119, 8,
	    23,	 175, 142, 83,	248, 148, 119, 90,  35,	 68,  138, 33,	133,
	    167, 124, 153, 56,	29,  252, 180, 41,  119, 61,  227, 239, 156,
	    8,	 248, 239, 24,	175, 221, 162, 66,  133, 116, 133, 9,	92,
	    131, 171, 21,  160, 110, 243, 104, 129, 45,	 182, 55,  94,	25,
	    25,	 228, 110, 215, 246, 68,  74,  164, 207, 106, 18,  212, 151,
	    3,	 24,  42,  50,	37,  198, 155, 92,  255, 212, 215, 236, 198,
	    173, 32,  9,   244, 81,  174, 172, 13,  105, 247, 9,   150, 191,
	    214, 207, 161, 108, 250, 26,  103, 234, 168, 181, 70,  136, 206,
	    194, 125, 116, 141, 172, 23,  47,  30,  168, 169, 79,  40,	211,
	    48,	 203, 42,  56,	133, 234, 172, 9,   170, 126, 130, 144, 219,
	    184, 147, 193, 68,	210, 218, 235, 204, 82,	 237, 221, 215, 173,
	    169, 248, 26,  163, 122, 38,  9,   191, 82,	 0,   82,  83,	9,
	    223, 141, 147, 157, 12,  191, 21,  153, 78,	 188, 186, 210, 164,
	    66,	 13,  17,  236, 223, 101, 195, 76,  159, 162, 189, 157, 235,
	    95,	 22,  181, 52,	88,  52,  66,  223, 53,	 235, 39,  211, 190,
	    129, 163, 41,  224, 7,   234, 64,  175, 203, 253, 7,   53,	169,
	    230, 40,  70,  116, 249, 150, 148, 242, 248, 38,  158, 61,	185,
	    122, 71,  12,  114, 249, 170, 95,  231, 114, 192, 118, 150, 141,
	    188, 155, 55,  20,	197, 111, 139, 38,  247, 56,  92,  253, 135,
	    1,	 123, 138, 115, 142, 55,  226, 204, 99,	 79,  235, 61,	250,
	    6,	 177, 75,  127, 181, 181, 118, 116, 57,	 121, 92,  14,	226,
	    159, 84,  132, 245, 134, 43,  176, 224, 245, 40,  70,  174, 249,
	    111, 68,  213, 207, 153, 115, 66,  148, 208, 81,  105, 186, 172,
	    52,	 48,  89,  17,	209, 78,  248, 230, 120, 1,   213, 81,	6,
	    141, 0,   124, 171, 231, 114, 131, 215, 137, 255, 84,  195, 119,
	    202, 160, 253, 189, 169, 55,  171, 222, 227, 1,   36,  16,	238,
	    251, 92,  207, 127, 84,  219, 111, 193, 76,	 247, 6,   243, 205,
	    146, 188, 6,   164, 127, 168, 44,  45,  106, 190, 196, 160, 72,
	    165, 42,  32,  244, 98,  13,  176, 254, 188, 31,  253, 193, 241,
	    122, 254, 159, 62,	85,  66,  156, 23,  30,	 172, 146, 194, 205,
	    61,	 171, 248, 82,	211, 140, 77,  85,  114, 174, 172, 82,	159,
	    105, 182, 24,  101, 123, 126, 88,  240, 190, 180, 253, 116, 152,
	    5,	 190, 243, 165, 176, 242, 167, 188, 145, 53,  16,  146, 243,
	    156, 107, 175, 55,	245, 7,	  137, 234, 180, 34,  13,  5,	49,
	    210, 111, 10,  228, 61,  84,  118, 9,   39,	 231, 169, 144, 120,
	    131, 216, 35,  177, 120, 7,	  249, 72,  55,	 165, 42,  135, 209,
	    82,	 91,  164, 160, 68,  250, 47,  10,  212, 15,  174, 71,	224,
	    71,	 228, 67,  99,	106, 134, 214, 165, 34,	 6,   109, 232, 147,
	    205, 153, 34,  201, 38,  18,  194, 38,  234, 183, 40,  149, 201,
	    171, 125, 201, 143, 91,  75,  4,   52,  132, 199, 95,  49,	130,
	    95,	 168, 21,  233, 108, 188, 99,  128, 239, 99,  89,  40,	117,
	    202, 60,  137, 162, 186, 199, 224, 173, 253, 76,  220, 225, 94,
	    236, 148, 124, 175, 68,  178, 223, 1,   91,	 99,  81,  43,	49,
	    85,	 91,  124, 89,	152, 75,  77,  251, 206, 70,  73,  189, 10,
	    66,	 44,  111, 175, 127, 243, 129, 33,  248, 249, 189, 47,	118,
	    139, 7,   180, 245, 239, 176, 69,  64,  221, 216, 31,  122, 227,
	    220, 41,  114, 0,	236, 82,  23,  62,  166, 10,  38,  45,	55,
	    94,	 119, 123, 126, 127, 129, 132, 156, 179, 184, 185, 189, 197,
	    206, 216, 219, 231, 232, 246, 4,   29,  51,	 90,  91,  98,	109,
	    121, 132, 149, 243, 244, 252, 14,  19,  20,	 70,  84,  88,	100,
	    106, 114, 168, 195, 227, 240, 241, 254, 13,	 21,  59,  118, 131,
	    139, 168, 188, 220, 231, 243, 246, 252, 0,	 0,   0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   23,	36,
	    51,	 64,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
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

