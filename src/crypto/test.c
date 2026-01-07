/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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
#include <libfam/storm_vectors.h>
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

extern u64 STORM_NUMS[20];

Test(verify_nums) {
	u64 v[] = {0x2d358dccaa6c78a5, 0x8bb84b93962eacc9, 0x4b33a62ed433d4a3,
		   0x4d5a2da51de1aa47};
	u64 vext[20];
	fastmemcpy(vext, v, sizeof(v));
	u64 state = v[0] ^ v[1] ^ v[2] ^ v[3];
	for (u32 i = 4; i < 20; i++) {
		vext[i] = state;
		state ^= vext[i - 1] * vext[i - 2];
	}
	for (u32 i = 0; i < 20; i++)
		ASSERT_EQ(STORM_NUMS[i], vext[i], "storm nums");
}

Test(storm_vectors) {
	StormContext ctx;
	for (u32 i = 0; i < sizeof(storm_vectors) / sizeof(storm_vectors[0]);
	     i++) {
		storm_init(&ctx, storm_vectors[i].key);
		for (u32 j = 0; j < sizeof(storm_vectors[i].input) /
					sizeof(storm_vectors[i].input[0]);
		     j++) {
			__attribute__((aligned(32))) u8 tmp[32];
			fastmemcpy(tmp, storm_vectors[i].input[j], 32);
			storm_next_block(&ctx, tmp);
			i32 res = memcmp(tmp, storm_vectors[i].expected[j], 32);
			if (res) {
				pwrite(2, "i=", 2, 0);
				write_num(2, i);
				pwrite(2, ",j=", 3, 0);
				write_num(2, j);
				pwrite(2, "\n", 1, 0);
			}
			ASSERT(!res, "vector");
		}
	}
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

	u8 expected1[32] = {71,	 133, 192, 11,	194, 23,  27,  203,
			    173, 163, 182, 59,	31,  226, 177, 116,
			    41,	 37,  219, 150, 175, 113, 190, 203,
			    53,	 124, 138, 254, 177, 111, 150, 212};

	ASSERT(!memcmp(buffer1, expected1, 32), "expected1");
	u8 expected2[32] = {122, 32,  132, 154, 196, 43,  248, 248,
			    88,	 71,  69,  196, 204, 27,  199, 135,
			    145, 59,  148, 51,	239, 220, 75,  82,
			    111, 186, 138, 31,	242, 105, 162, 235};

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
	    129, 70,  31,  219, 220, 182, 37,  117, 150, 255, 230, 81,	51,
	    150, 154, 197, 59,	81,  226, 159, 151, 74,	 159, 253, 239, 120,
	    28,	 108, 132, 195, 190, 175, 36,  235, 239, 201, 63,  55,	175,
	    172, 47,  28,  89,	241, 175, 127, 4,   86,	 30,  251, 182, 32,
	    211, 60,  62,  192, 232, 15,  165, 39,  153, 225, 119, 227};
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

Bench(storm_perf) {
#define STORM_COUNT (10000000000 / 32)
	static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};
	static __attribute__((aligned(32))) u8 ONE_SEED[32] = {1};
	static __attribute__((aligned(32))) u8 TWO_SEED[32] = {2};
	static __attribute__((aligned(32))) u8 THREE_SEED[32] = {3};
	static __attribute__((aligned(32))) u8 FOUR_SEED[32] = {4};
	static __attribute__((aligned(32))) u8 FIVE_SEED[32] = {5};

	i64 timer;
	__attribute__((aligned(32))) u8 buf1[64] = {11};
	__attribute__((aligned(32))) u8 buf2[64] = {23};
	__attribute__((aligned(32))) u8 buf3[64] = {56};
	__attribute__((aligned(32))) u8 buf4[64] = {67};
	__attribute__((aligned(32))) u8 buf5[64] = {78};
	__attribute__((aligned(32))) u8 buf6[64] = {99};

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
	write_num(2, (timer * 1000 * 1000) / (STORM_COUNT * 6));
	pwrite(2, "ps\n", 3, 0);
}

Bench(storm_preimage) {
	StormContext ctx1;
	StormContext ctx2;
	Rng rng;
	__attribute__((aligned(32))) u8 input[32] = {0};
	__attribute__((aligned(32))) u8 flipped[32] = {0};
	static const __attribute__((aligned(32))) u8 ZERO[32] = {0};
	u32 max_dist = 0;
	u32 hamm_sum, hamm_dist;
	u32 trials = 1 << 28;

	rng_init(&rng);
	for (u32 i = 0; i < trials; i++) {
		rng_gen(&rng, input, 32);
		u64 byte_pos = i % 32;
		u8 bit_pos = input[0] % 8;
		fastmemcpy(flipped, input, 32);
		flipped[byte_pos] ^= (1 << bit_pos);

		storm_init(&ctx1, ZERO);
		storm_init(&ctx2, ZERO);
		storm_next_block(&ctx1, input);
		storm_next_block(&ctx2, flipped);
		hamm_sum = 0;

		for (u32 i = 0; i < 32; i++) {
			u32 hamm = input[i] ^ flipped[i];
			hamm_sum += __builtin_popcountll(hamm);
		}
		hamm_dist = hamm_sum > 128 ? hamm_sum - 128 : 128 - hamm_sum;
		if (hamm_dist > max_dist) max_dist = hamm_dist;
	}

	ASSERT(max_dist > 40, "max_dist > 40");
	ASSERT(max_dist < 60, "max_dist < 60");
	pwrite(2, "trials=", 7, 0);
	write_num(2, trials);
	pwrite(2, ",max_distance=", 14, 0);
	write_num(2, max_dist);
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

Test(aighthash_vector) {
	u8 vector[1024] = {0};
	u64 r;
	for (u32 i = 0; i < 1024; i++) vector[i] = i % 256;
	r = aighthash64(vector, 1024, 0);
	ASSERT_EQ(r, 17797804553278143541ULL, "vector1");
	r = aighthash64(vector, 1024, 1);
	ASSERT_EQ(r, 10881699377260999209ULL, "vector2");
}

#define COUNT (1024ULL * 1024ULL)
#define SIZE 8192ULL

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
	pwrite(2, "cycles_per_byte=", 16, 0);
	f64 cycle_per_byte = (f64)cycle_sum / (COUNT * SIZE);
	u8 cpb[MAX_F64_STRING_LEN] = {0};
	f64_to_string(cpb, cycle_per_byte, 8, false);
	pwrite(2, cpb, strlen(cpb), 0);
	pwrite(2, ",sum=", 5, 0);
	write_num(2, sum);
	pwrite(2, "\n", 1, 0);
}

Bench(aighthash_bitflips) {
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
		b = bible_gen(true);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_sbox8_64(sbox);
	bible_hash(b, input, output, sbox);

	u8 expected[32] = {65, 229, 114, 172, 92,  145, 119, 123, 197, 180, 165,
			   88, 178, 42,	 104, 69,  194, 222, 84,  105, 136, 8,
			   80, 225, 180, 104, 222, 54,	137, 45,  62,  205};

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

	ASSERT_EQ(nonce, 45890, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	178, 28,  75,  191, 58,	 214,
				      17,  30,	146, 59,  42,  211, 72,	 59,
				      10,  5,	143, 171, 234, 121, 165, 205,
				      143, 221, 59,  50,  245, 97,  236, 73},
		       32),
	       "hash");
	bible_destroy(b);
}

Test(bible_dat) {
	__attribute__((aligned(32))) static const u8 BIBLE_GEN_DOMAIN[32] = {
	    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0x85, 0xeb,
	    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x35, 0x51, 0x7c, 0xc1, 0xb7,
	    0x27, 0x22, 0x0a, 0x95, 0x07, 0x00, 0x00, 0x01};
	StormContext ctx;
	const Bible* b;
	u8 bible[BIBLE_UNCOMPRESSED_SIZE];

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(true);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_expand(b, bible);

	storm_init(&ctx, BIBLE_GEN_DOMAIN);
	__attribute__((aligned(32))) u8 buffer[32];
	u64 off = 0;
	while (off < (BIBLE_UNCOMPRESSED_SIZE & ~31U)) {
		fastmemcpy(buffer, bible + off, 32);
		storm_next_block(&ctx, buffer);
		off += 32;
	}

	const u8* check =
	    "Genesis||1||1||In the beginning God created the heaven and the "
	    "earth.";

	ASSERT(!memcmp(bible, check, strlen(check)), "first verse");
	ASSERT(!memcmp(buffer, (u8[]){40,  57,	160, 40,  170, 236, 126, 115,
				      174, 135, 8,   248, 200, 93,  24,	 249,
				      138, 33,	80,  188, 155, 201, 175, 93,
				      32,  107, 130, 188, 4,   167, 155, 219},
		       32),
	       "hash");

	bible_destroy(b);
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
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ",
	// sk.data[i]);
	u8 expected_sk[] = {
	    2,	 151, 8,   158, 32,  171, 128, 7,   166, 188, 84,  133, 115,
	    182, 80,  79,  23,	34,  136, 112, 199, 169, 113, 150, 33,	128,
	    109, 235, 138, 186, 189, 176, 140, 247, 168, 107, 139, 135, 180,
	    224, 11,  141, 24,	178, 23,  234, 80,  33,	 148, 49,  23,	235,
	    209, 180, 224, 137, 90,  133, 75,  28,  56,	 137, 33,  244, 27,
	    155, 146, 123, 99,	237, 245, 117, 179, 97,	 180, 125, 87,	202,
	    28,	 240, 17,  41,	19,  34,  253, 70,  9,	 193, 64,  1,	92,
	    216, 35,  178, 66,	130, 126, 105, 26,  184, 204, 54,  123, 32,
	    153, 23,  135, 106, 113, 171, 42,  41,  96,	 82,  132, 155, 178,
	    22,	 229, 167, 5,	245, 46,  76,  20,  68,	 246, 39,  166, 202,
	    166, 32,  139, 119, 40,  219, 98,  106, 106, 71,  7,   247, 87,
	    89,	 131, 104, 170, 123, 69,  147, 59,  1,	 149, 230, 181, 33,
	    32,	 150, 62,  239, 199, 53,  183, 34,  180, 44,  81,  183, 130,
	    76,	 106, 59,  216, 138, 224, 129, 90,  246, 232, 143, 33,	144,
	    65,	 4,   129, 4,	195, 107, 205, 210, 72,	 185, 151, 148, 73,
	    23,	 168, 162, 223, 76,  196, 156, 41,  12,	 87,  153, 157, 132,
	    195, 159, 255, 44,	93,  251, 241, 36,  186, 245, 117, 34,	9,
	    118, 42,  1,   206, 197, 219, 148, 194, 38,	 160, 15,  208, 14,
	    99,	 5,   121, 66,	251, 31,  142, 54,  135, 8,   17,  152, 128,
	    153, 128, 212, 98,	40,  230, 36,  120, 158, 140, 81,  183, 235,
	    82,	 230, 57,  71,	195, 213, 46,  142, 230, 90,  195, 164, 137,
	    95,	 182, 38,  19,	2,   56,  62,  82,  185, 28,  152, 168, 144,
	    220, 187, 104, 112, 91,  134, 72,  23,  64,	 200, 1,   37,	4,
	    109, 133, 124, 39,	166, 106, 3,   135, 187, 101, 114, 149, 172,
	    200, 213, 63,  15,	188, 189, 71,  160, 182, 87,  124, 189, 172,
	    9,	 192, 14,  22,	98,  224, 153, 179, 153, 171, 204, 222, 187,
	    40,	 112, 65,  146, 102, 7,	  108, 39,  186, 101, 107, 64,	117,
	    158, 68,  184, 254, 8,   21,  117, 165, 188, 219, 9,   60,	244,
	    249, 43,  168, 128, 1,   175, 164, 81,  179, 7,   143, 41,	197,
	    82,	 181, 151, 110, 91,  155, 4,   1,   82,	 169, 118, 96,	10,
	    89,	 52,  28,  65,	70,  148, 233, 124, 114, 153, 147, 187, 122,
	    147, 78,  34,  251, 202, 92,  200, 153, 22,	 212, 145, 147, 201,
	    194, 20,  245, 0,	249, 43,  155, 132, 198, 57,  11,  57,	188,
	    231, 17,  11,  25,	41,  20,  77,  64,  36,	 112, 102, 182, 177,
	    24,	 56,  28,  213, 59,  157, 220, 51,  104, 21,  171, 201, 43,
	    7,	 84,  88,  2,	45,  4,	  146, 44,  188, 84,  25,  38,	141,
	    175, 108, 141, 144, 120, 28,  110, 140, 93,	 190, 102, 12,	164,
	    192, 185, 210, 65,	72,  198, 2,   206, 58,	 228, 135, 87,	17,
	    101, 20,  140, 184, 240, 24,  86,  1,   0,	 16,  204, 214, 14,
	    111, 130, 87,  142, 160, 87,  67,  39,  182, 201, 234, 17,	139,
	    230, 132, 161, 232, 52,  45,  72,  185, 165, 101, 54,  183, 180,
	    171, 205, 18,  166, 32,  167, 14,  241, 128, 123, 178, 200, 95,
	    142, 10,  68,  149, 43,  111, 255, 43,  185, 87,  251, 186, 49,
	    65,	 181, 84,  40,	120, 139, 99,  1,   148, 42,  143, 148, 249,
	    137, 235, 21,  113, 214, 70,  177, 221, 52,	 109, 80,  9,	43,
	    23,	 209, 148, 47,	192, 191, 251, 249, 176, 219, 115, 77,	176,
	    76,	 94,  28,  90,	37,  140, 107, 10,  223, 213, 25,  62,	171,
	    134, 120, 204, 6,	60,  203, 14,  74,  195, 57,  186, 188, 140,
	    132, 227, 201, 186, 28,  94,  88,  134, 121, 200, 247, 97,	170,
	    27,	 156, 121, 165, 25,  9,	  42,  40,  227, 195, 165, 155, 160,
	    152, 156, 217, 93,	84,  108, 174, 124, 233, 83,  212, 129, 91,
	    46,	 196, 191, 9,	42,  96,  40,  85,  44,	 70,  19,  57,	25,
	    215, 12,  199, 168, 45,  3,	  56,  172, 226, 64,  122, 243, 56,
	    149, 18,  83,  199, 87,  208, 161, 137, 180, 16,  86,  236, 55,
	    10,	 166, 81,  185, 234, 79,  16,  9,   87,	 164, 139, 58,	78,
	    195, 134, 253, 1,	100, 128, 56,  126, 123, 86,  92,  239, 10,
	    98,	 5,   168, 10,	136, 241, 136, 249, 168, 27,  173, 92,	14,
	    82,	 246, 149, 30,	24,  187, 75,  215, 140, 78,  37,  155, 247,
	    0,	 164, 229, 233, 144, 161, 51,  176, 72,	 151, 6,   253, 246,
	    160, 93,  248, 65,	234, 42,  93,  207, 133, 182, 91,  149, 103,
	    239, 146, 192, 29,	209, 72,  105, 85,  59,	 97,  194, 160, 154,
	    251, 59,  184, 86,	186, 23,  65,  69,  132, 182, 34,  158, 246,
	    147, 122, 51,  96,	104, 44,  71,  78,  245, 48,  26,  137, 168,
	    46,	 5,   39,  70,	4,   135, 250, 210, 72,	 192, 104, 176, 188,
	    90,	 58,  249, 21,	152, 0,	  66,  159, 103, 118, 69,  129, 32,
	    96,	 234, 6,   204, 6,   179, 9,   80,  80,	 179, 108, 236, 9,
	    205, 36,  178, 236, 185, 173, 154, 123, 40,	 164, 1,   166, 39,
	    251, 118, 42,  124, 182, 233, 67,  22,  0,	 240, 132, 31,	214,
	    203, 35,  178, 59,	32,  233, 11,  247, 217, 103, 74,  16,	84,
	    147, 112, 114, 201, 82,  39,  120, 149, 204, 227, 252, 46,	64,
	    226, 6,   140, 90,	167, 235, 202, 70,  165, 164, 96,  249, 249,
	    90,	 130, 150, 126, 80,  4,	  65,  129, 149, 136, 107, 135, 54,
	    228, 235, 123, 46,	235, 33,  98,  84,  130, 165, 48,  127, 35,
	    171, 61,  128, 198, 115, 59,  185, 180, 167, 83,  163, 47,	163,
	    66,	 207, 170, 130, 46,  220, 80,  73,  60,	 113, 201, 228, 145,
	    122, 122, 79,  139, 247, 68,  159, 66,  122, 244, 34,  76,	199,
	    193, 205, 149, 92,	23,  225, 234, 180, 63,	 59,  170, 68,	210,
	    188, 63,  17,  92,	81,  89,  49,  211, 184, 55,  254, 181, 13,
	    87,	 66,  65,  56,	137, 163, 30,  197, 58,	 222, 9,   102, 253,
	    43,	 195, 110, 236, 49,  66,  1,   38,  110, 26,  147, 40,	66,
	    89,	 67,  197, 66,	200, 231, 101, 162, 121, 110, 219, 37,	72,
	    98,	 52,  194, 134, 36,  136, 25,  226, 102, 151, 170, 206, 144,
	    73,	 152, 85,  0,	85,  96,  112, 109, 83,	 16,  31,  111, 169,
	    12,	 249, 73,  109, 160, 156, 157, 12,  60,	 143, 124, 166, 78,
	    51,	 73,  147, 145, 67,  28,  253, 234, 102, 160, 118, 43,	226,
	    155, 71,  169, 147, 93,  58,  28,  46,  74,	 146, 148, 168, 25,
	    49,	 116, 64,  122, 8,   219, 133, 211, 5,	 84,  228, 60,	9,
	    78,	 169, 180, 246, 219, 16,  70,  176, 128, 132, 236, 50,	119,
	    51,	 79,  48,  88,	42,  155, 148, 180, 79,	 65,  79,  152, 75,
	    36,	 61,  250, 107, 196, 144, 132, 135, 172, 62,  27,  148, 163,
	    142, 107, 197, 244, 162, 28,  134, 66,  189, 150, 124, 24,	32,
	    121, 16,  141, 10,	88,  175, 161, 4,   188, 105, 175, 80,	252,
	    26,	 88,  17,  151, 248, 6,	  167, 81,  36,	 107, 19,  106, 198,
	    99,	 243, 142, 237, 193, 57,  9,   197, 83,	 6,   65,  183, 207,
	    150, 30,  79,  44,	135, 101, 218, 31,  175, 156, 202, 74,	188,
	    106, 88,  170, 60,	148, 177, 180, 24,  225, 75,  138, 241, 96,
	    10,	 230, 66,  221, 232, 101, 127, 249, 8,	 97,  124, 48,	189,
	    228, 177, 111, 102, 31,  184, 129, 165, 249, 176, 53,  207, 211,
	    33,	 26,  216, 70,	184, 8,	  162, 22,  168, 31,  251, 195, 64,
	    193, 82,  169, 135, 151, 106, 110, 57,  1,	 214, 48,  33,	188,
	    87,	 126, 170, 72,	1,   163, 73,  82,  179, 171, 177, 98,	246,
	    61,	 160, 151, 66,	102, 60,  166, 149, 184, 131, 145, 198, 78,
	    169, 146, 81,  187, 85,  23,  167, 43,  3,	 211, 230, 164, 136,
	    193, 38,  72,  209, 183, 96,  249, 130, 60,	 122, 65,  158, 116,
	    114, 198, 66,  24,	39,  152, 34,  132, 25,	 164, 130, 218, 122,
	    176, 22,  3,   57,	176, 61,  29,  163, 136, 129, 188, 41,	30,
	    10,	 156, 51,  12,	179, 239, 193, 8,   104, 244, 12,  142, 44,
	    82,	 235, 193, 191, 213, 171, 180, 254, 9,	 89,  39,  117, 85,
	    95,	 213, 103, 40,	101, 97,  159, 33,  162, 107, 248, 119, 15,
	    240, 56,  67,  250, 122, 157, 192, 172, 147, 106, 97,  167, 150,
	    33,	 128, 128, 5,	225, 179, 152, 243, 40,	 89,  114, 168, 97,
	    111, 240, 65,  201, 147, 89,  216, 76,  146, 68,  128, 54,	19,
	    217, 25,  235, 181, 70,  52,  67,  68,  136, 241, 107, 110, 26,
	    39,	 248, 154, 34,	20,  151, 150, 249, 151, 181, 28,  178, 147,
	    126, 59,  192, 68,	106, 187, 106, 186, 185, 107, 227, 145, 169,
	    129, 47,  135, 233, 120, 38,  152, 194, 128, 121, 134, 211, 145,
	    73,	 213, 213, 131, 34,  68,  69,  62,  6,	 111, 70,  54,	115,
	    107, 230, 149, 243, 16,  43,  148, 145, 125, 43,  68,  159, 248,
	    128, 149, 213, 242, 46,  5,	  115, 31,  158, 5,   115, 215, 240,
	    11,	 139, 87,  58,	71,  235, 34,  53,  16,	 44,  173, 23,	234,
	    87,	 33,  64,  115, 236, 169, 232, 29,  40,	 90,  247, 189, 138,
	    142, 95,  54,  219, 139, 58,  236, 44,  98,	 69,  14,  230, 138,
	    81,	 9,   36,  109, 234, 149, 30,  252, 126, 165, 124, 236, 128,
	    168, 97,  35,  131, 115, 225, 144, 237, 245, 140, 231, 225, 153,
	    244, 164, 71,  233, 43,  196, 221, 158, 57,	 66,  94,  151, 239,
	    119, 174, 209, 104, 202, 225, 134};
	u8 expected_pk[] = {
	    93,	 248, 65,  234, 42,  93,  207, 133, 182, 91,  149, 103, 239,
	    146, 192, 29,  209, 72,  105, 85,  59,  97,	 194, 160, 154, 251,
	    59,	 184, 86,  186, 23,  65,  69,  132, 182, 34,  158, 246, 147,
	    122, 51,  96,  104, 44,  71,  78,  245, 48,	 26,  137, 168, 46,
	    5,	 39,  70,  4,	135, 250, 210, 72,  192, 104, 176, 188, 90,
	    58,	 249, 21,  152, 0,   66,  159, 103, 118, 69,  129, 32,	96,
	    234, 6,   204, 6,	179, 9,	  80,  80,  179, 108, 236, 9,	205,
	    36,	 178, 236, 185, 173, 154, 123, 40,  164, 1,   166, 39,	251,
	    118, 42,  124, 182, 233, 67,  22,  0,   240, 132, 31,  214, 203,
	    35,	 178, 59,  32,	233, 11,  247, 217, 103, 74,  16,  84,	147,
	    112, 114, 201, 82,	39,  120, 149, 204, 227, 252, 46,  64,	226,
	    6,	 140, 90,  167, 235, 202, 70,  165, 164, 96,  249, 249, 90,
	    130, 150, 126, 80,	4,   65,  129, 149, 136, 107, 135, 54,	228,
	    235, 123, 46,  235, 33,  98,  84,  130, 165, 48,  127, 35,	171,
	    61,	 128, 198, 115, 59,  185, 180, 167, 83,	 163, 47,  163, 66,
	    207, 170, 130, 46,	220, 80,  73,  60,  113, 201, 228, 145, 122,
	    122, 79,  139, 247, 68,  159, 66,  122, 244, 34,  76,  199, 193,
	    205, 149, 92,  23,	225, 234, 180, 63,  59,	 170, 68,  210, 188,
	    63,	 17,  92,  81,	89,  49,  211, 184, 55,	 254, 181, 13,	87,
	    66,	 65,  56,  137, 163, 30,  197, 58,  222, 9,   102, 253, 43,
	    195, 110, 236, 49,	66,  1,	  38,  110, 26,	 147, 40,  66,	89,
	    67,	 197, 66,  200, 231, 101, 162, 121, 110, 219, 37,  72,	98,
	    52,	 194, 134, 36,	136, 25,  226, 102, 151, 170, 206, 144, 73,
	    152, 85,  0,   85,	96,  112, 109, 83,  16,	 31,  111, 169, 12,
	    249, 73,  109, 160, 156, 157, 12,  60,  143, 124, 166, 78,	51,
	    73,	 147, 145, 67,	28,  253, 234, 102, 160, 118, 43,  226, 155,
	    71,	 169, 147, 93,	58,  28,  46,  74,  146, 148, 168, 25,	49,
	    116, 64,  122, 8,	219, 133, 211, 5,   84,	 228, 60,  9,	78,
	    169, 180, 246, 219, 16,  70,  176, 128, 132, 236, 50,  119, 51,
	    79,	 48,  88,  42,	155, 148, 180, 79,  65,	 79,  152, 75,	36,
	    61,	 250, 107, 196, 144, 132, 135, 172, 62,	 27,  148, 163, 142,
	    107, 197, 244, 162, 28,  134, 66,  189, 150, 124, 24,  32,	121,
	    16,	 141, 10,  88,	175, 161, 4,   188, 105, 175, 80,  252, 26,
	    88,	 17,  151, 248, 6,   167, 81,  36,  107, 19,  106, 198, 99,
	    243, 142, 237, 193, 57,  9,	  197, 83,  6,	 65,  183, 207, 150,
	    30,	 79,  44,  135, 101, 218, 31,  175, 156, 202, 74,  188, 106,
	    88,	 170, 60,  148, 177, 180, 24,  225, 75,	 138, 241, 96,	10,
	    230, 66,  221, 232, 101, 127, 249, 8,   97,	 124, 48,  189, 228,
	    177, 111, 102, 31,	184, 129, 165, 249, 176, 53,  207, 211, 33,
	    26,	 216, 70,  184, 8,   162, 22,  168, 31,	 251, 195, 64,	193,
	    82,	 169, 135, 151, 106, 110, 57,  1,   214, 48,  33,  188, 87,
	    126, 170, 72,  1,	163, 73,  82,  179, 171, 177, 98,  246, 61,
	    160, 151, 66,  102, 60,  166, 149, 184, 131, 145, 198, 78,	169,
	    146, 81,  187, 85,	23,  167, 43,  3,   211, 230, 164, 136, 193,
	    38,	 72,  209, 183, 96,  249, 130, 60,  122, 65,  158, 116, 114,
	    198, 66,  24,  39,	152, 34,  132, 25,  164, 130, 218, 122, 176,
	    22,	 3,   57,  176, 61,  29,  163, 136, 129, 188, 41,  30,	10,
	    156, 51,  12,  179, 239, 193, 8,   104, 244, 12,  142, 44,	82,
	    235, 193, 191, 213, 171, 180, 254, 9,   89,	 39,  117, 85,	95,
	    213, 103, 40,  101, 97,  159, 33,  162, 107, 248, 119, 15,	240,
	    56,	 67,  250, 122, 157, 192, 172, 147, 106, 97,  167, 150, 33,
	    128, 128, 5,   225, 179, 152, 243, 40,  89,	 114, 168, 97,	111,
	    240, 65,  201, 147, 89,  216, 76,  146, 68,	 128, 54,  19,	217,
	    25,	 235, 181, 70,	52,  67,  68,  136, 241, 107, 110, 26,	39,
	    248, 154, 34,  20,	151, 150, 249, 151, 181, 28,  178, 147, 126,
	    59,	 192, 68,  106, 187, 106, 186, 185, 107, 227, 145, 169, 129,
	    47,	 135, 233, 120, 38,  152, 194, 128, 121, 134, 211, 145, 73,
	    213, 213, 131, 34,	68,  69,  62,  6,   111, 70,  54,  115, 107,
	    230, 149, 243, 16,	43,  148, 145, 125, 43,	 68,  159, 248, 128,
	    149, 213, 242, 46,	5,   115, 31,  158, 5,	 115, 215, 240, 11,
	    139, 87,  58,  71,	235, 34,  53,  16,  44,	 173, 23,  234, 87,
	    33,	 64,  115, 236, 169, 232, 29};
	ASSERT(!fastmemcmp(pk.data, expected_pk, sizeof(pk)), "pk");
	ASSERT(!fastmemcmp(sk.data, expected_sk, sizeof(sk)), "sk");
	enc(&ct, &ss_bob, &pk, &rng);
	u8 expected_ct[] = {
	    140, 212, 13,  60,	49,  184, 207, 222, 9,	 96,  219, 177, 225,
	    214, 234, 55,  213, 100, 228, 96,  152, 238, 228, 63,  227, 182,
	    109, 148, 74,  201, 81,  159, 48,  156, 12,	 18,  146, 221, 148,
	    24,	 157, 7,   163, 214, 236, 102, 117, 21,	 91,  146, 113, 177,
	    16,	 208, 74,  217, 224, 182, 67,  32,  112, 126, 167, 60,	231,
	    237, 32,  100, 162, 70,  61,  39,  200, 156, 236, 62,  175, 121,
	    236, 1,   213, 3,	208, 67,  165, 93,  18,	 182, 149, 99,	180,
	    37,	 34,  74,  76,	140, 74,  101, 255, 141, 75,  174, 203, 63,
	    226, 164, 127, 14,	211, 149, 20,  43,  28,	 41,  187, 245, 167,
	    35,	 43,  103, 94,	136, 194, 202, 244, 177, 39,  241, 118, 200,
	    156, 190, 62,  208, 79,  37,  174, 128, 212, 115, 224, 216, 44,
	    123, 43,  127, 203, 241, 128, 75,  196, 153, 104, 27,  43,	163,
	    202, 67,  228, 141, 6,   77,  191, 93,  33,	 147, 250, 228, 193,
	    61,	 139, 8,   153, 228, 90,  160, 5,   249, 5,   244, 18,	238,
	    157, 176, 239, 234, 115, 251, 45,  12,  134, 118, 159, 117, 216,
	    29,	 20,  231, 155, 144, 245, 254, 221, 183, 186, 21,  224, 250,
	    106, 58,  36,  227, 106, 125, 62,  105, 180, 243, 232, 167, 63,
	    198, 242, 3,   91,	163, 18,  183, 8,   230, 119, 247, 188, 134,
	    81,	 192, 25,  227, 245, 94,  81,  215, 178, 120, 253, 62,	134,
	    82,	 124, 37,  12,	17,  217, 176, 116, 56,	 128, 33,  204, 10,
	    76,	 243, 38,  242, 71,  104, 118, 94,  214, 83,  200, 121, 79,
	    223, 54,  220, 49,	171, 48,  100, 210, 19,	 13,  56,  243, 130,
	    78,	 132, 43,  99,	3,   199, 34,  32,  133, 45,  197, 112, 165,
	    82,	 52,  1,   22,	226, 75,  10,  72,  158, 23,  22,  136, 78,
	    94,	 87,  71,  116, 58,  121, 111, 215, 11,	 247, 96,  203, 164,
	    27,	 121, 81,  104, 167, 93,  122, 213, 159, 100, 121, 41,	79,
	    205, 82,  30,  76,	157, 75,  76,  247, 174, 64,  183, 224, 68,
	    57,	 132, 235, 108, 55,  53,  200, 210, 205, 178, 38,  180, 11,
	    37,	 21,  241, 67,	199, 178, 139, 17,  112, 220, 45,  125, 232,
	    215, 154, 57,  161, 151, 222, 85,  248, 236, 190, 96,  227, 233,
	    83,	 227, 179, 222, 147, 132, 147, 14,  235, 223, 117, 234, 157,
	    139, 48,  10,  175, 151, 9,	  17,  150, 150, 87,  28,  145, 212,
	    60,	 24,  135, 208, 90,  130, 160, 48,  35,	 240, 208, 180, 192,
	    24,	 120, 132, 33,	61,  24,  78,  37,  43,	 67,  32,  124, 32,
	    209, 102, 243, 10,	38,  98,  147, 220, 133, 252, 101, 75,	240,
	    177, 37,  68,  49,	107, 197, 69,  135, 199, 181, 170, 59,	178,
	    44,	 70,  129, 195, 155, 0,	  25,  83,  192, 121, 128, 115, 14,
	    71,	 68,  105, 123, 224, 107, 173, 116, 202, 119, 135, 74,	173,
	    236, 107, 42,  36,	232, 203, 163, 126, 134, 99,  212, 136, 241,
	    84,	 220, 196, 132, 190, 241, 209, 153, 93,	 189, 102, 35,	211,
	    205, 152, 85,  45,	74,  107, 75,  6,   9,	 238, 163, 225, 123,
	    134, 24,  29,  31,	56,  233, 0,   140, 35,	 117, 176, 254, 239,
	    21,	 140, 251, 161, 170, 106, 144, 130, 13,	 112, 154, 116, 54,
	    212, 217, 68,  194, 94,  255, 115, 243, 51,	 216, 100, 67,	69,
	    135, 219, 180, 63,	41,  250, 244, 46,  43,	 185, 183, 218, 239,
	    139, 181, 148, 237, 218, 75,  17,  63,  121, 147, 179, 238, 139,
	    234, 84,  8,   204, 145, 255, 215, 22,  86,	 199, 251, 151, 213,
	    253, 111, 54,  222, 238, 183, 56,  7,   69,	 42,  187, 179, 163,
	    82,	 57,  9,   104, 68,  110, 40,  214, 52,	 100, 201, 116, 90,
	    32,	 49,  15,  163, 52,  164, 98,  48,  20,	 15,  39,  9,	252,
	    218, 128, 167, 95,	96,  153, 105, 75,  216, 54,  226, 254, 225,
	    147, 129, 26,  128, 111, 140, 108, 111, 141, 171, 190, 155, 107,
	    170, 159, 198, 234, 68,  69,  117, 32,  163, 151, 253, 71,	0,
	    99,	 202, 12,  39,	96,  92,  181, 214, 81,	 93,  59,  64,	171,
	    127, 251, 33,  71,	147, 122, 240, 149, 121, 79,  196, 103, 48,
	    1,	 41,  193, 218, 128, 76,  172, 2,   56,	 181, 163, 117, 39,
	    91,	 255, 118, 135, 133, 254, 46,  0,   142, 78,  7,   216, 24,
	    47,	 175, 11,  71,	224, 13,  232, 112, 250, 56,  143, 8,	105,
	    242, 143, 40,  111, 141, 216, 243, 176, 3,	 31,  112, 33,	87,
	    101};
	// print("ct: ");
	// for (u32 i = 0; i < sizeof(ct); i++) print("{}, ",
	// ct.data[i]);
	(void)expected_ct;
	(void)expected_pk;
	(void)expected_sk;
	ASSERT(!memcmp(&ct, expected_ct, sizeof(ct)), "ct");
	dec(&ss_alice, &ct, &sk);
	// for (u32 i = 0; i < sizeof(ss_bob); i++) print("{}, ",
	// ss_bob.data[i]);

	ASSERT(!fastmemcmp(&ss_bob, &ss_alice, KEM_SS_SIZE), "shared secret");

	u8 expected[32] = {85,	5,  173, 86,  0,   98,	98,  80,  82,  112, 143,
			   42,	81, 153, 71,  106, 110, 231, 85,  168, 10,  172,
			   250, 56, 203, 222, 87,  240, 244, 222, 139, 146};

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

Test(dilithium_vector) {
	__attribute__((aligned(32))) u8 seed[32] = {1, 2, 3, 4};
	__attribute__((aligned(32))) u8 msg[32] = {5, 4, 2, 1};
	PublicKey pk = {0};
	SecretKey sk = {0};
	Signature sig = {0};
	Rng rng;

	rng_test_seed(&rng, seed);
	keyfrom(seed, &sk, &pk);
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ",
	// sk.data[i]);
	sign(msg, &sk, &sig, &rng);
	// for (u32 i = 0; i < sizeof(sig); i++) print("{}, ",
	// sig.data[i]);
	u8 expected_pk[] = {
	    199, 176, 203, 198, 198, 70,  74,  61,  24,	 222, 203, 9,	152,
	    163, 52,  104, 207, 250, 32,  74,  71,  177, 7,   40,  128, 2,
	    123, 69,  102, 254, 55,  202, 95,  63,  223, 162, 64,  202, 1,
	    7,	 119, 90,  96,	86,  174, 17,  39,  69,	 6,   22,  252, 218,
	    194, 19,  98,  125, 150, 153, 207, 50,  254, 89,  169, 193, 14,
	    44,	 116, 224, 192, 91,  7,	  204, 62,  191, 30,  3,   193, 187,
	    87,	 41,  192, 248, 128, 198, 9,   84,  104, 164, 63,  4,	49,
	    129, 145, 114, 138, 203, 3,	  245, 209, 171, 44,  138, 68,	181,
	    50,	 34,  56,  138, 203, 232, 22,  239, 19,	 52,  140, 58,	105,
	    65,	 132, 166, 168, 137, 46,  227, 178, 90,	 175, 28,  117, 161,
	    87,	 113, 190, 9,	93,  107, 218, 18,  62,	 155, 132, 177, 85,
	    190, 181, 249, 111, 250, 20,  74,  84,  208, 72,  205, 231, 227,
	    153, 155, 68,  34,	223, 253, 175, 224, 125, 215, 130, 254, 133,
	    132, 65,  97,  75,	143, 241, 47,  254, 14,	 29,  17,  81,	60,
	    20,	 20,  166, 152, 44,  158, 136, 112, 200, 144, 6,   24,	181,
	    241, 110, 82,  203, 132, 89,  100, 63,  38,	 4,   211, 142, 235,
	    124, 233, 197, 115, 154, 113, 87,  14,  224, 85,  39,  204, 8,
	    25,	 151, 230, 54,	81,  90,  45,  133, 201, 3,   3,   180, 222,
	    27,	 203, 215, 160, 44,  103, 24,  82,  228, 232, 20,  72,	168,
	    72,	 213, 100, 186, 135, 113, 185, 209, 215, 217, 215, 14,	18,
	    236, 151, 200, 229, 137, 210, 140, 223, 171, 252, 92,  18,	201,
	    39,	 2,   141, 194, 241, 7,	  46,  104, 46,	 250, 168, 231, 154,
	    149, 53,  185, 135, 230, 6,	  191, 76,  43,	 160, 171, 192, 103,
	    98,	 134, 242, 70,	112, 132, 20,  102, 94,	 252, 71,  2,	255,
	    90,	 41,  83,  149, 27,  83,  162, 123, 190, 224, 66,  217, 93,
	    218, 70,  102, 227, 125, 154, 226, 175, 107, 105, 172, 130, 229,
	    21,	 17,  206, 244, 53,  52,  217, 10,  70,	 138, 159, 46,	167,
	    10,	 226, 83,  127, 227, 81,  160, 250, 161, 85,  61,  140, 244,
	    167, 145, 119, 82,	100, 88,  62,  203, 226, 133, 185, 17,	251,
	    255, 201, 221, 195, 229, 136, 105, 123, 173, 192, 4,   193, 245,
	    216, 42,  245, 22,	33,  187, 234, 185, 202, 174, 79,  64,	46,
	    157, 83,  153, 40,	250, 193, 89,  1,   29,	 187, 249, 179, 99,
	    47,	 80,  10,  66,	102, 246, 152, 115, 48,	 32,  156, 64,	136,
	    21,	 179, 43,  254, 213, 116, 223, 42,  161, 225, 119, 162, 78,
	    128, 32,  195, 192, 152, 45,  216, 231, 255, 35,  55,  84,	153,
	    67,	 14,  11,  216, 79,  205, 157, 44,  11,	 223, 143, 29,	192,
	    114, 65,  53,  139, 84,  45,  236, 127, 2,	 164, 129, 252, 195,
	    23,	 104, 46,  171, 86,  41,  153, 51,  44,	 192, 222, 221, 20,
	    174, 74,  172, 252, 78,  147, 71,  106, 178, 230, 201, 110, 199,
	    201, 11,  175, 3,	52,  22,  132, 94,  245, 58,  236, 37,	145,
	    56,	 187, 45,  164, 85,  162, 50,  38,  79,	 140, 20,  33,	39,
	    251, 160, 255, 94,	20,  215, 78,  255, 121, 221, 247, 32,	158,
	    152, 31,  209, 118, 166, 96,  119, 208, 109, 99,  18,  62,	179,
	    61,	 52,  97,  204, 78,  118, 249, 60,  161, 45,  18,  121, 115,
	    36,	 222, 104, 195, 221, 115, 60,  70,  101, 130, 174, 183, 166,
	    126, 146, 93,  60,	23,  197, 194, 206, 48,	 230, 167, 80,	161,
	    113, 128, 118, 246, 25,  39,  4,   52,  179, 147, 197, 180, 62,
	    89,	 249, 88,  42,	118, 100, 33,  119, 37,	 218, 44,  147, 123,
	    250, 235, 229, 138, 141, 12,  229, 62,  37,	 21,  127, 231, 108,
	    94,	 176, 133, 44,	239, 254, 168, 78,  177, 178, 94,  16,	229,
	    62,	 75,  92,  93,	199, 66,  148, 63,  89,	 33,  1,   188, 159,
	    153, 188, 211, 156, 225, 249, 5,   166, 25,	 164, 26,  79,	112,
	    136, 68,  197, 121, 229, 96,  84,  9,   207, 179, 187, 249, 206,
	    70,	 28,  64,  160, 226, 143, 252, 144, 142, 204, 151, 108, 136,
	    223, 138, 84,  13,	125, 234, 80,  82,  241, 132, 237, 44,	232,
	    222, 16,  215, 229, 67,  15,  57,  74,  129, 60,  72,  157, 62,
	    97,	 71,  206, 193, 244, 197, 30,  51,  51,	 215, 205, 128, 41,
	    179, 19,  234, 255, 238, 67,  47,  146, 242, 28,  165, 115, 73,
	    0,	 35,  3,   0,	90,  59,  209, 147, 2,	 193, 242, 60,	197,
	    135, 9,   169, 146, 76,  105, 215, 34,  120, 77,  95,  91,	67,
	    125, 3,   124, 39,	242, 188, 160, 154, 34,	 180, 190, 43,	250,
	    230, 201, 249, 117, 187, 218, 99,  233, 135, 81,  212, 212, 41,
	    22,	 89,  95,  0,	112, 143, 21,  131, 57,	 240, 176, 181, 9,
	    187, 37,  166, 85,	113, 48,  37,  245, 251, 1,   112, 10,	55,
	    246, 199, 110, 138, 134, 119, 38,  117, 90,	 151, 6,   250, 101,
	    43,	 104, 36,  125, 166, 45,  199, 11,  188, 71,  76,  58,	220,
	    182, 221, 107, 18,	103, 241, 155, 135, 25,	 122, 164, 155, 132,
	    18,	 241, 158, 153, 57,  150, 82,  136, 55,	 145, 166, 157, 190,
	    173, 149, 106, 219, 238, 252, 14,  80,  16,	 142, 214, 32,	51,
	    24,	 197, 82,  184, 95,  176, 155, 63,  213, 206, 140, 132, 161,
	    215, 164, 9,   149, 93,  60,  126, 105, 190, 23,  244, 229, 14,
	    230, 234, 117, 14,	33,  15,  204, 27,  151, 202, 146, 93,	206,
	    190, 79,  69,  163, 31,  59,  41,  124, 77,	 180, 90,  49,	238,
	    206, 85,  69,  179, 81,  77,  120, 114, 112, 106, 113, 105, 27,
	    184, 125, 157, 201, 196, 226, 216, 51,  228, 138, 129, 183, 37,
	    104, 240, 6,   45,	251, 225, 254, 151, 191, 126, 196, 65,	174,
	    240, 98,  205, 243, 19,  83,  81,  24,  96,	 30,  15,  198, 48,
	    197, 2,   80,  47,	161, 40,  128, 31,  10,	 231, 84,  138, 114,
	    36,	 175, 197, 2,	99,  182, 170, 136, 238, 77,  93,  231, 244,
	    59,	 89,  178, 68,	190, 16,  16,  108, 187, 60,  77,  220, 54,
	    68,	 6,   108, 105, 147, 17,  109, 146, 181, 41,  234, 220, 223,
	    241, 81,  93,  84,	253, 15,  125, 111, 33,	 253, 216, 224, 83,
	    79,	 200, 250, 34,	145, 220, 201, 45,  27,	 81,  33,  229, 241,
	    152, 52,  76,  206, 63,  89,  123, 191, 37,	 167, 140, 10,	104,
	    141, 127, 156, 93,	109, 14,  5,   36,  70,	 208, 21,  123, 52,
	    116, 47,  6,   162, 198, 162, 221, 117, 37,	 31,  61,  246, 15,
	    153, 139, 5,   183, 233, 78,  87,  170, 142, 77,  214, 58,	114,
	    134, 193, 65,  71,	75,  202, 28,  246, 62,	 5,   140, 7,	68,
	    77,	 4,   30,  181, 214, 31,  171, 132, 224, 218, 206, 5,	62,
	    69,	 105, 200, 20,	12,  121, 63,  215, 178, 174, 131, 205, 97,
	    164, 83,  237, 196, 134, 2,	  103, 188, 215, 66,  251, 243, 77,
	    196, 43,  211, 48,	165, 103, 55,  34,  126, 158, 47,  92,	78,
	    90,	 242, 237, 195, 87,  178, 232, 116, 192, 234, 168, 255, 182,
	    200, 25,  24,  177, 110, 202, 192, 65,  127, 82,  227, 59,	194,
	    86,	 245, 191, 222, 63,  7,	  163, 113, 60,	 44,  137, 201, 38,
	    164, 230, 222, 212, 90,  109, 185, 203, 140, 249, 153, 83,	68,
	    19,	 131, 212, 68,	172, 224, 49,  25,  175, 144, 135, 56,	38,
	    167, 52,  101, 162, 134, 167, 136, 66,  166, 81,  102, 160, 180,
	    246, 79,  175, 118, 128, 2,	  199, 155, 93,	 105, 11,  117, 137,
	    206, 70,  69,  248, 123, 67,  108, 51,  130, 246, 105, 230, 189,
	    218, 221, 125, 144, 37,  157, 30,  103, 246, 215, 143, 124};
	u8 expected_sk[] = {
	    199, 176, 203, 198, 198, 70,  74,  61,  24,	 222, 203, 9,	152,
	    163, 52,  104, 207, 250, 32,  74,  71,  177, 7,   40,  128, 2,
	    123, 69,  102, 254, 55,  202, 28,  195, 11,	 29,  226, 179, 121,
	    213, 142, 147, 187, 245, 90,  110, 26,  24,	 250, 200, 216, 81,
	    98,	 251, 39,  57,	149, 34,  233, 47,  75,	 203, 184, 194, 189,
	    179, 68,  156, 179, 210, 109, 211, 116, 236, 80,  24,  231, 250,
	    178, 170, 194, 8,	49,  20,  40,  31,  250, 224, 0,   161, 216,
	    19,	 34,  10,  152, 151, 55,  197, 199, 138, 135, 101, 62,	86,
	    28,	 91,  152, 233, 50,  157, 145, 195, 176, 230, 149, 228, 80,
	    201, 123, 184, 106, 9,   84,  253, 40,  237, 50,  110, 212, 182,
	    137, 193, 18,  80,	98,  128, 12,  80,  160, 81,  81,  70,	38,
	    128, 200, 76,  226, 54,  133, 19,  32,  0,	 90,  150, 105, 152,
	    72,	 78,  24,  148, 41,  8,	  177, 140, 195, 18,  136, 91,	196,
	    5,	 132, 192, 48,	153, 34,  133, 81,  52,	 0,   164, 16,	37,
	    84,	 182, 100, 28,	165, 72,  11,  66,  81,	 200, 56,  42,	81,
	    128, 141, 88,  152, 41,  1,	  67,  10,  1,	 150, 16,  0,	50,
	    145, 27,  198, 76,	33,  9,	  6,   220, 184, 112, 35,  153, 33,
	    11,	 134, 49,  210, 24,  109, 98,  66,  34,	 162, 22,  144, 33,
	    129, 133, 196, 66,	128, 25,  196, 113, 10,	 146, 113, 17,	38,
	    136, 144, 192, 1,	155, 38,  64,  196, 20,	 114, 76,  40,	34,
	    82,	 50,  110, 16,	34,  141, 146, 16,  146, 12,  201, 36,	76,
	    4,	 144, 2,   71,	102, 140, 196, 32,  100, 18,  36,  34,	53,
	    36,	 212, 20,  4,	17,  68,  96,  90,  0,	 81,  75,  22,	38,
	    35,	 38,  70,  136, 132, 17,  19,  64,  48,	 161, 178, 80,	128,
	    8,	 106, 228, 16,	136, 82,  50,  145, 36,	 67,  14,  210, 48,
	    78,	 10,  73,  69,	0,   0,	  82,  26,  71,	 105, 67,  40,	38,
	    2,	 149, 64,  3,	194, 17,  67,  56,  45,	 153, 192, 8,	25,
	    147, 49,  66,  64,	40,  34,  54,  1,   75,	 66,  137, 36,	57,
	    4,	 27,  56,  32,	26,  192, 65,  139, 50,	 140, 1,   6,	16,
	    196, 176, 17,  201, 178, 73,  99,  18,  78,	 1,   65,  137, 147,
	    176, 101, 68,  24,	78,  24,  164, 65,  145, 192, 100, 131, 2,
	    69,	 27,  135, 49,	136, 200, 8,   139, 8,	 77,  210, 54,	33,
	    202, 20,  10,  164, 144, 97,  16,  50,  41,	 76,  164, 5,	11,
	    34,	 102, 140, 176, 80,  18,  148, 108, 2,	 145, 65,  2,	36,
	    80,	 226, 150, 140, 12,  16,  42,  19,  178, 8,   136, 18,	130,
	    210, 194, 13,  220, 192, 140, 88,  36,  6,	 35,  9,   108, 11,
	    162, 16,  145, 38,	34,  8,	  133, 0,   131, 22,  76,  147, 128,
	    36,	 196, 18,  113, 92,  4,	  4,   74,  192, 145, 88,  144, 113,
	    26,	 196, 12,  163, 64,  109, 16,  40,  46,	 131, 56,  68,	32,
	    57,	 145, 12,  73,	34,  3,	  73,  132, 36,	 153, 128, 2,	52,
	    9,	 2,   36,  50,	144, 198, 65,  25,  180, 105, 8,   161, 81,
	    67,	 162, 145, 162, 2,   65,  100, 166, 33,	 17,  69,  106, 212,
	    160, 40,  1,   131, 41,  65,  176, 45,  0,	 133, 108, 139, 56,
	    6,	 3,   160, 13,	72,  54,  8,   97,  0,	 101, 35,  8,	65,
	    67,	 134, 80,  211, 146, 104, 0,   176, 113, 193, 8,   108, 132,
	    196, 33,  225, 22,	130, 140, 176, 129, 138, 160, 145, 195, 152,
	    137, 90,  52,  17,	24,  24,  38,  201, 56,	 105, 218, 16,	145,
	    220, 6,   4,   196, 72,  65,  99,  36,  50,	 35,  70,  106, 226,
	    20,	 36,  25,  72,	133, 138, 164, 4,   88,	 34,  13,  17,	38,
	    5,	 28,  65,  34,	209, 16,  1,   132, 8,	 110, 2,   201, 144,
	    4,	 55,  45,  2,	37,  48,  26,  8,   74,	 146, 146, 64,	211,
	    54,	 100, 9,   183, 8,   162, 162, 141, 204, 70,  48,  76,	134,
	    5,	 18,  7,   137, 35,  4,	  37,  18,  177, 68,  68,  178, 5,
	    76,	 18,  142, 212, 34,  133, 76,  4,   70,	 64,  152, 136, 156,
	    8,	 40,  11,  178, 80,  26,  8,   70,  228, 196, 108, 224, 6,
	    73,	 81,  180, 49,	16,  129, 144, 148, 64,	 40,  82,  18,	33,
	    218, 52,  4,   226, 32,  64,  25,  69,  4,	 27,  165, 96,	34,
	    152, 44,  33,  34,	72,  225, 4,   49,  74,	 150, 4,   17,	1,
	    82,	 224, 72,  142, 196, 72,  144, 202, 52,	 45,  67,  18,	144,
	    96,	 22,  97,  25,	73,  45,  204, 32,  4,	 219, 148, 77,	156,
	    32,	 112, 0,   152, 80,  161, 70,  2,   147, 34,  113, 34,	70,
	    50,	 68,  20,  102, 72,  152, 13,  4,   36,	 142, 154, 22,	69,
	    33,	 180, 113, 64,	130, 140, 11,  6,   6,	 88,  24,  112, 34,
	    192, 49,  137, 54,	46,  8,	  1,   69,  225, 184, 1,   2,	152,
	    97,	 36,  150, 141, 160, 6,	  77,  192, 8,	 32,  136, 128, 33,
	    11,	 56,  4,   203, 196, 68,  200, 72,  82,	 67,  64,  5,	76,
	    38,	 8,   3,   181, 80,  137, 68,  74,  25,	 64,  65,  2,	166,
	    69,	 24,  184, 48,	97,  2,	  36,  28,  40,	 140, 32,  130, 64,
	    10,	 195, 137, 10,	24,  45,  84,  198, 73,	 3,   179, 33,	151,
	    61,	 209, 246, 230, 205, 160, 29,  68,  180, 173, 151, 189, 114,
	    2,	 252, 81,  96,	108, 128, 128, 2,   145, 200, 65,  24,	24,
	    53,	 21,  246, 6,	186, 183, 131, 37,  255, 236, 152, 4,	115,
	    49,	 8,   101, 37,	212, 37,  60,  247, 183, 190, 68,  170, 49,
	    227, 194, 227, 60,	148, 125, 111, 84,  240, 105, 223, 185, 126,
	    12,	 141, 75,  70,	81,  174, 245, 0,   201, 80,  253, 10,	169,
	    219, 67,  242, 68,	215, 187, 242, 146, 159, 79,  126, 72,	233,
	    72,	 199, 34,  205, 52,  250, 228, 173, 226, 199, 96,  107, 42,
	    152, 72,  194, 177, 231, 20,  26,  125, 9,	 83,  51,  137, 157,
	    136, 141, 0,   28,	90,  139, 179, 163, 89,	 98,  164, 115, 2,
	    13,	 29,  255, 3,	210, 182, 38,  188, 102, 52,  68,  94,	237,
	    201, 126, 154, 212, 124, 158, 171, 172, 236, 71,  250, 97,	197,
	    129, 42,  153, 121, 203, 228, 17,  210, 83,	 79,  113, 153, 134,
	    175, 61,  102, 234, 59,  76,  224, 61,  51,	 105, 113, 125, 61,
	    93,	 62,  179, 40,	217, 189, 40,  124, 18,	 56,  48,  52,	239,
	    103, 52,  176, 107, 184, 45,  179, 101, 186, 147, 199, 174, 254,
	    95,	 105, 212, 14,	208, 110, 217, 223, 180, 48,  66,  21,	241,
	    144, 247, 188, 142, 100, 89,  250, 151, 190, 234, 186, 213, 94,
	    0,	 186, 129, 50,	72,  145, 204, 206, 152, 2,   238, 21,	69,
	    193, 123, 69,  146, 234, 250, 62,  8,   183, 129, 225, 119, 73,
	    212, 212, 36,  78,	49,  196, 96,  70,  156, 105, 158, 239, 150,
	    23,	 239, 82,  149, 195, 243, 168, 247, 79,	 41,  160, 4,	194,
	    212, 79,  89,  153, 7,   246, 186, 239, 58,	 187, 149, 240, 44,
	    22,	 153, 216, 200, 147, 25,  141, 66,  220, 31,  188, 62,	87,
	    57,	 254, 202, 12,	200, 213, 96,  13,  186, 151, 172, 14,	143,
	    177, 94,  107, 138, 185, 89,  151, 203, 249, 121, 251, 177, 241,
	    118, 221, 206, 128, 56,  244, 164, 38,  199, 158, 197, 201, 1,
	    4,	 0,   178, 137, 76,  36,  129, 165, 8,	 130, 227, 148, 86,
	    19,	 122, 20,  48,	194, 88,  221, 37,  0,	 35,  234, 122, 38,
	    66,	 198, 140, 122, 255, 207, 217, 240, 144, 14,  41,  164, 114,
	    44,	 217, 50,  177, 233, 14,  39,  194, 80,	 43,  221, 70,	4,
	    27,	 247, 193, 56,	232, 28,  191, 69,  45,	 104, 187, 17,	61,
	    136, 224, 28,  125, 129, 60,  255, 178, 144, 253, 232, 31,	235,
	    237, 187, 228, 12,	76,  99,  151, 231, 248, 155, 79,  221, 166,
	    147, 234, 14,  102, 160, 48,  247, 3,   82,	 70,  218, 254, 224,
	    114, 96,  36,  178, 153, 172, 221, 92,  35,	 56,  213, 193, 189,
	    64,	 113, 117, 139, 100, 56,  22,  168, 34,	 190, 147, 253, 174,
	    14,	 49,  89,  110, 23,  65,  226, 29,  73,	 189, 48,  191, 112,
	    100, 177, 224, 177, 93,  44,  60,  88,  219, 103, 214, 57,	241,
	    103, 22,  81,  207, 194, 0,	  150, 166, 248, 121, 224, 135, 243,
	    224, 99,  181, 220, 90,  149, 57,  68,  72,	 198, 151, 35,	87,
	    32,	 195, 111, 246, 29,  93,  90,  112, 161, 234, 86,  240, 95,
	    170, 238, 148, 94,	121, 214, 145, 30,  17,	 109, 167, 55,	125,
	    149, 71,  21,  206, 22,  182, 152, 93,  88,	 152, 76,  249, 206,
	    252, 203, 88,  102, 20,  164, 88,  123, 78,	 186, 10,  200, 58,
	    102, 23,  188, 21,	157, 106, 92,  248, 226, 9,   104, 190, 213,
	    50,	 66,  221, 129, 240, 104, 101, 170, 176, 252, 59,  13,	253,
	    254, 63,  157, 239, 34,  45,  92,  39,  203, 203, 55,  1,	153,
	    70,	 109, 85,  186, 86,  45,  118, 39,  156, 174, 219, 74,	157,
	    168, 201, 58,  153, 224, 151, 228, 162, 99,	 249, 89,  233, 199,
	    219, 98,  233, 43,	26,  223, 15,  116, 33,	 173, 101, 234, 49,
	    153, 89,  148, 163, 83,  182, 31,  222, 201, 225, 153, 179, 111,
	    57,	 225, 31,  179, 60,  14,  113, 8,   194, 189, 58,  171, 66,
	    113, 178, 124, 98,	78,  158, 121, 245, 82,	 95,  231, 67,	26,
	    203, 180, 128, 142, 35,  155, 195, 247, 47,	 203, 52,  218, 81,
	    253, 30,  216, 159, 169, 79,  149, 75,  215, 90,  149, 64,	18,
	    6,	 29,  195, 122, 103, 185, 130, 32,  74,	 102, 237, 72,	0,
	    136, 122, 86,  157, 146, 121, 119, 176, 252, 221, 105, 206, 14,
	    235, 243, 70,  11,	94,  94,  117, 90,  34,	 228, 161, 118, 135,
	    253, 129, 32,  33,	94,  85,  97,  46,  19,	 159, 9,   236, 32,
	    131, 1,   95,  173, 21,  215, 110, 37,  29,	 154, 35,  99,	66,
	    101, 144, 110, 157, 115, 145, 215, 114, 169, 99,  94,  197, 99,
	    81,	 187, 192, 224, 8,   33,  167, 22,  28,	 186, 28,  25,	156,
	    89,	 119, 57,  87,	246, 50,  118, 136, 229, 97,  220, 178, 124,
	    174, 212, 136, 12,	98,  18,  8,   127, 242, 122, 159, 126, 175,
	    248, 198, 137, 51,	161, 25,  2,   179, 29,	 112, 25,  53,	79,
	    22,	 33,  53,  175, 139, 55,  237, 55,  176, 115, 162, 102, 220,
	    91,	 35,  181, 37,	36,  120, 171, 43,  123, 145, 185, 127, 22,
	    21,	 135, 78,  126, 242, 246, 137, 110, 102, 160, 145, 23,	203,
	    51,	 86,  249, 42,	153, 136, 149, 105, 227, 81,  66,  26,	136,
	    1,	 153, 186, 198, 24,  119, 72,  148, 217, 247, 248, 93,	84,
	    105, 183, 45,  181, 169, 168, 89,  18,  207, 206, 208, 178, 69,
	    98,	 121, 246, 40,	209, 111, 185, 181, 65,	 28,  213, 171, 238,
	    4,	 86,  233, 123, 127, 18,  106, 142, 120, 127, 195, 41,	201,
	    226, 50,  27,  167, 50,  216, 43,  186, 23,	 243, 76,  88,	25,
	    10,	 167, 174, 207, 185, 187, 252, 250, 57,	 191, 10,  160, 182,
	    53,	 133, 148, 114, 114, 118, 87,  217, 41,	 4,   240, 140, 190,
	    236, 110, 172, 174, 25,  34,  7,   249, 65,	 53,  55,  193, 219,
	    22,	 151, 90,  211, 203, 185, 109, 155, 193, 194, 201, 167, 93,
	    74,	 165, 41,  45,	8,   231, 234, 223, 80,	 118, 69,  80,	51,
	    17,	 115, 12,  215, 176, 181, 109, 245, 135, 4,   82,  42,	215,
	    183, 90,  108, 182, 148, 185, 58,  140, 254, 199, 19,  119, 104,
	    59,	 157, 66,  84,	245, 56,  74,  210, 234, 76,  219, 100, 141,
	    70,	 42,  98,  224, 113, 249, 208, 67,  140, 243, 4,   53,	131,
	    29,	 88,  13,  174, 127, 156, 107, 141, 163, 76,  42,  59,	16,
	    148, 169, 231, 172, 127, 107, 92,  78,  94,	 58,  77,  192, 246,
	    220, 200, 91,  127, 18,  90,  47,  118, 8,	 130, 145, 6,	121,
	    154, 26,  35,  136, 77,  45,  94,  163, 5,	 226, 227, 124, 102,
	    236, 146, 216, 140, 139, 231, 40,  193, 217, 82,  162, 68,	237,
	    41,	 154, 191, 41,	80,  248, 253, 140, 240, 204, 206, 75,	37,
	    50,	 89,  93,  47,	175, 50,  62,  219, 61,	 211, 118, 225, 253,
	    202, 90,  77,  61,	230, 251, 13,  189, 154, 221, 123, 246, 2,
	    14,	 41,  47,  197, 194, 31,  181, 7,   2,	 179, 45,  159, 227,
	    140, 219, 61,  203, 2,   248, 140, 159, 127, 127, 76,  144, 95,
	    201, 40,  169, 137, 39,  234, 55,  189, 86,	 171, 169, 44,	121,
	    13,	 35,  6,   118, 79,  208, 124, 74,  146, 97,  85,  252, 190,
	    130, 5,   222, 148, 100, 135, 227, 98,  11,	 43,  93,  151, 68,
	    230, 181, 146, 35,	252, 205, 239, 30,  173, 143, 158, 27,	168,
	    143, 113, 143, 19,	54,  14,  173, 9,   167, 242, 104, 118, 191,
	    181, 11,  105, 120, 14,  99,  74,  151, 237, 247, 210, 39,	56,
	    71,	 119, 200, 143, 194, 32,  177, 54,  112, 238, 178, 203, 143,
	    242, 35,  41,  76,	245, 177, 144, 182, 127, 12,  162, 26,	76,
	    228, 106, 71,  136, 254, 67,  143, 239, 54,	 57,  60,  62,	81,
	    210, 168, 192, 40,	58,  78,  60,  242, 8,	 127, 61,  183, 87,
	    45,	 243, 250, 33,	112, 221, 223, 10,  232, 181, 204, 38,	224,
	    171, 81,  74,  49,	182, 190, 120, 234, 19,	 232, 8,   89,	110,
	    144, 43,  162, 122, 182, 120, 196, 212, 174, 34,  173, 72,	225,
	    160, 177, 245, 169, 249, 201, 27,  8,   164, 212, 253, 125, 189,
	    182, 95,  154, 169, 132, 37,  180, 136, 19,	 190, 233, 45,	183,
	    62,	 87,  61,  60,	240, 205, 80,  88,  251, 251, 11,  69,	22,
	    177, 200, 53,  159, 216, 226, 58,  56,  226, 231, 82,  113, 229,
	    193, 237, 105, 8,	204, 22,  254, 148, 198, 220, 154, 19,	245,
	    98,	 217, 43,  54,	99,  104, 67,  112, 251, 49,  113, 75,	155,
	    43,	 71,  138, 191, 207, 183, 191, 24,  151, 5,   199, 133, 135,
	    0,	 143, 148, 154, 212, 168, 99,  252, 188, 12,  129, 39,	97,
	    128, 191, 91,  97,	100, 229, 195, 29,  253, 194, 214, 92,	45,
	    167, 21,  177, 192, 12,  241, 168, 221, 227, 146, 143, 14,	104,
	    187, 141, 183, 35,	158, 93,  50,  221, 33,	 148, 41,  137, 146,
	    120, 61,  13,  176, 169, 180, 224, 101, 37,	 43,  190, 245, 48,
	    163, 5,   242, 208, 4,   235, 97,  182, 99,	 106, 125, 65,	94,
	    90,	 138, 140, 134, 156, 199, 252, 47,  42,	 90,  64,  58,	118,
	    33,	 21,  52,  66,	219, 148, 188, 63,  6,	 2,   229, 171, 214,
	    54,	 43,  85,  210, 220, 196, 22,  171, 68,	 205, 230, 181, 157,
	    44,	 114, 196, 49,	197, 7,	  164, 200, 140, 152, 39,  218, 230,
	    0,	 30,  30,  91,	22,  251, 199, 169, 247, 51,  52,  146, 41,
	    58,	 251, 18,  183, 158, 255, 61,  207, 95,	 68,  85,  132, 151,
	    127, 74,  233, 141, 205, 169, 136, 97,  100, 68,  197, 64,	138,
	    155, 95,  40,  29,	1,   91,  176, 224, 152, 174, 31,  26};
	u8 expected_sig[] = {
	    74,	 46,  191, 219, 65,  121, 153, 142, 97,	 0,   29,  20,	162,
	    240, 3,   127, 77,	151, 243, 119, 151, 70,	 224, 73,  113, 30,
	    30,	 51,  53,  221, 170, 141, 92,  169, 253, 158, 121, 122, 163,
	    185, 124, 166, 14,	249, 8,	  50,  251, 86,	 133, 150, 239, 66,
	    14,	 156, 55,  116, 163, 8,	  246, 222, 2,	 167, 20,  9,	178,
	    234, 107, 113, 195, 28,  147, 11,  212, 35,	 124, 33,  79,	168,
	    134, 70,  42,  185, 188, 153, 21,  4,   251, 109, 69,  214, 215,
	    65,	 51,  46,  54,	254, 72,  184, 217, 85,	 194, 71,  24,	42,
	    189, 181, 113, 78,	46,  200, 171, 214, 38,	 5,   195, 12,	30,
	    180, 62,  43,  84,	206, 179, 167, 83,  148, 53,  80,  22,	162,
	    235, 194, 9,   168, 74,  70,  18,  23,  125, 172, 113, 189, 117,
	    132, 203, 247, 6,	211, 163, 61,  165, 145, 164, 205, 95,	76,
	    12,	 52,  115, 202, 226, 223, 84,  238, 238, 69,  182, 135, 182,
	    9,	 139, 32,  148, 147, 248, 3,   112, 19,	 156, 181, 138, 11,
	    106, 125, 47,  26,	59,  200, 139, 151, 230, 10,  40,  30,	60,
	    119, 237, 196, 233, 18,  16,  62,  55,  235, 72,  47,  104, 108,
	    14,	 28,  148, 97,	232, 118, 2,   44,  207, 9,   68,  99,	130,
	    12,	 186, 42,  151, 47,  15,  184, 103, 91,	 25,  67,  202, 4,
	    146, 68,  105, 246, 152, 201, 28,  32,  63,	 54,  171, 164, 83,
	    18,	 96,  218, 208, 115, 74,  32,  192, 126, 188, 186, 67,	134,
	    183, 42,  188, 94,	116, 197, 174, 60,  160, 157, 120, 159, 147,
	    158, 38,  58,  53,	50,  68,  179, 109, 89,	 69,  217, 9,	199,
	    168, 138, 32,  193, 217, 95,  20,  248, 48,	 97,  204, 187, 171,
	    144, 133, 245, 58,	248, 133, 181, 167, 231, 116, 217, 222, 44,
	    173, 82,  242, 255, 66,  206, 201, 36,  40,	 235, 129, 20,	181,
	    139, 120, 81,  34,	205, 201, 125, 58,  187, 246, 99,  101, 158,
	    41,	 53,  57,  244, 40,  204, 254, 36,  254, 249, 62,  91,	46,
	    57,	 26,  200, 37,	254, 157, 194, 48,  179, 27,  199, 252, 203,
	    101, 24,  225, 59,	188, 36,  37,  252, 248, 220, 2,   114, 134,
	    37,	 230, 145, 18,	255, 63,  102, 0,   93,	 126, 200, 251, 122,
	    131, 13,  94,  164, 127, 219, 192, 50,  236, 84,  92,  19,	163,
	    11,	 209, 37,  237, 123, 57,  155, 158, 3,	 104, 185, 188, 229,
	    202, 230, 142, 177, 3,   97,  3,   205, 158, 26,  221, 28,	110,
	    62,	 116, 241, 37,	208, 23,  237, 240, 55,	 131, 123, 29,	206,
	    126, 178, 5,   2,	163, 84,  42,  86,  230, 199, 21,  183, 77,
	    78,	 164, 100, 49,	102, 198, 27,  8,   83,	 26,  129, 114, 145,
	    119, 33,  130, 74,	250, 205, 45,  150, 244, 202, 57,  163, 115,
	    71,	 247, 176, 234, 217, 172, 15,  230, 128, 230, 119, 198, 142,
	    5,	 61,  56,  118, 78,  103, 0,   3,   34,	 186, 222, 187, 181,
	    104, 253, 188, 114, 239, 26,  138, 165, 221, 130, 242, 115, 243,
	    72,	 65,  179, 105, 52,  155, 60,  209, 79,	 223, 39,  230, 107,
	    129, 21,  178, 144, 72,  98,  109, 81,  111, 114, 43,  210, 48,
	    152, 83,  47,  141, 174, 65,  132, 252, 128, 206, 114, 142, 167,
	    217, 40,  126, 13,	188, 200, 71,  174, 162, 48,  160, 26,	61,
	    47,	 79,  123, 170, 77,  84,  83,  64,  135, 40,  211, 6,	196,
	    47,	 234, 40,  216, 87,  222, 112, 169, 172, 23,  107, 52,	8,
	    226, 236, 37,  69,	10,  60,  83,  69,  30,	 132, 251, 151, 19,
	    198, 132, 0,   252, 84,  178, 147, 176, 186, 210, 171, 164, 222,
	    49,	 3,   34,  151, 45,  140, 79,  59,  120, 45,  142, 29,	64,
	    29,	 206, 84,  191, 153, 90,  186, 46,  174, 119, 207, 23,	236,
	    2,	 198, 155, 20,	221, 148, 211, 164, 22,	 8,   245, 82,	29,
	    105, 161, 114, 138, 242, 180, 200, 224, 209, 21,  108, 41,	199,
	    54,	 188, 158, 251, 239, 31,  203, 208, 138, 182, 118, 127, 192,
	    92,	 14,  105, 102, 243, 211, 74,  129, 231, 213, 130, 146, 129,
	    141, 247, 75,  82,	165, 14,  244, 73,  243, 12,  10,  155, 139,
	    198, 9,   120, 165, 184, 78,  254, 167, 17,	 115, 64,  96,	27,
	    9,	 136, 101, 55,	25,  118, 110, 10,  220, 104, 139, 213, 210,
	    131, 171, 16,  110, 175, 182, 25,  166, 35,	 150, 47,  133, 162,
	    132, 225, 189, 249, 246, 238, 209, 14,  98,	 67,  222, 254, 57,
	    58,	 169, 136, 118, 64,  23,  116, 9,   125, 45,  190, 200, 78,
	    131, 255, 183, 41,	115, 153, 50,  148, 149, 80,  163, 82,	225,
	    35,	 201, 166, 189, 172, 157, 135, 199, 120, 141, 59,  239, 164,
	    117, 218, 63,  228, 113, 175, 180, 167, 42,	 229, 204, 16,	219,
	    220, 114, 87,  23,	123, 252, 24,  194, 225, 150, 213, 1,	225,
	    20,	 146, 212, 16,	147, 206, 215, 170, 166, 112, 210, 139, 222,
	    140, 143, 188, 239, 54,  68,  209, 228, 86,	 86,  116, 71,	143,
	    181, 77,  217, 6,	233, 238, 251, 41,  128, 236, 14,  253, 89,
	    142, 120, 132, 69,	147, 31,  184, 165, 212, 222, 213, 77,	227,
	    221, 82,  80,  210, 47,  225, 205, 14,  229, 227, 230, 246, 247,
	    69,	 43,  199, 67,	212, 103, 26,  66,  48,	 233, 39,  196, 44,
	    201, 65,  139, 29,	237, 41,  220, 80,  52,	 118, 123, 204, 106,
	    234, 221, 40,  250, 210, 174, 231, 32,  128, 101, 161, 47,	187,
	    141, 233, 59,  157, 12,  164, 164, 88,  84,	 44,  29,  248, 199,
	    63,	 116, 79,  91,	151, 252, 135, 149, 224, 183, 204, 172, 83,
	    208, 48,  90,  65,	33,  105, 81,  191, 94,	 129, 229, 111, 216,
	    216, 225, 223, 123, 145, 24,  61,  24,  24,	 82,  83,  91,	1,
	    243, 210, 47,  242, 199, 109, 160, 55,  180, 240, 136, 47,	8,
	    211, 230, 46,  112, 241, 164, 231, 150, 157, 151, 98,  226, 70,
	    177, 48,  172, 103, 119, 61,  131, 93,  158, 7,   113, 32,	116,
	    45,	 20,  0,   173, 76,  24,  150, 15,  171, 107, 85,  90,	2,
	    233, 170, 14,  92,	219, 216, 59,  206, 162, 96,  229, 61,	208,
	    31,	 30,  20,  108, 168, 35,  23,  19,  14,	 82,  44,  143, 152,
	    27,	 200, 124, 94,	8,   29,  119, 91,  12,	 143, 9,   44,	138,
	    88,	 133, 112, 56,	198, 56,  251, 240, 61,	 10,  13,  180, 200,
	    100, 13,  247, 230, 122, 120, 1,   109, 169, 48,  31,  245, 26,
	    80,	 105, 192, 92,	127, 57,  196, 105, 94,	 112, 96,  60,	100,
	    13,	 23,  111, 33,	75,  197, 138, 132, 224, 98,  101, 147, 67,
	    245, 189, 22,  63,	174, 121, 97,  190, 16,	 135, 242, 185, 35,
	    95,	 196, 46,  113, 203, 212, 187, 44,  195, 37,  146, 141, 79,
	    206, 176, 112, 69,	128, 127, 58,  67,  0,	 25,  134, 118, 23,
	    213, 144, 25,  181, 198, 30,  242, 66,  123, 151, 62,  112, 187,
	    166, 116, 77,  215, 197, 105, 145, 250, 98,	 162, 175, 33,	212,
	    108, 50,  156, 251, 120, 75,  238, 40,  183, 74,  211, 155, 253,
	    61,	 48,  154, 163, 165, 156, 6,   237, 217, 144, 205, 48,	20,
	    112, 181, 187, 154, 244, 110, 188, 253, 184, 85,  16,  40,	226,
	    81,	 229, 41,  138, 114, 92,  23,  203, 103, 184, 122, 144, 144,
	    84,	 90,  141, 12,	117, 2,	  60,  250, 188, 51,  3,   204, 130,
	    182, 70,  183, 102, 198, 128, 212, 119, 120, 136, 55,  111, 115,
	    230, 62,  28,  249, 123, 30,  21,  45,  246, 198, 181, 249, 252,
	    240, 4,   33,  144, 164, 174, 67,  250, 95,	 16,  236, 140, 88,
	    178, 223, 21,  163, 205, 204, 125, 117, 83,	 51,  53,  89,	93,
	    172, 58,  27,  139, 26,  250, 63,  115, 50,	 169, 202, 56,	218,
	    130, 27,  38,  238, 7,   204, 233, 154, 253, 12,  238, 168, 186,
	    88,	 219, 56,  185, 248, 168, 219, 46,  22,	 112, 111, 160, 74,
	    65,	 69,  18,  213, 231, 99,  175, 193, 165, 82,  243, 156, 131,
	    147, 134, 216, 243, 231, 182, 112, 169, 99,	 59,  95,  252, 214,
	    5,	 32,  177, 157, 56,  246, 67,  52,  95,	 50,  51,  14,	204,
	    207, 229, 242, 8,	222, 212, 29,  48,  16,	 26,  122, 167, 206,
	    50,	 255, 90,  31,	191, 216, 107, 207, 20,	 99,  205, 2,	17,
	    254, 118, 122, 39,	30,  226, 252, 152, 198, 94,  117, 119, 64,
	    182, 122, 209, 79,	225, 97,  73,  135, 1,	 134, 99,  140, 182,
	    6,	 159, 145, 86,	36,  20,  40,  59,  177, 248, 184, 96,	128,
	    134, 89,  152, 90,	114, 34,  33,  230, 122, 54,  177, 41,	0,
	    158, 20,  160, 2,	103, 243, 182, 44,  110, 161, 166, 125, 122,
	    170, 118, 154, 223, 83,  194, 90,  127, 96,	 60,  139, 250, 211,
	    37,	 189, 195, 110, 46,  95,  101, 235, 85,	 89,  135, 140, 17,
	    40,	 33,  158, 114, 52,  181, 208, 243, 235, 69,  156, 221, 225,
	    1,	 165, 80,  35,	197, 93,  34,  24,  119, 191, 58,  144, 92,
	    41,	 117, 34,  139, 101, 118, 184, 89,  140, 192, 206, 65,	140,
	    99,	 64,  234, 196, 93,  93,  225, 101, 196, 247, 73,  180, 1,
	    18,	 96,  50,  183, 156, 192, 185, 255, 169, 137, 197, 61,	96,
	    184, 128, 117, 40,	81,  90,  215, 39,  39,	 10,  164, 144, 18,
	    215, 229, 6,   62,	23,  40,  254, 170, 195, 232, 194, 177, 97,
	    224, 198, 230, 182, 26,  234, 249, 157, 103, 173, 116, 120, 242,
	    129, 29,  105, 10,	92,  194, 177, 158, 226, 175, 135, 134, 236,
	    123, 34,  9,   207, 51,  206, 178, 216, 188, 236, 50,  79,	208,
	    14,	 132, 0,   251, 224, 6,	  192, 73,  166, 154, 182, 178, 65,
	    106, 216, 197, 56,	167, 13,  107, 1,   20,	 232, 87,  173, 53,
	    20,	 226, 130, 248, 125, 209, 113, 19,  218, 94,  219, 32,	165,
	    165, 171, 219, 144, 178, 166, 189, 154, 87,	 27,  79,  196, 215,
	    154, 204, 59,  158, 98,  124, 174, 172, 123, 15,  15,  131, 83,
	    253, 118, 79,  10,	220, 67,  233, 195, 19,	 149, 15,  105, 20,
	    146, 39,  191, 181, 170, 164, 201, 209, 84,	 223, 124, 120, 182,
	    105, 17,  163, 100, 131, 210, 178, 106, 66,	 182, 131, 145, 235,
	    228, 153, 131, 90,	236, 100, 150, 192, 188, 184, 136, 112, 102,
	    38,	 84,  216, 25,	14,  246, 15,  231, 144, 85,  189, 247, 184,
	    215, 193, 232, 176, 190, 220, 207, 47,  75,	 26,  105, 124, 201,
	    126, 101, 120, 21,	153, 39,  180, 27,  243, 82,  195, 219, 129,
	    82,	 2,   67,  215, 239, 14,  22,  204, 136, 168, 186, 185, 92,
	    123, 204, 252, 67,	144, 252, 165, 149, 49,	 148, 209, 244, 121,
	    203, 253, 77,  53,	238, 255, 90,  99,  188, 108, 46,  173, 89,
	    175, 147, 21,  101, 173, 131, 215, 95,  130, 158, 90,  93,	59,
	    180, 47,  13,  137, 196, 226, 232, 20,  40,	 127, 152, 171, 90,
	    20,	 77,  120, 213, 33,  93,  201, 167, 184, 154, 251, 49,	153,
	    200, 142, 244, 152, 203, 76,  166, 18,  199, 27,  69,  198, 219,
	    146, 69,  240, 212, 68,  219, 184, 172, 185, 7,   146, 79,	21,
	    232, 84,  233, 228, 63,  115, 98,  213, 88,	 102, 23,  31,	87,
	    176, 182, 37,  206, 141, 191, 213, 104, 160, 76,  48,  99,	38,
	    49,	 96,  166, 105, 182, 46,  105, 148, 255, 196, 209, 166, 108,
	    251, 123, 56,  23,	239, 141, 67,  236, 144, 106, 54,  167, 188,
	    45,	 201, 175, 223, 119, 95,  118, 25,  78,	 10,  222, 214, 8,
	    60,	 237, 73,  89,	42,  101, 59,  230, 75,	 229, 156, 89,	71,
	    203, 87,  178, 43,	237, 37,  149, 72,  235, 199, 161, 239, 107,
	    37,	 162, 1,   227, 196, 98,  169, 216, 146, 70,  149, 216, 26,
	    162, 120, 34,  10,	47,  192, 46,  219, 1,	 58,  78,  86,	154,
	    103, 108, 249, 233, 232, 21,  248, 214, 19,	 178, 203, 84,	84,
	    171, 217, 54,  168, 19,  15,  149, 119, 92,	 123, 190, 125, 129,
	    56,	 7,   139, 147, 190, 179, 119, 70,  74,	 40,  71,  28,	144,
	    120, 60,  42,  126, 148, 92,  206, 134, 149, 30,  20,  56,	143,
	    23,	 92,  196, 40,	117, 218, 56,  189, 249, 9,   224, 64,	134,
	    215, 193, 185, 146, 115, 110, 18,  44,  45,	 90,  116, 150, 211,
	    40,	 152, 34,  166, 57,  185, 49,  195, 251, 76,  85,  4,	135,
	    183, 115, 136, 158, 185, 147, 129, 247, 204, 150, 65,  169, 3,
	    46,	 197, 153, 203, 72,  137, 81,  183, 61,	 175, 98,  208, 35,
	    37,	 94,  111, 19,	239, 167, 35,  90,  66,	 7,   117, 185, 39,
	    138, 150, 224, 144, 99,  153, 195, 203, 21,	 74,  157, 112, 207,
	    190, 151, 249, 114, 79,  236, 41,  15,  64,	 88,  91,  158, 168,
	    130, 100, 10,  182, 249, 99,  123, 27,  4,	 29,  140, 33,	38,
	    241, 228, 46,  113, 194, 244, 146, 125, 72,	 111, 85,  146, 33,
	    101, 37,  95,  122, 49,  122, 15,  72,  208, 116, 139, 30,	225,
	    50,	 161, 19,  135, 59,  238, 184, 8,   235, 48,  45,  181, 163,
	    248, 142, 80,  183, 204, 216, 228, 12,  3,	 29,  126, 203, 12,
	    66,	 233, 108, 142, 151, 54,  13,  192, 240, 89,  152, 73,	10,
	    205, 33,  65,  109, 254, 181, 47,  185, 43,	 38,  4,   235, 146,
	    76,	 57,  77,  179, 176, 145, 250, 44,  139, 71,  22,  10,	168,
	    221, 252, 231, 223, 220, 23,  42,  62,  63,	 237, 237, 12,	239,
	    246, 194, 246, 125, 157, 108, 8,   238, 225, 146, 79,  12,	190,
	    210, 50,  199, 61,	62,  82,  113, 218, 6,	 160, 66,  17,	181,
	    255, 248, 153, 69,	92,  151, 138, 27,  32,	 150, 60,  101, 167,
	    30,	 46,  21,  246, 234, 116, 252, 50,  61,	 2,   7,   9,	18,
	    43,	 52,  60,  85,	90,  166, 202, 210, 223, 229, 235, 253, 11,
	    47,	 55,  86,  99,	106, 109, 117, 122, 137, 144, 166, 213, 240,
	    247, 7,   41,  44,	68,  125, 126, 133, 156, 159, 162, 190, 192,
	    202, 5,   21,  32,	36,  41,  72,  79,  143, 156, 161, 165, 179,
	    187, 202, 246, 255, 0,   0,	  0,   0,   0,	 0,   0,   0,	0,
	    0,	 0,   0,   0,	0,   0,	  0,   0,   0,	 0,   0,   16,	31,
	    44,	 60,  0,   0,	0,   0,	  0,   0,   0,	 0,   0,   0,	0,
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

