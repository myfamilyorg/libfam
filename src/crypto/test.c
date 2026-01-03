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

#include <libfam/format.h>

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

	u8 expected[32] = {40,	192, 31,  210, 152, 82,	 145, 102,
			   194, 227, 178, 224, 202, 241, 248, 191,
			   165, 179, 57,  163, 186, 229, 192, 232,
			   14,	212, 35,  226, 77,  15,	 127, 228};

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

	ASSERT_EQ(nonce, 104304, "nonce");
	ASSERT(!memcmp(output,
		       (u8[]){0,  0,   226, 113, 61,  60,  155, 26, 6,	0,   39,
			      37, 162, 57,  14,	 240, 107, 211, 72, 1,	176, 36,
			      78, 164, 241, 22,	 173, 150, 17,	52, 71, 242},
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
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ", sk.data[i]);
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
	// for (u32 i = 0; i < sizeof(ct); i++) print("{}, ", ct.data[i]);
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
