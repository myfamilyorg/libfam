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

#include <kyber/kem.h>
#include <libfam/aighthash.h>
#include <libfam/bible.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/test_base.h>
#include <libfam/wots.h>

Test(storm_vectors) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    9,	 93,  216, 137, 224, 212, 105, 200, 163, 28,  146,
	    246, 75,  164, 149, 109, 209, 70,  183, 116, 224, 157,
	    245, 221, 5,   53,	245, 155, 165, 135, 142, 218};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf1);

	u8 exp1[32] = {204, 193, 116, 178, 204, 191, 250, 240, 24,  241, 23,
		       185, 255, 250, 66,  221, 100, 77,  187, 202, 221, 228,
		       223, 20,	 106, 134, 78,	38,  178, 172, 110, 153};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {104, 232, 235, 200, 225, 117, 15,  17,  193, 182, 235,
		       70,  96,	 116, 156, 217, 123, 199, 27,  10,  131, 152,
		       172, 145, 79,  14,  208, 70,  27,  207, 59,  211};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf2);

	u8 exp3[32] = {140, 187, 82,  252, 180, 187, 246, 27,  94,  60, 140,
		       8,   58,	 82,  23,  211, 56,  168, 6,   16,  22, 181,
		       32,  164, 138, 211, 201, 50,  77,  254, 156, 40};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm_next_block(&ctx, buf2);

	u8 exp4[32] = {115, 33,	 96,  112, 88, 80, 97, 17,  236, 164, 249,
		       136, 197, 55,  160, 85, 30, 92, 154, 49,	 11,  80,
		       164, 112, 126, 77,  25, 42, 22, 18,  14,	 15};
	ASSERT(!memcmp(buf2, exp4, sizeof(buf2)), "buf2 round2");
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
	    92,	 76,  15, 74,  85,  157, 30,  92,  90,	59,  107, 147, 160,
	    157, 236, 35, 0,   42,  84,	 59,  133, 69,	15,  170, 206, 78,
	    49,	 164, 66, 231, 142, 24,	 73,  51,  97,	88,  100, 70,  102,
	    247, 191, 91, 118, 240, 16,	 238, 24,  105, 171, 108, 133, 166,
	    87,	 105, 86, 214, 101, 23,	 209, 144, 254, 12,  116, 246};
	ASSERT_EQ(memcmp(z, expected, 64), 0, "z");
}

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

#define WOTS_COUNT 100

Test(wots_perf) {
	__attribute__((aligned(32))) u8 key[32] = {1, 2, 3, 4, 5};
	WotsPubKey pk;
	WotsSecKey sk;
	WotsSig sig;
	u8 msg[32] = {9, 9, 9, 9, 9, 4};

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

	(void)keygen_sum;
	(void)sign_sum;
	(void)verify_sum;

	/*
	println("keygen={},sign={},verify={}", keygen_sum / WOTS_COUNT,
		sign_sum / WOTS_COUNT, verify_sum / WOTS_COUNT);
		*/
}

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

	u8 expected[32] = {155, 115, 44,  19,  62,  253, 241, 244,
			   190, 79,  245, 217, 85,  195, 38,  108,
			   244, 44,  203, 158, 122, 32,	 229, 32,
			   56,	172, 212, 236, 89,  111, 233, 183};

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

	ASSERT_EQ(nonce, 34264, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	30, 233, 156, 138, 107, 143,
				      57,  175, 10, 239, 101, 30,  32,	154,
				      249, 219, 21, 189, 4,   220, 79,	104,
				      144, 104, 71, 40,	 223, 159, 75,	174},
		       32),
	       "hash");
	bible_destroy(b);
}

Test(kyber) {
	__attribute__((aligned(32))) u8 sk[KYBER_SECRETKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 pk[KYBER_PUBLICKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 ct[KYBER_CIPHERTEXTBYTES] = {0};
	__attribute__((aligned(32))) u8 ss_bob[KYBER_SSBYTES] = {0};
	__attribute__((aligned(32))) u8 ss_alice[KYBER_SSBYTES] = {1};

	Rng rng1, rng2;
	rng_init(&rng1);
	rng_init(&rng2);
	kem_keypair(pk, sk, &rng1);
	kem_enc(ct, ss_bob, pk, &rng2);
	kem_dec(ss_alice, ct, sk);
	ASSERT(!fastmemcmp(ss_bob, ss_alice, KYBER_SSBYTES), "shared secret");
}

#define KYBER_COUNT 100

Test(kyber_perf) {
	__attribute__((aligned(32))) u8 sk[KYBER_SECRETKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 pk[KYBER_PUBLICKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 ct[KYBER_CIPHERTEXTBYTES] = {0};
	__attribute__((aligned(32))) u8 ss_bob[KYBER_SSBYTES] = {0};
	__attribute__((aligned(32))) u8 ss_alice[KYBER_SSBYTES] = {1};
	Rng rng1, rng2;
	u64 keygen_sum = 0;
	u64 enc_sum = 0;
	u64 dec_sum = 0;

	for (u32 i = 0; i < KYBER_COUNT; i++) {
		rng_init(&rng1);
		rng_init(&rng2);
		u64 start = cycle_counter();
		kem_keypair(pk, sk, &rng1);
		keygen_sum += cycle_counter() - start;
		start = cycle_counter();
		kem_enc(ct, ss_bob, pk, &rng2);
		enc_sum += cycle_counter() - start;
		start = cycle_counter();
		kem_dec(ss_alice, ct, sk);
		dec_sum += cycle_counter() - start;
		ASSERT(!fastmemcmp(ss_bob, ss_alice, KYBER_SSBYTES),
		       "shared secret");
	}

	(void)keygen_sum;
	(void)enc_sum;
	(void)dec_sum;

	/*
	println("keygen={},enc={},dec={}", keygen_sum / KYBER_COUNT,
		enc_sum / KYBER_COUNT, dec_sum / KYBER_COUNT);
		*/
}

