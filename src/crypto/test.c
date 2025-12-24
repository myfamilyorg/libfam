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

#include <libfam/aighthash.h>
#include <libfam/bible.h>
#include <libfam/env.h>
#include <libfam/kem.h>
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

	u8 exp1[32] = {0,   44, 64, 186, 106, 113, 172, 78,  14,  234, 67,
		       247, 7,	57, 25,	 97,  57,  105, 29,  115, 159, 138,
		       37,  57, 65, 176, 12,  144, 174, 186, 4,	  236};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {210, 174, 13,  100, 187, 212, 168, 128, 197, 235, 213,
		       78,  125, 115, 205, 92,	133, 242, 110, 234, 125, 133,
		       168, 230, 240, 252, 10,	168, 89,  227, 74,  62};

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

	u8 exp4[32] = {162, 251, 154, 18,  139, 107, 17,  243, 220, 138, 196,
		       181, 69,	 163, 85,  123, 226, 16,  149, 98,  13,	 154,
		       218, 24,	 241, 200, 137, 0,   247, 150, 246, 123};
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
	u8 expected2[32] = {161, 153, 144, 19,	202, 43,  81,  154,
			    83,	 150, 76,  209, 103, 85,  1,   74,
			    116, 231, 230, 62,	23,  126, 208, 173,
			    13,	 252, 88,  139, 176, 20,  42,  167};
	ASSERT(!memcmp(buffer2, expected2, 32), "expected2");
}

#define STORM_COUNT (1000000000 / 32)
static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};
static __attribute__((aligned(32))) u8 ONE_SEED[32] = {1};
static __attribute__((aligned(32))) u8 TWO_SEED[32] = {2};
static __attribute__((aligned(32))) u8 THREE_SEED[32] = {3};
static __attribute__((aligned(32))) u8 FOUR_SEED[32] = {4};
static __attribute__((aligned(32))) u8 FIVE_SEED[32] = {5};

Bench(storm) {
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

	pwrite(2, "time=", 5, 0);
	write_num(2, timer);
	pwrite(2, ",avg=", 5, 0);
	write_num(2, (timer * 1000) / STORM_COUNT);
	pwrite(2, "ns\n", 3, 0);
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
	    175, 6,   181, 187, 130, 62,  195, 118, 94,	 242, 150, 45,	156,
	    18,	 240, 207, 220, 197, 36,  154, 149, 82,	 140, 108, 33,	154,
	    30,	 22,  146, 169, 199, 72,  2,   124, 117, 60,  141, 191};
	ASSERT_EQ(memcmp(z, expected, 64), 0, "z");
}

#define RNG_BYTES (32 * 1000000ULL)

Bench(rngpf) {
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

	u8 expected[32] = {161, 219, 95,  165, 143, 81,	 8,  96,  175, 215, 101,
			   246, 130, 254, 99,  17,  61,	 84, 7,	  110, 157, 128,
			   179, 165, 67,  64,  193, 247, 70, 100, 54,  146};

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

	ASSERT_EQ(nonce, 1312, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	28,  44,  170, 182, 139, 188,
				      55,  146, 148, 53,  14,  68,  79,	 182,
				      130, 246, 76,  17,  102, 240, 129, 186,
				      69,  227, 176, 231, 224, 33,  141, 0},
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
	// print("sk: ");
	// for (u32 i = 0; i < sizeof(sk); i++) print("{}, ", sk.data[i]);
	u8 expected_sk[] = {
	    202, 229, 135, 92,	120, 95,  253, 244, 120, 162, 199, 89,	92,
	    83,	 144, 199, 84,	18,  120, 133, 66,  88,	 68,  172, 152, 172,
	    196, 82,  66,  207, 252, 128, 32,  39,  23,	 65,  152, 124, 157,
	    116, 20,  123, 113, 122, 120, 88,  17,  31,	 221, 57,  148, 35,
	    160, 91,  197, 160, 126, 63,  218, 111, 69,	 210, 31,  11,	26,
	    63,	 241, 115, 83,	62,  231, 186, 165, 100, 188, 95,  204, 59,
	    225, 92,  48,  180, 136, 44,  118, 96,  23,	 208, 108, 53,	36,
	    249, 151, 191, 136, 20,  67,  64,  77,  78,	 0,   106, 9,	129,
	    202, 62,  199, 171, 86,  226, 193, 53,  154, 44,  167, 44,	111,
	    81,	 156, 137, 12,	24,  40,  169, 119, 100, 219, 204, 192, 33,
	    70,	 156, 210, 33,	129, 207, 161, 78,  111, 36,  147, 9,	176,
	    25,	 36,  137, 152, 80,  99,  207, 70,  116, 165, 69,  86,	175,
	    8,	 69,  196, 238, 25,  62,  99,  68,  181, 63,  133, 196, 155,
	    119, 186, 158, 42,	169, 58,  99,  190, 183, 203, 182, 99,	90,
	    179, 161, 35,  58,	75,  90,  20,  12,  11,	 96,  61,  240, 111,
	    92,	 98,  204, 40,	11,  198, 41,  4,   0,	 238, 100, 95,	129,
	    133, 91,  51,  138, 36,  204, 67,  204, 75,	 104, 52,  106, 145,
	    83,	 78,  218, 152, 96,  212, 58,  173, 234, 13,  239, 91,	66,
	    168, 177, 24,  126, 160, 170, 254, 88,  152, 20,  64,  160, 60,
	    171, 182, 166, 27,	205, 135, 132, 44,  107, 4,   174, 235, 136,
	    197, 45,  76,  172, 132, 57,  121, 26,  114, 10,  16,  138, 80,
	    58,	 186, 4,   19,	194, 44,  239, 103, 111, 65,  51,  54,	210,
	    121, 49,  22,  27,	118, 243, 133, 18,  140, 181, 99,  100, 81,
	    139, 131, 42,  8,	204, 236, 46,  10,  240, 111, 153, 186, 172,
	    73,	 166, 205, 125, 186, 166, 12,  12,  136, 163, 154, 162, 157,
	    116, 98,  54,  85,	58,  70,  211, 144, 175, 108, 97,  8,	17,
	    123, 247, 7,   87,	228, 200, 24,  120, 147, 167, 120, 70,	117,
	    201, 192, 143, 20,	38,  93,  192, 122, 36,	 11,  40,  117, 103,
	    101, 97,  199, 213, 57,  68,  229, 4,   136, 24,  182, 250, 6,
	    109, 220, 73,  21,	54,  146, 114, 185, 240, 47,  86,  214, 83,
	    3,	 169, 30,  209, 11,  101, 30,  44,  165, 106, 135, 189, 52,
	    80,	 157, 129, 82,	199, 154, 235, 38,  198, 8,   133, 56,	98,
	    25,	 43,  27,  166, 186, 153, 65,  124, 198, 32,  91,  198, 48,
	    22,	 87,  12,  250, 212, 186, 173, 212, 51,	 12,  245, 177, 247,
	    41,	 74,  48,  0,	180, 123, 87,  172, 162, 180, 34,  92,	26,
	    68,	 212, 227, 72,	20,  184, 9,   85,  166, 74,  232, 134, 112,
	    144, 252, 125, 55,	1,   184, 5,   101, 137, 106, 248, 166, 213,
	    247, 43,  191, 118, 38,  234, 218, 135, 118, 188, 113, 214, 72,
	    44,	 122, 117, 192, 23,  132, 113, 83,  71,	 197, 158, 9,	113,
	    0,	 101, 61,  132, 32,  105, 204, 11,  47,	 6,   58,  120, 132,
	    75,	 114, 207, 212, 40,  255, 16,  147, 243, 172, 115, 97,	1,
	    130, 101, 216, 90,	194, 70,  118, 133, 182, 30,  14,  227, 17,
	    50,	 216, 88,  146, 115, 3,	  126, 209, 52,	 226, 140, 111, 227,
	    70,	 82,  26,  50,	67,  73,  187, 196, 152, 51,  126, 12,	180,
	    200, 89,  4,   58,	167, 69,  98,  45,  202, 207, 244, 140, 71,
	    176, 76,  2,   43,	145, 77,  105, 228, 199, 37,  164, 111, 99,
	    88,	 17,  95,  55,	166, 182, 55,  129, 133, 49,  12,  58,	83,
	    41,	 115, 44,  136, 146, 194, 176, 103, 122, 17,  10,  187, 5,
	    60,	 1,   54,  232, 70,  27,  156, 200, 193, 228, 195, 47,	215,
	    250, 117, 114, 44,	207, 76,  56,  132, 213, 0,   71,  30,	240,
	    75,	 128, 197, 116, 106, 67,  120, 239, 10,	 194, 4,   182, 81,
	    120, 91,  169, 122, 108, 161, 96,  183, 85,	 228, 92,  178, 59,
	    181, 46,  113, 150, 22,  191, 6,   108, 194, 204, 43,  247, 27,
	    74,	 112, 116, 29,	48,  116, 126, 95,  80,	 59,  212, 164, 24,
	    126, 59,  19,  195, 104, 92,  27,  169, 149, 27,  122, 8,	194,
	    242, 21,  52,  184, 113, 161, 216, 55,  34,	 250, 84,  219, 85,
	    104, 128, 8,   5,	16,  154, 44,  67,  25,	 138, 220, 164, 130,
	    139, 130, 90,  37,	10,  190, 70,  231, 86,	 143, 216, 78,	145,
	    51,	 10,  152, 65,	134, 82,  233, 168, 134, 73,  88,  80,	91,
	    173, 120, 4,   147, 238, 170, 192, 146, 123, 140, 71,  219, 107,
	    53,	 186, 100, 193, 91,  188, 227, 86,  28,	 153, 41,  115, 15,
	    170, 58,  123, 115, 126, 57,  25,  175, 187, 211, 26,  35,	92,
	    101, 84,  167, 188, 78,  224, 0,   115, 232, 166, 213, 186, 189,
	    164, 163, 176, 25,	74,  13,  182, 151, 60,	 99,  108, 141, 132,
	    68,	 72,  80,  169, 113, 247, 28,  207, 255, 139, 31,  241, 90,
	    119, 60,  115, 178, 92,  200, 41,  54,  9,	 22,  211, 76,	132,
	    133, 183, 45,  52,	146, 182, 121, 38,  118, 105, 133, 157, 54,
	    192, 94,  0,   102, 153, 124, 140, 140, 106, 70,  134, 243, 178,
	    5,	 190, 35,  136, 244, 118, 129, 63,  192, 196, 252, 42,	202,
	    253, 209, 27,  49,	248, 195, 82,  35,  125, 8,   41,  69,	191,
	    80,	 7,   184, 148, 78,  68,  27,  56,  187, 233, 57,  88,	162,
	    5,	 145, 129, 32,	82,  144, 156, 190, 12,	 189, 32,  156, 178,
	    199, 6,   9,   76,	64,  125, 246, 236, 58,	 244, 178, 139, 184,
	    83,	 86,  10,  18,	41,  169, 178, 175, 175, 113, 148, 172, 163,
	    57,	 38,  170, 186, 41,  148, 40,  68,  172, 101, 13,  242, 41,
	    195, 102, 15,  156, 186, 4,	  13,  117, 2,	 86,  86,  50,	49,
	    99,	 53,  185, 8,	88,  8,	  145, 155, 75,	 144, 116, 62,	9,
	    32,	 109, 87,  32,	129, 35,  191, 136, 17,	 102, 67,  114, 157,
	    105, 154, 20,  137, 101, 38,  212, 192, 91,	 153, 165, 120, 83,
	    195, 36,  61,  132, 114, 63,  212, 37,  56,	 170, 57,  250, 168,
	    128, 224, 244, 104, 64,  87,  119, 1,   186, 167, 249, 71,	171,
	    166, 57,  53,  142, 54,  64,  4,   12,  59,	 237, 107, 119, 77,
	    184, 156, 132, 64,	31,  253, 201, 115, 166, 150, 102, 62,	163,
	    122, 81,  10,  63,	147, 204, 155, 234, 68,	 54,  68,  186, 26,
	    6,	 211, 12,  67,	104, 24,  83,  112, 132, 145, 155, 164, 116,
	    163, 111, 226, 38,	101, 231, 67,  18,  47,	 121, 105, 64,	228,
	    125, 225, 155, 59,	15,  226, 43,  221, 44,	 177, 52,  214, 35,
	    126, 6,   26,  183, 83,  188, 218, 195, 186, 36,  204, 157, 237,
	    7,	 95,  165, 135, 113, 117, 136, 159, 90,	 165, 47,  69,	233,
	    11,	 43,  151, 86,	8,   231, 167, 188, 164, 9,   149, 60,	69,
	    28,	 3,   71,  238, 162, 180, 182, 147, 155, 16,  39,  102, 60,
	    36,	 115, 20,  70,	161, 233, 179, 204, 19,	 228, 111, 224, 89,
	    107, 167, 123, 178, 119, 250, 130, 203, 184, 142, 132, 57,	138,
	    172, 105, 112, 155, 0,   79,  214, 231, 52,	 168, 0,   26,	254,
	    130, 106, 180, 193, 128, 234, 102, 136, 102, 193, 185, 72,	167,
	    197, 31,  236, 5,	254, 161, 22,  89,  104, 136, 138, 17,	28,
	    42,	 72,  58,  92,	92,  71,  44,  87,  43,	 151, 151, 95,	158,
	    59,	 109, 217, 72,	121, 157, 136, 169, 100, 65,  141, 35,	228,
	    80,	 7,   54,  194, 13,  150, 182, 221, 6,	 89,  217, 4,	79,
	    105, 50,  38,  54,	215, 69,  100, 137, 43,	 133, 113, 33,	58,
	    44,	 20,  249, 154, 112, 43,  2,   80,  238, 4,   49,  218, 85,
	    8,	 1,   242, 202, 219, 180, 88,  21,  35,	 93,  222, 104, 204,
	    184, 7,   101, 235, 201, 97,  34,  83,  176, 95,  115, 197, 228,
	    248, 46,  195, 168, 171, 135, 153, 71,  109, 131, 2,   192, 76,
	    69,	 199, 23,  207, 225, 168, 39,  162, 247, 53,  102, 52,	172,
	    13,	 231, 158, 144, 38,  72,  3,   3,   107, 38,  39,  59,	100,
	    184, 133, 182, 134, 73,  185, 64,  176, 111, 145, 48,  221, 251,
	    142, 72,  134, 32,	228, 149, 197, 19,  169, 118, 240, 66,	148,
	    115, 242, 177, 187, 48,  9,	  67,  2,   10,	 79,  244, 43,	134,
	    100, 67,  159, 23,	151, 163, 92,  163, 43,	 76,  126, 200, 17,
	    47,	 192, 117, 46,	95,  233, 194, 234, 68,	 61,  162, 43,	171,
	    181, 184, 111, 123, 124, 113, 135, 201, 126, 21,  38,  194, 121,
	    36,	 195, 219, 102, 123, 90,  149, 84,  81,	 53,  8,   149, 131,
	    62,	 252, 70,  101, 198, 235, 59,  149, 2,	 11,  27,  107, 133,
	    119, 24,  10,  125, 185, 142, 112, 145, 73,	 126, 71,  92,	226,
	    163, 188, 213, 2,	13,  103, 130, 42,  108, 216, 196, 89,	57,
	    66,	 46,  88,  22,	22,  69,  190, 99,  74,	 78,  12,  25,	28,
	    131, 83,  16,  102, 82,  3,	  94,  8,   154, 198, 84,  34,	232,
	    232, 135, 250, 30,	19,  136, 6,   35,  19,	 153, 114, 61,	42,
	    183, 70,  185, 223, 50,  0,	  13,  111, 183, 61,  118, 47,	189,
	    227, 89,  26,  152, 245, 247, 226, 81,  85,	 6,   199, 1,	227,
	    233, 103, 186, 32,	208, 231, 199, 24,  42,	 19,  65,  33,	70,
	    23,	 225, 220, 21,	217, 136, 79,  217, 89,	 156, 129, 66,	24,
	    77,	 175, 242, 27,	187, 98,  87,  212, 220, 169, 50,  128, 55,
	    38,	 100, 170, 60,	13,  170, 233, 101, 210, 192, 153, 214, 142,
	    115, 99,  39,  49,	106, 123, 15};

	u8 expected_pk[] = {
	    120, 4,   147, 238, 170, 192, 146, 123, 140, 71,  219, 107, 53,
	    186, 100, 193, 91,	188, 227, 86,  28,  153, 41,  115, 15,	170,
	    58,	 123, 115, 126, 57,  25,  175, 187, 211, 26,  35,  92,	101,
	    84,	 167, 188, 78,	224, 0,	  115, 232, 166, 213, 186, 189, 164,
	    163, 176, 25,  74,	13,  182, 151, 60,  99,	 108, 141, 132, 68,
	    72,	 80,  169, 113, 247, 28,  207, 255, 139, 31,  241, 90,	119,
	    60,	 115, 178, 92,	200, 41,  54,  9,   22,	 211, 76,  132, 133,
	    183, 45,  52,  146, 182, 121, 38,  118, 105, 133, 157, 54,	192,
	    94,	 0,   102, 153, 124, 140, 140, 106, 70,	 134, 243, 178, 5,
	    190, 35,  136, 244, 118, 129, 63,  192, 196, 252, 42,  202, 253,
	    209, 27,  49,  248, 195, 82,  35,  125, 8,	 41,  69,  191, 80,
	    7,	 184, 148, 78,	68,  27,  56,  187, 233, 57,  88,  162, 5,
	    145, 129, 32,  82,	144, 156, 190, 12,  189, 32,  156, 178, 199,
	    6,	 9,   76,  64,	125, 246, 236, 58,  244, 178, 139, 184, 83,
	    86,	 10,  18,  41,	169, 178, 175, 175, 113, 148, 172, 163, 57,
	    38,	 170, 186, 41,	148, 40,  68,  172, 101, 13,  242, 41,	195,
	    102, 15,  156, 186, 4,   13,  117, 2,   86,	 86,  50,  49,	99,
	    53,	 185, 8,   88,	8,   145, 155, 75,  144, 116, 62,  9,	32,
	    109, 87,  32,  129, 35,  191, 136, 17,  102, 67,  114, 157, 105,
	    154, 20,  137, 101, 38,  212, 192, 91,  153, 165, 120, 83,	195,
	    36,	 61,  132, 114, 63,  212, 37,  56,  170, 57,  250, 168, 128,
	    224, 244, 104, 64,	87,  119, 1,   186, 167, 249, 71,  171, 166,
	    57,	 53,  142, 54,	64,  4,	  12,  59,  237, 107, 119, 77,	184,
	    156, 132, 64,  31,	253, 201, 115, 166, 150, 102, 62,  163, 122,
	    81,	 10,  63,  147, 204, 155, 234, 68,  54,	 68,  186, 26,	6,
	    211, 12,  67,  104, 24,  83,  112, 132, 145, 155, 164, 116, 163,
	    111, 226, 38,  101, 231, 67,  18,  47,  121, 105, 64,  228, 125,
	    225, 155, 59,  15,	226, 43,  221, 44,  177, 52,  214, 35,	126,
	    6,	 26,  183, 83,	188, 218, 195, 186, 36,	 204, 157, 237, 7,
	    95,	 165, 135, 113, 117, 136, 159, 90,  165, 47,  69,  233, 11,
	    43,	 151, 86,  8,	231, 167, 188, 164, 9,	 149, 60,  69,	28,
	    3,	 71,  238, 162, 180, 182, 147, 155, 16,	 39,  102, 60,	36,
	    115, 20,  70,  161, 233, 179, 204, 19,  228, 111, 224, 89,	107,
	    167, 123, 178, 119, 250, 130, 203, 184, 142, 132, 57,  138, 172,
	    105, 112, 155, 0,	79,  214, 231, 52,  168, 0,   26,  254, 130,
	    106, 180, 193, 128, 234, 102, 136, 102, 193, 185, 72,  167, 197,
	    31,	 236, 5,   254, 161, 22,  89,  104, 136, 138, 17,  28,	42,
	    72,	 58,  92,  92,	71,  44,  87,  43,  151, 151, 95,  158, 59,
	    109, 217, 72,  121, 157, 136, 169, 100, 65,	 141, 35,  228, 80,
	    7,	 54,  194, 13,	150, 182, 221, 6,   89,	 217, 4,   79,	105,
	    50,	 38,  54,  215, 69,  100, 137, 43,  133, 113, 33,  58,	44,
	    20,	 249, 154, 112, 43,  2,	  80,  238, 4,	 49,  218, 85,	8,
	    1,	 242, 202, 219, 180, 88,  21,  35,  93,	 222, 104, 204, 184,
	    7,	 101, 235, 201, 97,  34,  83,  176, 95,	 115, 197, 228, 248,
	    46,	 195, 168, 171, 135, 153, 71,  109, 131, 2,   192, 76,	69,
	    199, 23,  207, 225, 168, 39,  162, 247, 53,	 102, 52,  172, 13,
	    231, 158, 144, 38,	72,  3,	  3,   107, 38,	 39,  59,  100, 184,
	    133, 182, 134, 73,	185, 64,  176, 111, 145, 48,  221, 251, 142,
	    72,	 134, 32,  228, 149, 197, 19,  169, 118, 240, 66,  148, 115,
	    242, 177, 187, 48,	9,   67,  2,   10,  79,	 244, 43,  134, 100,
	    67,	 159, 23,  151, 163, 92,  163, 43,  76,	 126, 200, 17,	47,
	    192, 117, 46,  95,	233, 194, 234, 68,  61,	 162, 43,  171, 181,
	    184, 111, 123, 124, 113, 135, 201, 126, 21,	 38,  194, 121, 36,
	    195, 219, 102, 123, 90,  149, 84,  81,  53,	 8,   149, 131, 62,
	    252, 70,  101, 198, 235, 59,  149, 2,   11,	 27,  107, 133, 119,
	    24,	 10,  125, 185, 142, 112, 145, 73,  126, 71,  92,  226, 163,
	    188, 213, 2,   13,	103, 130, 42,  108, 216, 196, 89,  57,	66,
	    46,	 88,  22,  22,	69,  190, 99,  74,  78,	 12,  25,  28,	131,
	    83,	 16,  102, 82,	3,   94,  8,   154, 198, 84,  34,  232, 232,
	    135, 250, 30,  19,	136, 6,	  35,  19,  153, 114, 61,  42,	183,
	    70,	 185, 223, 50,	0,   13,  111, 183, 61,	 118, 47,  189, 227,
	    89,	 26,  152, 245, 247, 226, 81};
	ASSERT(!fastmemcmp(pk.data, expected_pk, sizeof(pk)), "pk");
	ASSERT(!fastmemcmp(sk.data, expected_sk, sizeof(sk)), "sk");
	enc(&ct, &ss_bob, &pk, &rng);
	u8 expected_ct[] = {
	    250, 29,  73,  173, 157, 227, 145, 17,  107, 179, 113, 61,	207,
	    204, 116, 32,  149, 121, 88,  166, 209, 4,	 74,  208, 114, 42,
	    8,	 15,  132, 71,	108, 190, 4,   137, 4,	 149, 234, 88,	180,
	    53,	 128, 113, 174, 164, 1,	  38,  194, 241, 26,  183, 112, 99,
	    192, 57,  142, 214, 109, 72,  80,  103, 209, 157, 181, 26,	15,
	    78,	 87,  53,  201, 121, 50,  214, 62,  217, 247, 15,  71,	87,
	    194, 196, 55,  87,	96,  127, 77,  103, 20,	 92,  10,  87,	215,
	    97,	 132, 209, 174, 175, 20,  192, 185, 78,	 198, 151, 201, 218,
	    0,	 151, 175, 73,	133, 116, 226, 154, 42,	 148, 225, 206, 110,
	    43,	 36,  168, 119, 81,  105, 208, 130, 75,	 223, 121, 230, 119,
	    213, 41,  2,   92,	47,  236, 72,  26,  136, 67,  211, 74,	202,
	    176, 77,  73,  195, 75,  26,  151, 114, 132, 8,   4,   205, 144,
	    198, 217, 155, 38,	115, 82,  3,   162, 148, 91,  162, 61,	252,
	    140, 202, 192, 45,	124, 59,  137, 98,  121, 12,  104, 177, 172,
	    76,	 168, 212, 151, 38,  16,  141, 232, 76,	 107, 223, 13,	251,
	    50,	 36,  36,  169, 225, 51,  228, 115, 80,	 243, 108, 202, 184,
	    108, 254, 230, 83,	138, 19,  154, 107, 122, 126, 225, 7,	249,
	    166, 234, 130, 221, 42,  117, 56,  219, 79,	 13,  108, 86,	59,
	    5,	 39,  137, 86,	121, 100, 74,  215, 96,	 57,  4,   193, 17,
	    40,	 44,  250, 123, 176, 212, 52,  241, 185, 65,  217, 101, 191,
	    37,	 102, 161, 224, 90,  160, 145, 132, 139, 167, 9,   159, 117,
	    246, 223, 187, 166, 84,  151, 126, 237, 89,	 10,  62,  67,	133,
	    78,	 43,  53,  34,	248, 240, 22,  214, 42,	 101, 25,  49,	41,
	    121, 206, 43,  132, 190, 10,  57,  17,  136, 34,  229, 136, 162,
	    25,	 194, 127, 113, 171, 244, 179, 30,  33,	 196, 122, 199, 144,
	    100, 56,  146, 224, 61,  156, 247, 126, 35,	 9,   165, 139, 54,
	    232, 194, 94,  92,	163, 8,	  156, 154, 67,	 132, 47,  153, 198,
	    117, 235, 176, 17,	148, 152, 11,  54,  175, 251, 19,  211, 138,
	    35,	 123, 58,  146, 179, 174, 154, 54,  199, 142, 232, 148, 56,
	    13,	 33,  76,  157, 102, 228, 11,  65,  128, 224, 191, 193, 185,
	    136, 150, 220, 249, 208, 110, 111, 184, 203, 112, 202, 252, 83,
	    49,	 108, 182, 63,	18,  148, 34,  69,  53,	 58,  188, 206, 191,
	    29,	 28,  121, 35,	22,  128, 166, 56,  215, 118, 153, 116, 212,
	    255, 38,  128, 183, 88,  187, 149, 106, 23,	 152, 122, 162, 145,
	    242, 180, 180, 56,	56,  34,  75,  130, 18,	 104, 32,  233, 181,
	    232, 3,   19,  47,	11,  39,  118, 83,  141, 224, 6,   61,	34,
	    181, 190, 74,  132, 103, 190, 80,  234, 12,	 211, 109, 187, 183,
	    251, 125, 102, 111, 201, 70,  109, 3,   6,	 203, 62,  96,	110,
	    122, 193, 248, 109, 72,  46,  88,  167, 45,	 70,  25,  128, 253,
	    136, 154, 160, 81,	13,  20,  33,  66,  230, 27,  166, 56,	210,
	    27,	 152, 22,  169, 129, 125, 90,  11,  67,	 14,  70,  222, 43,
	    215, 117, 110, 39,	213, 215, 143, 45,  205, 167, 116, 107, 161,
	    17,	 144, 12,  141, 146, 13,  41,  96,  77,	 146, 40,  194, 153,
	    188, 85,  105, 198, 161, 74,  110, 55,  183, 71,  233, 255, 110,
	    71,	 86,  234, 84,	18,  189, 165, 45,  172, 10,  107, 183, 185,
	    144, 123, 215, 144, 33,  14,  127, 22,  209, 49,  98,  233, 33,
	    85,	 225, 247, 5,	47,  250, 248, 215, 74,	 151, 131, 101, 253,
	    45,	 232, 20,  43,	65,  16,  127, 154, 142, 74,  142, 231, 134,
	    49,	 219, 192, 0,	187, 57,  32,  72,  239, 118, 210, 64,	105,
	    254, 43,  32,  5,	26,  81,  179, 243, 114, 229, 105, 252, 181,
	    20,	 114, 204, 34,	184, 186, 11,  137, 1,	 3,   92,  201, 152,
	    197, 103, 99,  94,	37,  45,  241, 50,  255, 43,  152, 240, 27,
	    185, 78,  32,  137, 99,  156, 130, 148, 16,	 77,  27,  189, 30,
	    101, 81,  54,  174, 68,  54,  12,  240, 208, 7,   97,  196, 190,
	    73,	 27,  224, 73,	30,  225, 35,  100, 132, 190, 249, 46,	182,
	    71,	 153, 51,  170, 151, 117, 97,  232, 93,	 88,  106, 194, 113,
	    123, 182, 78,  30,	18,  124, 228, 132, 107, 202, 225, 30,	175,
	    113, 138, 158, 42,	213, 138, 96,  182, 60,	 239, 98,  80,	37,
	    187, 62,  3,   187, 102, 211, 189, 117, 235, 75,  80,  231, 149,
	    82};
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
	u8 expected[32] = {99,	59,  179, 2,   225, 204, 225, 2,  50,  6,  184,
			   161, 135, 207, 99,  13,  230, 127, 34, 221, 32, 1,
			   129, 97,  104, 118, 247, 40,	 205, 99, 225, 184};

	ASSERT(!fastmemcmp(&ss_bob, expected, KEM_SS_SIZE), "expected");
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

#include <dilithium_scalar/sign.h>

#define MLEN 59
#define CTXLEN 14
#define NTESTS 100

Test(dilithium) {
	int ret;
	u64 mlen, smlen;
	u16 v = 0;
	u8 b = 0;
	__attribute__((aligned(32))) u8 ctx[CTXLEN] = {'t', 'e', 's', 't'};
	__attribute__((aligned(32))) u8 m[MLEN + CRYPTO_BYTES] = {0};
	__attribute__((aligned(32))) u8 m2[MLEN + CRYPTO_BYTES] = {0};
	__attribute__((aligned(32))) u8 sm[MLEN + CRYPTO_BYTES] = {0};
	__attribute__((aligned(32))) u8 pk[CRYPTO_PUBLICKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 sk[CRYPTO_SECRETKEYBYTES] = {0};
	Rng rng;

	for (u32 i = 0; i < NTESTS; i++) {
		rng_init(&rng);
		rng_gen(&rng, m, MLEN);

		crypto_sign_keypair(pk, sk);
		crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
		ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);

		ASSERT(!ret, "verify");
		ASSERT_EQ(smlen, MLEN + CRYPTO_BYTES, "smlen");
		ASSERT_EQ(mlen, MLEN, "mlen");
		ASSERT(!memcmp(m, m2, MLEN), "msg");

		rng_gen(&rng, &v, sizeof(v));
		rng_gen(&rng, &b, sizeof(b));
		v %= MLEN + CRYPTO_BYTES;
		sm[v] += 7;
		ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
		ASSERT(ret, "fail sig");
	}
}

