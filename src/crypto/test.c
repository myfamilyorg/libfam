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
		b = bible_gen(true);
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
	    173, 44,  4,   88,	170, 156, 109, 228, 56,	 148, 114, 39,	191,
	    106, 32,  172, 132, 210, 81,  200, 92,  19,	 98,  35,  63,	208,
	    66,	 86,  198, 149, 106, 179, 179, 131, 22,	 130, 83,  132, 147,
	    170, 151, 12,  103, 70,  234, 97,  106, 187, 171, 249, 5,	46,
	    184, 228, 191, 83,	151, 79,  74,  170, 151, 87,  203, 38,	183,
	    44,	 85,  41,  85,	25,  95,  180, 33,  7,	 64,  27,  16,	18,
	    164, 79,  243, 201, 68,  28,  33,  164, 168, 153, 93,  244, 11,
	    122, 152, 40,  116, 64,  116, 241, 59,  180, 234, 245, 183, 243,
	    196, 107, 120, 183, 161, 93,  60,  168, 121, 82,  195, 255, 68,
	    146, 85,  183, 185, 77,  65,  29,  52,  34,	 77,  150, 198, 33,
	    116, 213, 193, 70,	37,  175, 98,  8,   143, 147, 192, 156, 166,
	    145, 111, 131, 233, 85,  33,  26,  105, 250, 82,  159, 39,	73,
	    93,	 22,  55,  1,	27,  247, 163, 63,  145, 125, 198, 27,	42,
	    181, 37,  207, 90,	34,  120, 185, 43,  204, 161, 4,   30,	153,
	    92,	 14,  50,  184, 32,  44,  245, 53,  177, 240, 40,  89,	248,
	    67,	 14,  201, 142, 151, 202, 173, 55,  161, 162, 155, 128, 101,
	    243, 39,  80,  58,	36,  195, 99,  130, 54,	 235, 225, 183, 4,
	    58,	 192, 84,  23,	137, 51,  56,  85,  176, 102, 137, 217, 97,
	    19,	 211, 184, 139, 36,  60,  129, 255, 202, 62,  255, 57,	36,
	    103, 71,  121, 80,	178, 191, 196, 22,  90,	 133, 219, 171, 9,
	    209, 42,  246, 102, 153, 192, 176, 175, 176, 209, 188, 117, 103,
	    54,	 230, 132, 66,	219, 167, 179, 206, 41,	 129, 136, 198, 197,
	    153, 37,  92,  71,	73,  22,  190, 5,   177, 252, 149, 102, 222,
	    69,	 145, 215, 231, 13,  134, 139, 160, 63,	 17,  192, 79,	83,
	    41,	 201, 188, 42,	125, 150, 59,  159, 96,	 10,  31,  220, 30,
	    86,	 17,  41,  120, 180, 176, 88,  145, 111, 61,  107, 7,	22,
	    100, 47,  22,  165, 90,  219, 196, 118, 153, 100, 45,  175, 182,
	    156, 120, 49,  140, 116, 83,  86,  44,  69,	 144, 42,  107, 24,
	    133, 193, 31,  117, 153, 178, 67,  184, 124, 182, 0,   82,	145,
	    235, 160, 59,  130, 68,  230, 73,  116, 119, 133, 21,  107, 20,
	    207, 230, 134, 69,	243, 152, 99,  1,   17,	 176, 174, 5,	92,
	    200, 11,  86,  24,	209, 147, 86,  214, 165, 84,  122, 194, 21,
	    102, 187, 63,  154, 17,  21,  23,  56,  251, 209, 51,  51,	130,
	    31,	 253, 51,  118, 26,  162, 31,  75,  246, 56,  52,  27,	150,
	    23,	 67,  152, 53,	106, 81,  238, 197, 160, 99,  156, 124, 91,
	    160, 114, 87,  10,	202, 110, 194, 26,  73,	 76,  104, 69,	1,
	    77,	 161, 5,   102, 140, 198, 111, 9,   202, 187, 147, 40,	189,
	    242, 134, 45,  78,	240, 186, 224, 41,  15,	 252, 227, 78,	114,
	    0,	 146, 109, 186, 133, 147, 25,  145, 160, 247, 187, 207, 38,
	    43,	 165, 148, 83,	174, 12,  89,  134, 210, 13,  78,  234, 71,
	    89,	 58,  148, 229, 194, 113, 105, 164, 54,	 44,  1,   91,	30,
	    234, 15,  122, 122, 181, 172, 152, 80,  210, 236, 113, 38,	153,
	    47,	 47,  193, 3,	64,  9,	  64,  58,  80,	 11,  95,  233, 91,
	    150, 194, 8,   183, 75,  116, 242, 203, 163, 167, 20,  34,	204,
	    44,	 192, 57,  192, 167, 145, 102, 100, 214, 163, 22,  6,	35,
	    123, 13,  52,  132, 246, 165, 10,  209, 104, 50,  233, 85,	19,
	    148, 240, 191, 194, 234, 105, 244, 11,  170, 210, 144, 164, 120,
	    218, 114, 99,  231, 175, 85,  73,  187, 129, 198, 110, 80,	122,
	    6,	 214, 235, 103, 18,  228, 18,  232, 210, 146, 23,  12,	47,
	    83,	 138, 128, 11,	232, 12,  45,  65,  126, 33,  17,  157, 116,
	    210, 105, 48,  203, 54,  28,  40,  169, 32,	 74,  199, 140, 128,
	    106, 167, 12,  207, 23,  250, 134, 28,  2,	 171, 45,  51,	162,
	    138, 89,  43,  122, 99,  172, 134, 211, 159, 118, 248, 84,	1,
	    4,	 60,  41,  69,	20,  189, 226, 87,  209, 12,  64,  103, 10,
	    188, 107, 180, 114, 212, 204, 130, 72,  2,	 24,  220, 199, 195,
	    33,	 152, 33,  48,	252, 131, 73,  192, 169, 7,   65,  84,	190,
	    204, 65,  131, 10,	146, 229, 121, 144, 147, 56,  45,  68,	124,
	    61,	 96,  3,   36,	181, 98,  74,  96,  12,	 91,  76,  212, 115,
	    189, 234, 179, 217, 230, 162, 139, 102, 175, 58,  209, 60,	143,
	    101, 121, 250, 30,	19,  136, 6,   35,  19,	 153, 114, 61,	42,
	    183, 70,  185, 223, 50,  0,	  13,  111, 183, 61,  118, 47,	189,
	    227, 89,  26,  152, 245, 247, 226, 81,  212, 149, 235, 242, 203,
	    10,	 150, 113, 249, 255, 6,	  107, 99,  91,	 55,  41,  20,	99,
	    237, 74,  197, 185, 3,   34,  253, 64,  9,	 82,  64,  33,	241,
	    213, 175, 242, 27,	187, 98,  87,  212, 220, 169, 50,  128, 55,
	    38,	 100, 170, 60,	13,  170, 233, 101, 210, 192, 153, 214, 142,
	    115, 99,  39,  49,	106, 123, 15};
	u8 expected_pk[] = {
	    44,	 4,   88,  170, 156, 109, 228, 56,  148, 114, 39,  191, 106,
	    32,	 172, 132, 210, 81,  200, 92,  19,  98,	 35,  63,  208, 66,
	    86,	 198, 149, 106, 179, 179, 131, 22,  130, 83,  132, 147, 170,
	    151, 12,  103, 70,	234, 97,  106, 187, 171, 249, 5,   46,	184,
	    228, 191, 83,  151, 79,  74,  170, 151, 87,	 203, 38,  183, 44,
	    85,	 41,  85,  25,	95,  180, 33,  7,   64,	 27,  16,  18,	164,
	    79,	 243, 201, 68,	28,  33,  164, 168, 153, 93,  244, 11,	122,
	    152, 40,  116, 64,	116, 241, 59,  180, 234, 245, 183, 243, 196,
	    107, 120, 183, 161, 93,  60,  168, 121, 82,	 195, 255, 68,	146,
	    85,	 183, 185, 77,	65,  29,  52,  34,  77,	 150, 198, 33,	116,
	    213, 193, 70,  37,	175, 98,  8,   143, 147, 192, 156, 166, 145,
	    111, 131, 233, 85,	33,  26,  105, 250, 82,	 159, 39,  73,	93,
	    22,	 55,  1,   27,	247, 163, 63,  145, 125, 198, 27,  42,	181,
	    37,	 207, 90,  34,	120, 185, 43,  204, 161, 4,   30,  153, 92,
	    14,	 50,  184, 32,	44,  245, 53,  177, 240, 40,  89,  248, 67,
	    14,	 201, 142, 151, 202, 173, 55,  161, 162, 155, 128, 101, 243,
	    39,	 80,  58,  36,	195, 99,  130, 54,  235, 225, 183, 4,	58,
	    192, 84,  23,  137, 51,  56,  85,  176, 102, 137, 217, 97,	19,
	    211, 184, 139, 36,	60,  129, 255, 202, 62,	 255, 57,  36,	103,
	    71,	 121, 80,  178, 191, 196, 22,  90,  133, 219, 171, 9,	209,
	    42,	 246, 102, 153, 192, 176, 175, 176, 209, 188, 117, 103, 54,
	    230, 132, 66,  219, 167, 179, 206, 41,  129, 136, 198, 197, 153,
	    37,	 92,  71,  73,	22,  190, 5,   177, 252, 149, 102, 222, 69,
	    145, 215, 231, 13,	134, 139, 160, 63,  17,	 192, 79,  83,	41,
	    201, 188, 42,  125, 150, 59,  159, 96,  10,	 31,  220, 30,	86,
	    17,	 41,  120, 180, 176, 88,  145, 111, 61,	 107, 7,   22,	100,
	    47,	 22,  165, 90,	219, 196, 118, 153, 100, 45,  175, 182, 156,
	    120, 49,  140, 116, 83,  86,  44,  69,  144, 42,  107, 24,	133,
	    193, 31,  117, 153, 178, 67,  184, 124, 182, 0,   82,  145, 235,
	    160, 59,  130, 68,	230, 73,  116, 119, 133, 21,  107, 20,	207,
	    230, 134, 69,  243, 152, 99,  1,   17,  176, 174, 5,   92,	200,
	    11,	 86,  24,  209, 147, 86,  214, 165, 84,	 122, 194, 21,	102,
	    187, 63,  154, 17,	21,  23,  56,  251, 209, 51,  51,  130, 31,
	    253, 51,  118, 26,	162, 31,  75,  246, 56,	 52,  27,  150, 23,
	    67,	 152, 53,  106, 81,  238, 197, 160, 99,	 156, 124, 91,	160,
	    114, 87,  10,  202, 110, 194, 26,  73,  76,	 104, 69,  1,	77,
	    161, 5,   102, 140, 198, 111, 9,   202, 187, 147, 40,  189, 242,
	    134, 45,  78,  240, 186, 224, 41,  15,  252, 227, 78,  114, 0,
	    146, 109, 186, 133, 147, 25,  145, 160, 247, 187, 207, 38,	43,
	    165, 148, 83,  174, 12,  89,  134, 210, 13,	 78,  234, 71,	89,
	    58,	 148, 229, 194, 113, 105, 164, 54,  44,	 1,   91,  30,	234,
	    15,	 122, 122, 181, 172, 152, 80,  210, 236, 113, 38,  153, 47,
	    47,	 193, 3,   64,	9,   64,  58,  80,  11,	 95,  233, 91,	150,
	    194, 8,   183, 75,	116, 242, 203, 163, 167, 20,  34,  204, 44,
	    192, 57,  192, 167, 145, 102, 100, 214, 163, 22,  6,   35,	123,
	    13,	 52,  132, 246, 165, 10,  209, 104, 50,	 233, 85,  19,	148,
	    240, 191, 194, 234, 105, 244, 11,  170, 210, 144, 164, 120, 218,
	    114, 99,  231, 175, 85,  73,  187, 129, 198, 110, 80,  122, 6,
	    214, 235, 103, 18,	228, 18,  232, 210, 146, 23,  12,  47,	83,
	    138, 128, 11,  232, 12,  45,  65,  126, 33,	 17,  157, 116, 210,
	    105, 48,  203, 54,	28,  40,  169, 32,  74,	 199, 140, 128, 106,
	    167, 12,  207, 23,	250, 134, 28,  2,   171, 45,  51,  162, 138,
	    89,	 43,  122, 99,	172, 134, 211, 159, 118, 248, 84,  1,	4,
	    60,	 41,  69,  20,	189, 226, 87,  209, 12,	 64,  103, 10,	188,
	    107, 180, 114, 212, 204, 130, 72,  2,   24,	 220, 199, 195, 33,
	    152, 33,  48,  252, 131, 73,  192, 169, 7,	 65,  84,  190, 204,
	    65,	 131, 10,  146, 229, 121, 144, 147, 56,	 45,  68,  124, 61,
	    96,	 3,   36,  181, 98,  74,  96,  12,  91,	 76,  212, 115, 189,
	    234, 179, 217, 230, 162, 139, 102, 175, 58,	 209, 60,  143, 101,
	    121, 250, 30,  19,	136, 6,	  35,  19,  153, 114, 61,  42,	183,
	    70,	 185, 223, 50,	0,   13,  111, 183, 61,	 118, 47,  189, 227,
	    89,	 26,  152, 245, 247, 226, 81};
	ASSERT(!fastmemcmp(pk.data, expected_pk, sizeof(pk)), "pk");
	ASSERT(!fastmemcmp(sk.data, expected_sk, sizeof(sk)), "sk");
	enc(&ct, &ss_bob, &pk, &rng);
	u8 expected_ct[] = {
	    193, 253, 164, 21,	137, 132, 144, 69,  181, 10,  146, 245, 22,
	    180, 37,  227, 163, 68,  51,  233, 205, 253, 166, 63,  99,	197,
	    192, 85,  101, 47,	39,  254, 31,  150, 189, 146, 128, 214, 211,
	    209, 207, 198, 234, 207, 16,  192, 110, 114, 84,  86,  11,	71,
	    173, 61,  179, 179, 16,  97,  75,  85,  4,	 181, 181, 168, 165,
	    227, 139, 249, 170, 208, 88,  241, 43,  1,	 98,  116, 161, 90,
	    66,	 0,   9,   83,	2,   171, 34,  61,  233, 224, 247, 224, 120,
	    51,	 139, 179, 46,	94,  81,  142, 136, 32,	 166, 101, 123, 241,
	    218, 120, 152, 82,	10,  228, 228, 65,  141, 154, 174, 63,	127,
	    182, 183, 40,  181, 189, 180, 234, 62,  117, 143, 98,  209, 74,
	    28,	 210, 191, 104, 33,  253, 3,   109, 151, 70,  216, 112, 70,
	    102, 237, 138, 213, 18,  26,  139, 63,  86,	 53,  0,   132, 139,
	    21,	 127, 72,  247, 189, 59,  111, 191, 196, 141, 33,  54,	182,
	    71,	 229, 179, 189, 180, 220, 19,  94,  159, 178, 29,  134, 88,
	    181, 115, 54,  214, 220, 81,  184, 80,  50,	 171, 101, 8,	152,
	    152, 81,  240, 25,	93,  200, 44,  62,  72,	 236, 244, 221, 163,
	    228, 119, 77,  84,	137, 77,  131, 225, 98,	 20,  54,  199, 120,
	    22,	 242, 205, 168, 168, 166, 98,  78,  115, 46,  72,  42,	169,
	    11,	 245, 238, 169, 243, 149, 113, 109, 6,	 190, 115, 45,	19,
	    81,	 18,  185, 168, 53,  30,  77,  129, 140, 172, 26,  68,	3,
	    211, 201, 34,  228, 209, 176, 53,  233, 213, 205, 132, 31,	175,
	    90,	 73,  119, 237, 145, 230, 123, 87,  145, 45,  204, 131, 39,
	    218, 163, 85,  80,	60,  127, 200, 112, 62,	 145, 188, 170, 160,
	    237, 53,  165, 21,	130, 145, 18,  16,  129, 242, 187, 3,	245,
	    132, 188, 37,  203, 89,  57,  55,  69,  184, 243, 45,  80,	115,
	    75,	 170, 124, 251, 195, 182, 39,  149, 93,	 56,  160, 77,	149,
	    85,	 253, 184, 126, 185, 79,  97,  78,  24,	 214, 68,  11,	201,
	    151, 42,  48,  147, 121, 83,  193, 254, 158, 194, 203, 56,	251,
	    96,	 4,   64,  3,	72,  38,  46,  149, 107, 176, 17,  99,	157,
	    27,	 213, 189, 33,	157, 26,  201, 212, 208, 129, 112, 22,	24,
	    135, 76,  192, 207, 13,  76,  106, 219, 18,	 243, 219, 78,	107,
	    104, 215, 107, 120, 175, 122, 9,   24,  97,	 225, 201, 168, 121,
	    149, 150, 6,   121, 180, 3,	  247, 36,  33,	 220, 108, 42,	255,
	    21,	 173, 172, 255, 36,  83,  15,  168, 252, 137, 56,  83,	225,
	    112, 211, 17,  243, 175, 24,  0,   157, 240, 237, 143, 114, 109,
	    56,	 6,   2,   85,	161, 208, 111, 26,  84,	 44,  105, 23,	18,
	    123, 76,  212, 61,	191, 179, 6,   46,  172, 218, 192, 60,	163,
	    243, 205, 145, 220, 6,   66,  237, 170, 8,	 236, 150, 149, 75,
	    124, 41,  75,  160, 138, 58,  219, 111, 122, 154, 170, 12,	143,
	    125, 46,  57,  189, 175, 207, 143, 197, 25,	 156, 1,   122, 78,
	    131, 216, 118, 217, 186, 50,  20,  115, 143, 155, 96,  13,	239,
	    51,	 144, 66,  184, 211, 96,  174, 209, 94,	 168, 215, 225, 227,
	    72,	 251, 253, 176, 31,  212, 70,  138, 77,	 134, 246, 101, 20,
	    124, 24,  7,   157, 172, 245, 103, 124, 87,	 103, 109, 36,	153,
	    133, 221, 159, 159, 171, 131, 39,  216, 237, 8,   42,  107, 178,
	    121, 239, 99,  65,	125, 20,  67,  0,   68,	 59,  75,  131, 167,
	    30,	 120, 134, 83,	24,  222, 162, 32,  246, 50,  154, 235, 249,
	    35,	 237, 7,   90,	95,  139, 245, 49,  63,	 184, 18,  64,	226,
	    181, 225, 51,  140, 185, 83,  225, 193, 4,	 148, 69,  129, 31,
	    52,	 41,  198, 43,	25,  199, 188, 253, 223, 58,  122, 246, 150,
	    160, 13,  156, 45,	134, 135, 199, 78,  135, 12,  82,  20,	75,
	    164, 206, 18,  76,	27,  33,  94,  175, 18,	 125, 22,  255, 140,
	    49,	 36,  254, 232, 39,  71,  215, 105, 153, 2,   75,  74,	236,
	    28,	 124, 26,  201, 117, 106, 222, 107, 219, 85,  107, 21,	42,
	    220, 151, 194, 117, 158, 49,  136, 137, 135, 107, 103, 75,	114,
	    180, 162, 165, 218, 84,  132, 193, 70,  70,	 209, 162, 144, 239,
	    79,	 186, 31,  57,	43,  28,  114, 185, 221, 181, 71,  205, 35,
	    95,	 92,  207, 194, 7,   183, 104, 222, 108, 130, 128, 157, 88,
	    12,	 238, 0,   62,	72,  242, 205, 171, 142, 110, 97,  232, 76,
	    214};
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

