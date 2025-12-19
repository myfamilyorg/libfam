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
#include <libfam/format.h>
#include <libfam/lamport.h>
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/sign.h>
#include <libfam/storm.h>
#include <libfam/test.h>
#include <libfam/verihash.h>
#include <libfam/wots.h>

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

Test(storm) {
	Storm256Context ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute__((aligned(32))) u8 buffer1[32] = {0};
	__attribute__((aligned(32))) u8 buffer2[32] = {0};
	__attribute__((aligned(32))) u8 buffer3[32] = {0};
	__attribute__((aligned(32))) u8 buffer4[32] = {0};
	__attribute__((aligned(32))) u8 buffer5[32] = {0};

	storm256_init(&ctx, SEED);
	faststrcpy(buffer1, "test1");
	storm256_xcrypt_buffer(&ctx, buffer1);
	faststrcpy(buffer2, "test2");
	storm256_xcrypt_buffer(&ctx, buffer2);
	faststrcpy(buffer3, "blahblah");
	storm256_xcrypt_buffer(&ctx, buffer3);
	faststrcpy(buffer4, "ok");
	storm256_xcrypt_buffer(&ctx, buffer4);
	faststrcpy(buffer5, "x");
	storm256_xcrypt_buffer(&ctx, buffer5);

	ASSERT(memcmp(buffer1, "test1", 5), "ne1");
	ASSERT(memcmp(buffer2, "test2", 5), "ne2");
	ASSERT(memcmp(buffer3, "blahblah", 8), "ne3");
	ASSERT(memcmp(buffer4, "ok", 2), "ne4");
	ASSERT(memcmp(buffer5, "x", 1), "ne5");

	Storm256Context ctx2;
	storm256_init(&ctx2, SEED);

	storm256_xcrypt_buffer(&ctx2, buffer1);
	ASSERT(!memcmp(buffer1, "test1", 5), "eq1");
	storm256_xcrypt_buffer(&ctx2, buffer2);
	ASSERT(!memcmp(buffer2, "test2", 5), "eq2");

	storm256_xcrypt_buffer(&ctx2, buffer3);
	ASSERT(!memcmp(buffer3, "blahblah", 8), "eq3");

	storm256_xcrypt_buffer(&ctx2, buffer4);
	ASSERT(!memcmp(buffer4, "ok", 2), "eq4");

	storm256_xcrypt_buffer(&ctx2, buffer5);
	ASSERT(!memcmp(buffer5, "x", 1), "eq5");
}

Test(storm_vectors) {
	Storm256Context ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    9,	 93,  216, 137, 224, 212, 105, 200, 163, 28,  146,
	    246, 75,  164, 149, 109, 209, 70,  183, 116, 224, 157,
	    245, 221, 5,   53,	245, 155, 165, 135, 142, 218};
	storm256_init(&ctx, SEED);
	storm256_next_block(&ctx, buf1);

	u8 exp1[32] = {204, 193, 116, 178, 204, 191, 250, 240, 24,  241, 23,
		       185, 255, 250, 66,  221, 100, 77,  187, 202, 221, 228,
		       223, 20,	 106, 134, 78,	38,  178, 172, 110, 153};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm256_next_block(&ctx, buf1);

	u8 exp2[32] = {104, 232, 235, 200, 225, 117, 15,  17,  193, 182, 235,
		       70,  96,	 116, 156, 217, 123, 199, 27,  10,  131, 152,
		       172, 145, 79,  14,  208, 70,  27,  207, 59,  211};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm256_init(&ctx, SEED);
	storm256_next_block(&ctx, buf2);

	u8 exp3[32] = {140, 187, 82,  252, 180, 187, 246, 27,  94,  60, 140,
		       8,   58,	 82,  23,  211, 56,  168, 6,   16,  22, 181,
		       32,  164, 138, 211, 201, 50,  77,  254, 156, 40};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm256_next_block(&ctx, buf2);

	u8 exp4[32] = {115, 33,	 96,  112, 88, 80, 97, 17,  236, 164, 249,
		       136, 197, 55,  160, 85, 30, 92, 154, 49,	 11,  80,
		       164, 112, 126, 77,  25, 42, 22, 18,  14,	 15};
	ASSERT(!memcmp(buf2, exp4, sizeof(buf2)), "buf2 round2");
}

Test(rng) {
	Rng rng1;
	__attribute__((aligned(32))) u8 v[36] = {0};
	__attribute__((aligned(32))) u8 entropy[] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	__attribute__((aligned(32))) u8 k1[32] = {1};

	rng_init(&rng1, entropy);

	rng_gen(&rng1, v, 36);
	ASSERT(memcmp(v, entropy, 32), "check entropy");

	rng_reseed(&rng1, NULL);
	rng_test_seed(&rng1, k1);
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

Test(perfx) {
	__attribute__((aligned(32))) u8 header[HASH_INPUT_LEN];
	__attribute__((aligned(32))) u8 buf[32] = {
	    0,	 0,   130, 112, 151, 22,  74,  167, 170, 113, 109,
	    27,	 234, 235, 45,	189, 100, 230, 166, 0,	 116, 241,
	    182, 57,  182, 170, 158, 209, 46,  165, 155, 209};
	Storm256Context ctx;

	storm256_init(&ctx, buf);

	u64 c = cycle_counter();
	for (u32 i = 0; i < 16384 * 32; i++) storm256_next_block(&ctx, buf);

	c = cycle_counter() - c;
	ASSERT_EQ(buf[0], 204, "check 0 index 1");

	const Bible *b;
	u64 sbox[256];
	__attribute__((aligned(32))) u8 output[32] = {0};
	for (u32 i = 0; i < HASH_INPUT_LEN; i++) header[i] = i;

	if (!exists(BIBLE_PATH)) {
		b = bible_gen();
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_sbox8_64(sbox);
	c = cycle_counter();
	bible_hash(b, header, output, sbox);
	c = cycle_counter() - c;

	ASSERT_EQ(output[0], 150, "check 0 index 2");
}

void ntt(i32 a[256]);

Test(ntt) {
	__attribute__((aligned(32))) i32 a[256];
	for (i32 i = -128; i < 128; i++) a[i + 128] = i;
	ntt(a);

	i32 expected[256] = {
	    -2729132,  -6058314,  -5137715,  -5679267,	-2813548,  -6040182,
	    -7202739,  -1282871,  -6941802,  352074,	2013441,   -3761017,
	    -3908522,  -3670440,  4244052,   3177870,	-586457,   -133697,
	    9756786,   3211544,	  353957,    -3035591,	-8165497,  -3691341,
	    -269489,   7203423,	  4977621,   2761801,	4944525,   8551779,
	    3724879,   7707373,	  2022841,   7307463,	1758316,   -5360748,
	    2042434,   -830548,	  -4124118,  2271928,	-2233877,  5469383,
	    5827391,   200535,	  -2138391,  -282155,	1733551,   -6314949,
	    -2720630,  3692712,	  668752,    7940570,	5704864,   1514238,
	    2646363,   4564451,	  -5909147,  305407,	-3911884,  3079496,
	    -11171325, -11091841, -2571461,  -8740341,	-6305269,  -7641463,
	    -749046,   3253082,	  8417212,   1511506,	-291140,   -3802858,
	    -3069034,  -912290,	  -7714567,  -5031513,	-11801537, -8785919,
	    -4206607,  -1381277,  1446840,   -1947136,	7089714,   1486386,
	    8565471,   7226071,	  11495692,  9489474,	-674847,   -3090383,
	    -2643106,  5507800,	  -1359393,  6186907,	6918547,   1062123,
	    2979375,   300627,	  -6686767,  -3819659,	-5381512,  -7648582,
	    -5058517,  -3775581,  -2062198,  -4716106,	-2569431,  1051427,
	    5491054,   -3642,	  3868276,   -248492,	3807278,   798216,
	    9347858,   5370032,	  -3625724,  2721358,	9458781,   4205473,
	    1478050,   -5367718,  -3099142,  395562,	-530170,   6503906,
	    150123,    5177237,	  5177237,   150123,	6503906,   -530170,
	    395562,    -3099142,  -5367718,  1478050,	4205473,   9458781,
	    2721358,   -3625724,  5370032,   9347858,	798216,	   3807278,
	    -248492,   3868276,	  -3642,     5491054,	1051427,   -2569431,
	    -4716106,  -2062198,  -3775581,  -5058517,	-7648582,  -5381512,
	    -3819659,  -6686767,  300627,    2979375,	1062123,   6918547,
	    6186907,   -1359393,  5507800,   -2643106,	-3090383,  -674847,
	    9489474,   11495692,  7226071,   8565471,	1486386,   7089714,
	    -1947136,  1446840,	  -1381277,  -4206607,	-8785919,  -11801537,
	    -5031513,  -7714567,  -912290,   -3069034,	-3802858,  -291140,
	    1511506,   8417212,	  3253082,   -749046,	-7641463,  -6305269,
	    -8740341,  -2571461,  -11091841, -11171325, 3079496,   -3911884,
	    305407,    -5909147,  4564451,   2646363,	1514238,   5704864,
	    7940570,   668752,	  3692712,   -2720630,	-6314949,  1733551,
	    -282155,   -2138391,  200535,    5827391,	5469383,   -2233877,
	    2271928,   -4124118,  -830548,   2042434,	-5360748,  1758316,
	    7307463,   2022841,	  7707373,   3724879,	8551779,   4944525,
	    2761801,   4977621,	  7203423,   -269489,	-3691341,  -8165497,
	    -3035591,  353957,	  3211544,   9756786,	-133697,   -586457,
	    3177870,   4244052,	  -3670440,  -3908522,	-3761017,  2013441,
	    352074,    -6941802,  -1282871,  -7202739,	-6040182,  -2813548,
	    -5679267,  -5137715,  -6058314,  -2729132};
	ASSERT(!memcmp(a, expected, sizeof(expected)), "ntt correct");
}

void invntt_tomont(i32 a[256]);

Test(invntt_tomont) {
	__attribute__((aligned(32))) i32 a[256];
	for (i32 i = -128; i < 128; i++) a[i + 128] = i;
	invntt_tomont(a);

	i32 expected[] = {
	    -2096896, -4094004, 445741,	  2492145,  162954,   -1493646,
	    -2865316, 1966120,	117724,	  -2156024, 57377,    -1401077,
	    2374870,  -661169,	1872253,  -767385,  -625297,  2884685,
	    4153317,  1532728,	2384177,  3960789,  731652,   -1116420,
	    753608,   -1654232, 2924054,  -1173541, -45721,   -631616,
	    -1723799, 1878580,	-3802464, -4084618, 2749031,  286136,
	    4002964,  -166624,	-3493179, -631726,  3400745,  -1977111,
	    1397312,  -2299943, 3995664,  2070626,  -3852781, -3384455,
	    -2517502, 2457249,	422330,	  -3295048, 1842693,  -3834082,
	    -2178890, -1701355, 2950922,  -867524,  -143226,  -1456024,
	    -2801287, 2729086,	-888547,  1486038,  237654,   606622,
	    1646805,  -2150186, -2085699, 3735539,  -736528,  -3324245,
	    2607922,  577665,	2713084,  2378349,  -3415389, 1474673,
	    -139,     3373477,	-3174776, -2535613, -977540,  -3381541,
	    -1130192, 3338667,	1666030,  3230146,  -3670193, 2391298,
	    2460446,  -3936985, -3041226, -605892,  -3550388, 859718,
	    -1050783, 867686,	-3490841, -3014890, 2449692,  2479138,
	    1970172,  -1525900, -744625,  -1680592, -78330,   144689,
	    3842724,  2874774,	-3910481, 3364246,  -3149985, 3141233,
	    1064407,  -2995303, 1836223,  -2602407, -2183595, 94329,
	    1698223,  2516058,	3313587,  1600397,  -2224306, 3379734,
	    -2534394, 3982644,	1654208,  3982644,  -2534394, 3379734,
	    -2224306, 1600397,	3313587,  2516058,  1698223,  94329,
	    -2183595, -2602407, 1836223,  -2995303, 1064407,  3141233,
	    -3149985, 3364246,	-3910481, 2874774,  3842724,  144689,
	    -78330,   -1680592, -744625,  -1525900, 1970172,  2479138,
	    2449692,  -3014890, -3490841, 867686,   -1050783, 859718,
	    -3550388, -605892,	-3041226, -3936985, 2460446,  2391298,
	    -3670193, 3230146,	1666030,  3338667,  -1130192, -3381541,
	    -977540,  -2535613, -3174776, 3373477,  -139,     1474673,
	    -3415389, 2378349,	2713084,  577665,   2607922,  -3324245,
	    -736528,  3735539,	-2085699, -2150186, 1646805,  606622,
	    237654,   1486038,	-888547,  2729086,  -2801287, -1456024,
	    -143226,  -867524,	2950922,  -1701355, -2178890, -3834082,
	    1842693,  -3295048, 422330,	  2457249,  -2517502, -3384455,
	    -3852781, 2070626,	3995664,  -2299943, 1397312,  -1977111,
	    3400745,  -631726,	-3493179, -166624,  4002964,  286136,
	    2749031,  -4084618, -3802464, 1878580,  -1723799, -631616,
	    -45721,   -1173541, 2924054,  -1654232, 753608,   -1116420,
	    731652,   3960789,	2384177,  1532728,  4153317,  2884685,
	    -625297,  -767385,	1872253,  -661169,  2374870,  -1401077,
	    57377,    -2156024, 117724,	  1966120,  -2865316, -1493646,
	    162954,   2492145,	445741,	  -4094004};

	ASSERT(!memcmp(a, expected, sizeof(a)), "result");
}

Test(dilithium) {
	SecretKey sk;
	PublicKey pk;
	Signature sig;
	Message msg = {0};
	__attribute__((aligned(32))) u8 rnd[SEEDLEN] = {0};
	Rng rng;

	rng_init(&rng, NULL);

	for (u32 i = 0; i < 12; i++) {
		rng_gen(&rng, rnd, 32);
		rng_gen(&rng, &msg, MLEN);

		keyfrom(&sk, &pk, rnd);
		sign(&sig, &msg, &sk);
		ASSERT(!verify(&sig, &pk), "verify");
		((u8 *)&sig)[0]++;
		ASSERT(verify(&sig, &pk), "!verify");
		ASSERT(!memcmp(&msg, ((u8 *)&sig) + 2420, MLEN), "msg");
	}
}

#define DILITHIUM_COUNT 100

Test(dilithium_perf) {
	__attribute__((aligned(32))) u8 rnd[SEEDLEN] = {0};
	Message m = {0};
	SecretKey sk;
	PublicKey pk;
	Signature sm;

	Rng rng;
	u64 keygen_sum = 0;
	u64 sign_sum = 0;
	u64 verify_sum = 0;

	rng_init(&rng, NULL);

	for (u32 i = 0; i < DILITHIUM_COUNT; i++) {
		rng_gen(&rng, rnd, 32);
		rng_gen(&rng, &m, MLEN);

		u64 start = cycle_counter();
		keyfrom(&sk, &pk, rnd);
		keygen_sum += cycle_counter() - start;
		start = cycle_counter();
		sign(&sm, &m, &sk);
		sign_sum += cycle_counter() - start;
		start = cycle_counter();
		verify(&sm, &pk);
		verify_sum += cycle_counter() - start;
	}
	(void)keygen_sum;
	(void)sign_sum;
	(void)verify_sum;

	/*
	println("keygen={},sign={},verify={}", keygen_sum / DILITHIUM_COUNT,
		sign_sum / DILITHIUM_COUNT, verify_sum / DILITHIUM_COUNT);
		*/
}

Test(verihash) {
	u128 v = verihash128("abc", 3);
	(void)v;
	// println("v={}", v);
}

Test(verihash_bitflip) {
	Rng rng;
	u8 plaintext[32] = {0};
	u8 plaintext2[32] = {0};
	u32 iter = 10;
	u32 trials = 10000;
	u32 total_fail = 0;

	(void)total_fail;

	rng_init(&rng, NULL);
	// rng_test_seed(&rng, ZERO_SEED);
	f64 max = 0.0, min = 100.0;

	for (u32 i = 0; i < iter; i++) {
		rng_gen(&rng, plaintext, 32);
		u64 zeros[256] = {0};
		u64 ones[256] = {0};

		u128 r1 = verihash128(plaintext, 32);

		for (u32 j = 0; j < trials; j++) {
			fastmemcpy(plaintext2, plaintext, 32);
			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 32;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			plaintext2[byte_pos] ^= (u8)(1 << bit_pos);
			u128 r2 = verihash128(plaintext2, 32);
			u8 *a = (void *)&r1;
			u8 *b = (void *)&r2;

			for (u32 k = 0; k < 16; k++) {
				u8 diff = a[k] ^ b[k];
				for (u32 bit = 0; bit < 8; bit++) {
					if (diff & (1 << bit)) {
						ones[k * 8 + bit]++;
					} else {
						zeros[k * 8 + bit]++;
					}
				}
			}
		}
		for (u32 j = 0; j < 128; j++) {
			f64 avg = (f64)(((f64)zeros[j] * (f64)1000)) /
				  (f64)(((f64)zeros[j] + (f64)ones[j]));
			avg /= 10.00000;
			if (avg > max) max = avg;
			if (avg < min) min = avg;
			if (avg > 55.0 || avg < 45.0) total_fail++;
		}
	}
	println("total_failed(verihash)={}/{},diff={},ratio={}", total_fail,
		iter * 128, max - min, (f64)total_fail / (f64)(iter * 128));
}

#include <libfam/aes.h>

Test(aes_bitflip) {
	AesContext aes;
	Rng rng;
	u8 plaintext[32] = {0};
	u8 plaintext2[32] = {0};
	u8 plaintext3[32] = {0};
	u32 iter = 100;
	u32 trials = 10000;
	u32 total_fail = 0;

	(void)total_fail;

	rng_init(&rng, NULL);
	f64 max = 0.0, min = 100.0;

	u8 key[32] = {0}, iv[16] = {0};
	rng_gen(&rng, key, 32);
	rng_gen(&rng, iv, 16);
	aes_init(&aes, key, iv);

	for (u32 i = 0; i < iter; i++) {
		rng_gen(&rng, plaintext, 32);
		u64 zeros[256] = {0};
		u64 ones[256] = {0};

		for (u32 j = 0; j < trials; j++) {
			AesContext aes2;
			fastmemcpy(&aes2, &aes, sizeof(aes2));
			fastmemcpy(plaintext2, plaintext, 32);
			fastmemcpy(plaintext3, plaintext, 32);
			aes_ctr_xcrypt_buffer(&aes, plaintext2, 32);
			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 16;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			plaintext3[byte_pos] ^= (u8)(1 << bit_pos);
			ASSERT(memcmp(plaintext2, plaintext3, 32), "pt");
			aes_ctr_xcrypt_buffer(&aes, plaintext3, 32);
			u8 *a = plaintext2;
			u8 *b = plaintext3;

			ASSERT(memcmp(a, b, 32), "a==b");

			for (u32 k = 0; k < 32; k++) {
				u8 diff = a[k] ^ b[k];
				for (u32 bit = 0; bit < 8; bit++) {
					if (diff & (1 << bit)) {
						ones[k * 8 + bit]++;
					} else {
						zeros[k * 8 + bit]++;
					}
				}
			}
		}

		for (u32 j = 0; j < 256; j++) {
			f64 avg = (zeros[j] * 1000) / (zeros[j] + ones[j]);
			avg /= 10.0;
			if (avg > max) max = avg;
			if (avg < min) min = avg;
			if (avg > 55.0 || avg < 45.0) total_fail++;
		}
	}
	println("total_failed(aes)={}/{},diff={},ratio={}", total_fail,
		iter * 256, max - min, (f64)total_fail / (f64)(iter * 256));
}

Test(storm256_bitflip) {
	Storm256Context ctx;
	Rng rng;
	__attribute__((aligned(32))) u8 plaintext[32] = {0};
	__attribute__((aligned(32))) u8 plaintext2[32] = {0};
	__attribute__((aligned(32))) u8 plaintext3[32] = {0};
	u32 iter = 100;
	u32 trials = 10000;
	u32 total_fail = 0;

	(void)total_fail;

	rng_init(&rng, NULL);
	f64 max = 0.0, min = 100.0;

	__attribute__((aligned(32))) u8 key[32] = {0};
	rng_gen(&rng, key, 32);
	storm256_init(&ctx, key);

	for (u32 i = 0; i < iter; i++) {
		rng_gen(&rng, plaintext, 32);
		u64 zeros[256] = {0};
		u64 ones[256] = {0};

		for (u32 j = 0; j < trials; j++) {
			Storm256Context ctx2;
			fastmemcpy(&ctx2, &ctx, sizeof(ctx2));
			fastmemcpy(plaintext2, plaintext, 32);
			fastmemcpy(plaintext3, plaintext, 32);
			storm256_next_block(&ctx, plaintext2);
			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 32;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			plaintext3[byte_pos] ^= (u8)(1 << bit_pos);
			ASSERT(memcmp(plaintext2, plaintext3, 32), "pt");
			storm256_next_block(&ctx2, plaintext3);
			u8 *a = plaintext2;
			u8 *b = plaintext3;

			ASSERT(memcmp(a, b, 32), "a==b");

			for (u32 k = 0; k < 32; k++) {
				u8 diff = a[k] ^ b[k];
				for (u32 bit = 0; bit < 8; bit++) {
					if (diff & (1 << bit)) {
						ones[k * 8 + bit]++;
					} else {
						zeros[k * 8 + bit]++;
					}
				}
			}
		}

		for (u32 j = 0; j < 256; j++) {
			f64 avg = (zeros[j] * 1000) / (zeros[j] + ones[j]);
			avg /= 10.0;
			if (avg > max) max = avg;
			if (avg < min) min = avg;
			if (avg > 55.0 || avg < 45.0) total_fail++;
		}
	}
	println("total_failed(storm256)={}/{},diff={},ratio={}", total_fail,
		iter * 256, max - min, (f64)total_fail / (f64)(iter * 256));
}

static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};
static __attribute__((aligned(32))) u8 ONE_SEED[32] = {1};
static __attribute__((aligned(32))) u8 TWO_SEED[32] = {2};
static __attribute__((aligned(32))) u8 THREE_SEED[32] = {3};
static __attribute__((aligned(32))) u8 FOUR_SEED[32] = {4};
static __attribute__((aligned(32))) u8 FIVE_SEED[32] = {5};
#define STORM_PERF2_COUNT (1000000 / 32)

Test(storm256_perf) {
	i64 timer;
	__attribute__((aligned(32))) u8 buf1[64] = {0};
	__attribute__((aligned(32))) u8 buf2[64] = {0};
	__attribute__((aligned(32))) u8 buf3[64] = {0};
	__attribute__((aligned(32))) u8 buf4[64] = {0};
	__attribute__((aligned(32))) u8 buf5[64] = {0};
	__attribute__((aligned(32))) u8 buf6[64] = {0};

	Storm256Context ctx1;
	Storm256Context ctx2;
	Storm256Context ctx3;
	Storm256Context ctx4;
	Storm256Context ctx5;
	Storm256Context ctx6;

	u64 sum = 0;

	(void)sum;

	storm256_init(&ctx1, ZERO_SEED);
	storm256_init(&ctx2, ONE_SEED);
	storm256_init(&ctx3, TWO_SEED);
	storm256_init(&ctx4, THREE_SEED);
	storm256_init(&ctx5, FOUR_SEED);
	storm256_init(&ctx6, FIVE_SEED);

	timer = micros();
	for (u32 i = 0; i < STORM_PERF2_COUNT; i++) {
		u8 *block1 = buf1 + (i & 32);
		u8 *block2 = buf2 + (i & 32);
		u8 *block3 = buf3 + (i & 32);
		u8 *block4 = buf4 + (i & 32);
		u8 *block5 = buf5 + (i & 32);
		u8 *block6 = buf6 + (i & 32);
		storm256_xcrypt_buffer(&ctx1, block1);
		sum += ((u64 *)block1)[0];
		storm256_xcrypt_buffer(&ctx2, block2);
		sum += ((u64 *)block2)[0];
		storm256_xcrypt_buffer(&ctx3, block3);
		sum += ((u64 *)block3)[0];
		storm256_xcrypt_buffer(&ctx4, block4);
		sum += ((u64 *)block4)[0];
		storm256_xcrypt_buffer(&ctx5, block5);
		sum += ((u64 *)block6)[0];
		storm256_xcrypt_buffer(&ctx6, block6);
		sum += ((u64 *)block6)[0];
	}
	timer = micros() - timer;
	(void)buf2;
	(void)buf3;
	(void)buf4;
	(void)buf5;
	(void)buf6;

	/*println("time={}us, sum={}, avg={}ns", timer, sum,
		(timer * 1000) / STORM_PERF2_COUNT);*/
}

__attribute__((aligned(32))) static const u8 VERIHASH_DOMAIN[32] = {1, 2, 39,
								    99};

Test(verihash_consts) {
	__attribute__((aligned(32))) static u64
	    local_const_data[FULL_ROUNDS + PARTIAL_ROUNDS][FIELD_SIZE] = {0};
	Storm256Context ctx;
	storm256_init(&ctx, VERIHASH_DOMAIN);
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++) {
		for (u64 j = 0; j < FIELD_SIZE / 4; j++)
			storm256_next_block(
			    &ctx, (((u8 *)local_const_data[i]) + j * 32));
	}
	for (u64 i = 0; i < FULL_ROUNDS + PARTIAL_ROUNDS; i++) {
		for (u64 j = 0; j < FIELD_SIZE; j++) {
			ASSERT_EQ(local_const_data[i][j], const_data[i][j],
				  "consts");
		}
	}
}

Test(verihash_preimage) {
	Rng rng;
	u8 input[32] = {0}, flipped[32] = {0};
	u128 target = 0;
	u128 min_diff = U128_MAX;
	u8 min_hamm = 128;
	u32 trials = 1 << 10;
	u32 matches = 0;

	rng_init(&rng, NULL);
	for (u32 i = 0; i < trials; i++) {
		rng_gen(&rng, input, 32);
		target = verihash128(input, 32);
		fastmemcpy(flipped, input, 32);
		u64 byte_pos = i % 32;
		u8 bit_pos = (i / 32) % 8;
		flipped[byte_pos] ^= (1 << bit_pos);
		u128 result = verihash128(flipped, 32);
		if (result == target) matches++;
		u128 diff = result > target ? result - target : target - result;
		min_diff = diff < min_diff ? diff : min_diff;

		u128 hamm_diff = target ^ result;
		u32 hamm = __builtin_popcountll((u64)hamm_diff) +
			   __builtin_popcountll((u64)(hamm_diff >> 64));
		min_hamm = hamm < min_hamm ? hamm : min_hamm;

		if (i % 10000 == 0)
			println(
			    "i={},matches={},min_diff={},diff={},min_hamm={}",
			    i, matches, min_diff, diff, min_hamm);
	}
	ASSERT(matches == 0, "Preimage matches: {}", matches);
	println("Preimage test: {} trials, {} matches (expected 0)", trials,
		matches);
}

Test(verihash256_vector) {
	u8 output[32];
	verihash256((u8[32]){1}, 32, output);
	u8 expected[32] = {1,	234, 21,  162, 57,  185, 194, 20,
			   44,	171, 197, 101, 161, 140, 208, 121,
			   71,	204, 119, 192, 229, 34,	 218, 120,
			   110, 94,  131, 20,  38,  4,	 247, 63};
	ASSERT(!memcmp(output, expected, 32), "vector1");
}

Test(verihash256_preimage) {
	Rng rng;
	u8 input[32] = {0}, flipped[32] = {0};
	__attribute__((aligned(32))) u8 target[32];
	u32 min_hamm = 256;
	u64 trials = 1 << 18;
	u64 timer = micros();

	rng_init(&rng, NULL);
	for (u64 i = 0; i < trials; i++) {
		rng_gen(&rng, input, 32);
		verihash256(input, 32, target);
		fastmemcpy(flipped, input, 32);
		u64 byte_pos = i % 32;
		u8 bit_pos = (i / 32) % 8;
		flipped[byte_pos] ^= (1 << bit_pos);
		u8 result[32];
		verihash256(flipped, 32, result);

		u128 hamm_diff1 = ((u128 *)target)[0] ^ ((u128 *)result)[0];
		u128 hamm_diff2 = ((u128 *)target)[1] ^ ((u128 *)result)[1];
		u32 hamm = __builtin_popcountll((u64)hamm_diff1) +
			   __builtin_popcountll((u64)(hamm_diff1 >> 64)) +
			   __builtin_popcountll((u64)hamm_diff2) +
			   __builtin_popcountll((u64)(hamm_diff2 >> 64));
		min_hamm = hamm < min_hamm ? hamm : min_hamm;

		if (i && (i % 100000 == 0)) {
			u64 elapsed = micros() - timer;
			println("i={},min_hamm={},elapsed={}ms", i, min_hamm,
				elapsed / 1000);
			timer = micros();
		}
	}
}

Test(lamport_storm) {
	u8 key[32] = {1, 2, 3, 4, 5};
	LamportPubKey pk;
	LamportSecKey sk;
	LamportSig sig;
	u8 msg[32] = {9, 9, 9, 9, 9, 4};

	u64 timer = cycle_counter();
	lamport_keyfrom(key, &pk, &sk);
	timer = cycle_counter() - timer;
	println("keygen={}", timer);
	timer = cycle_counter();
	lamport_sign(&sk, msg, &sig);
	timer = cycle_counter() - timer;
	println("sign={}", timer);
	timer = cycle_counter();
	ASSERT(!lamport_verify(&pk, &sig, msg), "verify");
	timer = cycle_counter() - timer;
	println("verify={}", timer);
	msg[0]++;
	ASSERT(lamport_verify(&pk, &sig, msg), "!verify");
}

#define LAMPORT_LOOPS 100000

Test(lamport_perf) {
	Rng rng;
	LamportPubKey pk;
	LamportSecKey sk;
	LamportSig sig;
	u64 keygen_cycles = 0, sign_cycles = 0, verify_cycles = 0, timer;
	__attribute__((aligned(32))) u8 msg[32];
	__attribute__((aligned(32))) u8 key[32];
	rng_init(&rng, NULL);

	for (u32 i = 0; i < LAMPORT_LOOPS; i++) {
		rng_gen(&rng, key, 32);
		rng_gen(&rng, msg, 32);
		timer = cycle_counter();
		lamport_keyfrom(key, &pk, &sk);
		keygen_cycles += cycle_counter() - timer;
		timer = cycle_counter();
		lamport_sign(&sk, msg, &sig);
		sign_cycles += cycle_counter() - timer;
		timer = cycle_counter();
		i32 res = lamport_verify(&pk, &sig, msg);
		verify_cycles += cycle_counter() - timer;

		ASSERT(!res, "verify");

		sig.data[7]++;
		ASSERT_EQ(lamport_verify(&pk, &sig, msg), -1, "err");
	}
	println("keygen={},sign={},verify={}", keygen_cycles / LAMPORT_LOOPS,
		sign_cycles / LAMPORT_LOOPS, verify_cycles / LAMPORT_LOOPS);
}

Test(wots) {
	u8 key[32] = {1, 2, 3, 4, 5};
	WotsPubKey pk;
	WotsSecKey sk;
	WotsSig sig;
	u8 msg[32] = {9, 9, 9, 9, 9, 4};

	u64 timer = cycle_counter();
	wots_keyfrom(key, &pk, &sk);
	timer = cycle_counter() - timer;
	println("keygen={}", timer);
	timer = cycle_counter();
	wots_sign(&sk, msg, &sig);
	timer = cycle_counter() - timer;
	println("sign={}", timer);
	timer = cycle_counter();
	ASSERT(!wots_verify(&pk, &sig, msg), "verify");
	timer = cycle_counter() - timer;
	println("verify={}", timer);
	msg[0]++;
	ASSERT(wots_verify(&pk, &sig, msg), "!verify");
}

#define WOTS_LOOPS 1000

Test(wots_perf) {
	Rng rng;
	WotsPubKey pk;
	WotsSecKey sk;
	WotsSig sig;
	u64 keygen_cycles = 0, sign_cycles = 0, verify_cycles = 0, timer;
	__attribute__((aligned(32))) u8 msg[32];
	__attribute__((aligned(32))) u8 key[32];
	rng_init(&rng, NULL);

	for (u32 i = 0; i < WOTS_LOOPS; i++) {
		rng_gen(&rng, key, 32);
		rng_gen(&rng, msg, 32);
		timer = cycle_counter();
		wots_keyfrom(key, &pk, &sk);
		keygen_cycles += cycle_counter() - timer;
		timer = cycle_counter();
		wots_sign(&sk, msg, &sig);
		sign_cycles += cycle_counter() - timer;
		timer = cycle_counter();
		i32 res = wots_verify(&pk, &sig, msg);
		verify_cycles += cycle_counter() - timer;

		ASSERT(!res, "verify");

		sig.data[7]++;
		ASSERT_EQ(wots_verify(&pk, &sig, msg), -1, "err");
	}
	println("keygen={},sign={},verify={}", keygen_cycles / WOTS_LOOPS,
		sign_cycles / WOTS_LOOPS, verify_cycles / WOTS_LOOPS);
}

