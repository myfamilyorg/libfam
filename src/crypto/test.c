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
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/sign.h>
#include <libfam/storm.h>
#include <libfam/test_base.h>

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

Test(storm_vectors) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf1);

	u8 exp1[32] = {0x90, 0xC0, 0xC6, 0x22, 0xE6, 0x25, 0x85, 0x38,
		       0x17, 0x59, 0x2F, 0x3,  0xA,  0x3C, 0xD9, 0x98,
		       0x1C, 0x41, 0x99, 0xC6, 0x9D, 0x5C, 0x79, 0x36,
		       0xED, 0x98, 0x94, 0xF5, 0xB3, 0xEF, 0x7F, 0xE2};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {0x71, 0xEF, 0xAB, 0x45, 0x53, 0x34, 0x1C, 0x3C,
		       0xE1, 0xDC, 0x38, 0x32, 0x8A, 0x6,  0xF5, 0x3,
		       0xDE, 0xFF, 0xD1, 0x53, 0xE3, 0x9A, 0x7A, 0x8D,
		       0x4B, 0xD0, 0xD,	 0x9A, 0x64, 0x54, 0x1E, 0xA7};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf2);

	u8 exp3[32] = {0x80, 0xFA, 0x57, 0x25, 0xD2, 0xE9, 0x6C, 0x6,
		       0x96, 0x5C, 0x62, 0x1D, 0xF2, 0x5B, 0xD6, 0x1,
		       0x5E, 0x6A, 0xFE, 0x3B, 0x32, 0xD3, 0x49, 0xB8,
		       0xDD, 0xA2, 0xDF, 0xB0, 0x74, 0x6F, 0x4A, 0xBD};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm_next_block(&ctx, buf2);

	u8 exp4[32] = {0x8F, 0x15, 0x94, 0x6D, 0x72, 0x5C, 0xE6, 0xB4,
		       0x92, 0x79, 0xFE, 0xEF, 0x85, 0x38, 0x55, 0x21,
		       0x2E, 0x70, 0xBC, 0xD9, 0xFC, 0xF3, 0xA7, 0xDC,
		       0x4A, 0x4F, 0x9B, 0x44, 0x24, 0x75, 0x2C, 0xAA};
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

	u8 expected[32] = {0xDE, 0x2A, 0x3A, 0xB2, 0xF0, 0x58, 0xF0, 0x72,
			   0x25, 0x26, 0x1C, 0x18, 0x8F, 0x35, 0x27, 0x45,
			   0xD0, 0x3F, 0x98, 0x31, 0x86, 0xFF, 0x32, 0x61,
			   0xC9, 0xAE, 0x6B, 0x5A, 0x78, 0x7F, 0xF0, 0x62};

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

	ASSERT_EQ(nonce, 97178, "nonce");
	ASSERT(!memcmp(output,
		       (u8[]){0x0,  0x0,  0xB1, 0x34, 0x74, 0xE0, 0xB5, 0xF7,
			      0xA6, 0xE2, 0xA6, 0xA1, 0x70, 0x7A, 0x80, 0x6C,
			      0xF5, 0x9D, 0x21, 0x76, 0x52, 0xB7, 0x4C, 0xED,
			      0x64, 0x56, 0xC,	0xD4, 0xCD, 0xFD, 0xD2, 0x2E},
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
	StormContext ctx;

	storm_init(&ctx, buf);

	u64 c = cycle_counter();
	for (u32 i = 0; i < 16384 * 32; i++) storm_next_block(&ctx, buf);

	c = cycle_counter() - c;

	ASSERT_EQ(buf[0], 239, "check 0 index");

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
	ASSERT_EQ(output[0], 197, "check 0 index");
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

		dilithium_keyfrom(&sk, &pk, rnd);
		dilithium_sign(&sig, &msg, &sk);
		ASSERT(!dilithium_verify(&sig, &pk), "verify");
		((u8 *)&sig)[0]++;
		ASSERT(dilithium_verify(&sig, &pk), "!verify");
	}
}

#define DILITHIUM_COUNT 1000

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
		dilithium_keyfrom(&sk, &pk, rnd);
		keygen_sum += cycle_counter() - start;
		start = cycle_counter();
		dilithium_sign(&sm, &m, &sk);
		sign_sum += cycle_counter() - start;
		start = cycle_counter();
		dilithium_verify(&sm, &pk);
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

