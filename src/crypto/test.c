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
#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/lattice.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/test.h>

#define COUNT (1024 * 1024)

Test(aighthash) {
	i64 timer = micros();
	u8 text[32] = {0};
	u64* v = (void*)text;
	u32 sum = 0;

	for (u32 i = 0; i < COUNT; i++) {
		u64 r = aighthash64(text, 32, 0);
		(*v)++;
		sum += r;
	}
	timer = micros() - timer;
	(void)sum;
	// println("time={},r={},avg={}ns", timer, sum, (timer * 1000) / COUNT);
}

Test(twobytefails) {
	u32 h1 = aighthash32("a\0", 2, 0);  // input: 0x61 0x00
	u32 h2 = aighthash32("ab", 2, 0);   // input: 0x61 0x62
					   // println("h1={x},h2={x}", h1, h2);

	ASSERT(h1 != h2, "twobyte");
}

Test(aighthash_original_fails_this) {
	// These two inputs are 3 bytes each, differ only in last byte
	// Your tail handling accumulates big-endian → same low 16 bits → weak
	// final mix can't save it
	u32 h1 = aighthash32("abc", 3, 0);   // bytes: 0x61 0x62 0x63
	u32 h2 = aighthash32("ab\0", 3, 0);  // bytes: 0x61 0x62 0x00

	// println("h_abc = 0x{x}", h1);
	// println("h_ab0 = 0x{x}", h2);

	// With your original code → COLLISION (same hash)
	ASSERT(h1 != h2, "3-byte collision: \"abc\" vs \"ab\\0\"");
}

Test(random_stir) {
	__attribute__((aligned(32))) u8 v1[32];
	__attribute__((aligned(32))) u8 v2[32];
	__attribute__((aligned(32))) const u8 st[32] = {1, 2, 3};

	random32(v1);
	memcpy(v2, v1, 32);
	ASSERT(!memcmp(v1, v2, 32), "equal");
	random_stir(v2, st);
	ASSERT(memcmp(v1, v2, 32), "equal");
}

#define SIZE (128 * 1024)
static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};
static __attribute__((aligned(32))) u8 ONE_SEED[32] = {1};
static __attribute__((aligned(32))) u8 TWO_SEED[32] = {2};
static __attribute__((aligned(32))) u8 THREE_SEED[32] = {3};

Test(aighthash_longneighbors) {
	Rng rng;
	int size = SIZE;
	u8 a[SIZE] = {0};
	u8 b[SIZE] = {0};

	rng_test_seed(&rng, ZERO_SEED);

	int total_fail = 0;
	(void)total_fail;
	int iter = 1;
	for (u32 i = 0; i < iter; i++) {
		for (u64 i = 0; i < size; ++i)
			a[i] = b[i] = (u8)(i ^ (i >> 8) ^ (i >> 16));

		int total_tests = 0;
		int bias[32] = {0};
		u32 seed = i;

		for (int trial = 0; trial < 500; ++trial) {
			memcpy(b, a, size);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= size;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);

			u32 ha = aighthash32(a, size, seed);
			u32 hb = aighthash32(b, size, seed);
			u32 diff = ha ^ hb;

			for (int bit = 0; bit < 32; ++bit) {
				if (diff & (1u << bit)) {
					bias[bit]++;
				}
			}
			total_tests++;
		}

		/*
		println(
		    "LongNeighbors (seed={}) — 500 single-bit diffs in 128KB "
		    "keys:",
		    seed);
		    */
		for (int bit = 0; bit < 32; ++bit) {
			f64 percent = 100.0 * bias[bit] / total_tests;
			/*
			println("  bit {}: {} flips → {}", bit, bias[bit],
				percent);
				*/
			(void)percent;
		}

		int failed = 0;
		for (int bit = 0; bit < 32; ++bit) {
			double p = 100.0 * bias[bit] / total_tests;
			if (p < 44.0 || p > 56.0) {
				failed++;
			}
		}
		(void)failed;

		total_fail += failed != 0;
	}
	// println("total_failed={}/{}", total_fail, iter);
}

Test(aighthash64_longneighbors) {
	Rng rng = {0};
	int size = SIZE;
	u8 a[SIZE] = {0};
	u8 b[SIZE] = {0};

	rng_test_seed(&rng, ZERO_SEED);
	u8 key[16];
	rng_gen(&rng, key, 16);

	int total_fail = 0;
	int iter = 10;

	(void)total_fail;

	for (u32 i = 0; i < iter; i++) {
		for (u64 j = 0; j < size; ++j)
			a[j] = b[j] =
			    (u8)(j ^ (j >> 8) ^ (j >> 16) ^ (j >> 32));

		int total_tests = 0;
		int bias[64] = {0};  // now 64 bits
		u64 seed = i;

		for (int trial = 0; trial < 50; ++trial) {
			fastmemcpy(b, a, size);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= size;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);

			u64 ha = aighthash64(a, size, seed);
			u64 hb = aighthash64(b, size, seed);
			u64 diff = ha ^ hb;

			for (int bit = 0; bit < 64; ++bit) {
				if (diff & (1ULL << bit)) {
					bias[bit]++;
				}
			}
			total_tests++;
		}

		/*
		println(
		    "LongNeighbors64 (seed={}) — 500 single-bit diffs in 128KB "
		    "keys:",
		    seed);
		    */
		for (int bit = 0; bit < 64; ++bit) {
			f64 percent = 100.0 * bias[bit] / total_tests;
			/*
			println("  bit {:2}: {:3} flips → {:5.2}", bit,
				bias[bit], percent);
				*/
			(void)percent;
		}

		int failed = 0;
		for (int bit = 0; bit < 64; ++bit) {
			f64 p = 100.0 * bias[bit] / total_tests;
			if (p < 44.0 || p > 56.0) {
				failed++;
			}
		}

		total_fail += (failed != 0);
	}

	// println("total_failed={}/{}", total_fail, iter);
}

#define SYMCRYPT_COUNT ((1000000 / 32))

Test(storm_perf) {
	i64 timer;
	__attribute__((aligned(32))) u8 text[32] = {0};
	u64* v = (void*)text;
	StormContext ctx;
	u64 sum = 0;

	u8* vg = getenv("VALGRIND");
	if (vg && strlen(vg) == 1 && !memcmp(vg, "1", 1)) return;

	storm_init(&ctx, ZERO_SEED);

	timer = micros();
	for (u32 i = 0; i < SYMCRYPT_COUNT; i++) {
		storm_xcrypt_buffer(&ctx, text);
		sum += *v;
		// println("{X}", *v);
	}
	timer = micros() - timer;
	(void)sum;
	/* println("time={},r={},avg={}ns", timer, sum,
		(timer * 1000) / SYMCRYPT_COUNT);*/
}

Test(storm_perf2) {
	i64 timer;
	__attribute__((aligned(32))) u8 buf1[64] = {0};
	__attribute__((aligned(32))) u8 buf2[64] = {0};
	__attribute__((aligned(32))) u8 buf3[64] = {0};
	__attribute__((aligned(32))) u8 buf4[64] = {0};

	StormContext ctx1;
	StormContext ctx2;
	StormContext ctx3;
	StormContext ctx4;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	u64 sum = 0;

	(void)sum;

	storm_init(&ctx1, ZERO_SEED);
	storm_init(&ctx2, ONE_SEED);
	storm_init(&ctx3, TWO_SEED);
	storm_init(&ctx4, THREE_SEED);

	timer = micros();
	for (u32 i = 0; i < SYMCRYPT_COUNT; i++) {
		u8* block1 = buf1 + (i & 32);
		u8* block2 = buf2 + (i & 32);
		u8* block3 = buf3 + (i & 32);
		u8* block4 = buf4 + (i & 32);

		storm_xcrypt_buffer(&ctx1, block1);
		sum += ((u64*)block1)[0];
		storm_xcrypt_buffer(&ctx2, block2);
		sum += ((u64*)block2)[0];
		storm_xcrypt_buffer(&ctx3, block3);
		sum += ((u64*)block3)[0];
		storm_xcrypt_buffer(&ctx4, block4);
		sum += ((u64*)block4)[0];
	}
	timer = micros() - timer;

	/*
	println("time={}us, sum={}, avg={}ns", timer, sum,
		(timer * 1000) / SYMCRYPT_COUNT);
		*/
}

Test(storm_longneighbors) {
	Rng rng;
	StormContext ctx;
	(void)ctx;
	u8 a[32] __attribute__((aligned(32))) = {0};
	u8 b[32] __attribute__((aligned(32))) = {0};
	u8 __attribute__((aligned(32))) key[32] = {0};
	u32 iter = 1000;
	u32 trials = 10000;
	u32 total_fail = 0;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	(void)total_fail;

	rng_init(&rng, NULL);
	rng_test_seed(&rng, ZERO_SEED);
	f64 max = 0.0, min = 100.0;

	for (u32 i = 0; i < iter; i++) {
		rng_gen(&rng, key, 32);
		storm_init(&ctx, key);
		u64 zeros[256] = {0};
		u64 ones[256] = {0};

		for (u32 j = 0; j < trials; j++) {
			fastmemcpy(b, a, 32);
			storm_xcrypt_buffer(&ctx, a);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 32;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);

			storm_xcrypt_buffer(&ctx, b);

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

	/*
		println("total_failed(storm)={}/{},diff={}", total_fail,
			iter * 256, max - min);
			*/
}

Test(storm_vector) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 key[32] = {0};
	__attribute__((aligned(32))) u8 buf[32] = {0};

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	storm_init(&ctx, key);
	storm_xcrypt_buffer(&ctx, buf);

	u8 expected[32] = {139, 231, 18,  148, 147, 111, 68,  147, 28,	62,  83,
			   6,	32,  160, 243, 30,  117, 133, 168, 133, 130, 56,
			   183, 98,  92,  255, 62,  128, 176, 240, 123, 96};

	// for (u32 i = 0; i < 32; i++) println("{},", buf[i]);
	ASSERT(!memcmp(buf, expected, 32), "0 vector");

	storm_xcrypt_buffer(&ctx, buf);
	// for (u32 i = 0; i < 32; i++) print("{},", buf[i]);

	u8 expected2[32] = {242, 175, 190, 246, 110, 89,  178, 98,
			    181, 26,  85,  141, 43,  233, 200, 139,
			    86,	 109, 235, 205, 148, 225, 9,   157,
			    202, 151, 169, 38,	49,  111, 141, 187};
	ASSERT(!memcmp(buf, expected2, 32), "next vector");
	(void)expected;
	(void)expected2;

	storm_init(&ctx, ONE_SEED);
	memset(buf, 0, 32);
	storm_xcrypt_buffer(&ctx, buf);
	// for (u32 i = 0; i < 32; i++) println("{},", buf[i]);
	u8 expected3[32] = {109, 148, 97,  1,	144, 108, 65,  149,
			    251, 12,  134, 225, 243, 203, 75,  166,
			    116, 133, 168, 133, 130, 56,  183, 98,
			    92,	 255, 62,  128, 176, 240, 123, 96};
	ASSERT(!memcmp(buf, expected3, 32), "expected3");
	storm_xcrypt_buffer(&ctx, buf);
	// for (u32 i = 0; i < 32; i++) println("{},", buf[i]);
	u8 expected4[32] = {133, 219, 225, 147, 114, 181, 160, 4,
			    237, 23,  158, 4,	82,  217, 227, 209,
			    160, 57,  34,  150, 105, 43,  82,  115,
			    162, 108, 212, 222, 145, 89,  115, 189};
	ASSERT(!memcmp(buf, expected4, 32), "expected4");
}

Test(storm_cross_half_diffusion) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 key[32] = {
	    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
	    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	storm_init(&ctx, key);

	u8 first_high[16];
	int total_diff = 0;
	int runs = 0;

	for (int test = 1; test <= 255; test++) {
		u8 block[32] = {0};
		block[0] = (u8)test;

		__attribute__((aligned(32))) u8 ct[32];
		memcpy(ct, block, 32);
		storm_xcrypt_buffer(&ctx, ct);

		u8* high = ct + 16;

		if (test == 1) {
			memcpy(first_high, high, 16);
			continue;
		}

		int diff_bits = 0;
		for (int i = 0; i < 16; i++)
			diff_bits +=
			    __builtin_popcount(high[i] ^ first_high[i]);

		total_diff += diff_bits;
		runs++;

		ASSERT(diff_bits >= 40 && diff_bits <= 90,
		       "Cross-half diffusion out of range: {} bits "
		       "(test={})",
		       diff_bits, test);
	}

	double avg = (double)total_diff / runs;
	ASSERT(avg >= 58 && avg <= 70, "Average diffusion too weak");
}
Test(storm_key_recovery_integral) {
	Rng rng;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	rng_init(&rng, NULL);
	rng_test_seed(&rng, ZERO_SEED);

	StormContext ctx;
	__attribute__((aligned(32))) u8 key[32];
	rng_gen(&rng, key, 32);

	storm_init(&ctx, key);

	const int N = 1 << 24;
	u8* ct = map(N * 32);
	ASSERT(ct, "alloc");

	for (u32 i = 0; i < N; i++) {
		memset(ct + i * 32, 0, 32);
		u8 val = i;
		u8 val2 = i >> 8;
		u8 val3 = i >> 16;
		ct[i * 32 + 0] = val;
		ct[i * 32 + 5] = val;
		ct[i * 32 + 10] = val;
		ct[i * 32 + 15] = val;

		ct[i * 32 + 0] ^= val2;
		ct[i * 32 + 5] ^= val2;
		ct[i * 32 + 10] ^= val2;
		ct[i * 32 + 15] ^= val2;

		ct[i * 32 + 0] ^= val3;
		ct[i * 32 + 5] ^= val3;
		ct[i * 32 + 10] ^= val3;
		ct[i * 32 + 15] ^= val3;
	}

	for (u32 i = 0; i < N; i++) {
		__attribute__((aligned(32))) u8 block[32];
		memcpy(block, ct + i * 32, 32);
		storm_xcrypt_buffer(&ctx, block);
		memcpy(ct + i * 32, block, 32);
	}

	u64 xor0 = 0, xor5 = 0, xor10 = 0, xor15 = 0;
	for (u32 i = 0; i < N; i++) {
		xor0 ^= ct[i * 32 + 0];
		xor5 ^= ct[i * 32 + 5];
		xor10 ^= ct[i * 32 + 10];
		xor15 ^= ct[i * 32 + 15];
	}

	u32 active_xor = (u32)xor0 ^ (u32)xor5 ^ (u32)xor10 ^ (u32)xor15;

	ASSERT(active_xor, "active_xor");

	munmap(ct, N * 32);
}

Test(storm_2round_integral_distinguisher) {
	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	Rng rng;
	rng_init(&rng, NULL);
	rng_test_seed(&rng, ZERO_SEED);

	StormContext ctx;
	__attribute__((aligned(32))) u8 key[32];

	const u32 N = 1 << 19;
	u64 xor_sum[32] = {0};

	for (u32 exp = 0; exp < 16; exp++) {
		rng_gen(&rng, key, 32);
		storm_init(&ctx, key);

		for (u32 i = 0; i < N; i++) {
			__attribute__((aligned(32))) u8 block[32] = {0};

			block[0] = (u8)i;
			block[1] = 0xAA;
			block[2] = 0x55;
			block[3] = 0xCC;

			storm_xcrypt_buffer(&ctx, block);

			for (int j = 0; j < 32; j++) xor_sum[j] ^= block[j];
		}
	}

	u32 zero_bytes = 0;
	for (int j = 0; j < 32; j++)
		if (xor_sum[j] == 0) zero_bytes++;

	ASSERT(zero_bytes <= 24,
	       "2-round integral distinguisher triggered! "
	       "Too many zero XORs ({}). Cipher is structurally broken.",
	       zero_bytes);
}

Test(bible1) {
	__attribute__((aligned(32))) u64 sbox[256];
	bible_sbox8_64(sbox);
	// for (u32 i = 0; i < 256; i++) println("sbox[{}]={X},", i, sbox[i]);
}

Test(rng2) {
	Rng rng;
	rng_init(&rng, NULL);
	for (i32 i = 0; i < 10; i++) {
		u64 v;
		rng_gen(&rng, &v, sizeof(v));
		// println("v={}", v);
	}
}

Test(lattice) {
	__attribute__((aligned(32))) u8 skey[32] = {0, 1, 2};
	u8 msg[128] = {0};
	LatticeSK sk;
	LatticeSig sig;
	lattice_skey(skey, &sk);
	lattice_sign(&sk, msg, &sig);
}
