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

#include <libfam/aes.h>
#include <libfam/aighthash.h>
#include <libfam/bible.h>
#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/rng.h>
#include <libfam/sha3.h>
#include <libfam/string.h>
#include <libfam/symcrypt.h>
#include <libfam/test.h>

u8 hex_to_nibble(u8 v1, u8 v2) {
	u8 high;
	u8 low;
	u8 val;

	if (v1 >= '0' && v1 <= '9')
		high = v1 - '0';
	else if (v1 >= 'a' && v1 <= 'f')
		high = v1 - 'a' + 10;
	else if (v1 >= 'A' && v1 <= 'F')
		high = v1 - 'A' + 10;
	else
		high = 0;

	if (v2 >= '0' && v2 <= '9')
		low = v2 - '0';
	else if (v2 >= 'a' && v2 <= 'f')
		low = v2 - 'a' + 10;
	else if (v2 >= 'A' && v2 <= 'F')
		low = v2 - 'A' + 10;
	else
		low = 0;
	val = (high << 4) | low;
	return val;
}

void hex_to_bytes(const u8* hex, u8* bytes) {
	u8 high, low;
	u32 out_len = 0;

	for (u32 i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
		if (hex[i] >= '0' && hex[i] <= '9')
			high = hex[i] - '0';
		else if (hex[i] >= 'A' && hex[i] <= 'F')
			high = hex[i] - 'A' + 10;
		else
			high = hex[i] - 'a' + 10;

		if (hex[i + 1] >= '0' && hex[i + 1] <= '9')
			low = hex[i + 1] - '0';
		else if (hex[i + 1] >= 'A' && hex[i + 1] <= 'F')
			low = hex[i + 1] - 'A' + 10;
		else
			low = hex[i + 1] - 'a' + 10;

		bytes[out_len] = (high << 4) | low;
		out_len++;
	}
}

bool hex_byte_check(const u8* expected_hex, const u8* value, u32 bytes) {
	i32 i;
	bool ret = true;
	for (i = 0; i < bytes; i++) {
		u8 val =
		    hex_to_nibble(expected_hex[i * 2], expected_hex[i * 2 + 1]);
		if (val != value[i]) ret = false;
	}
	return ret;
}

void sha3_check256(const u8* in, u8* expected) {
	Sha3Context ctx = {0};
	u8 buf[4096] = {0};
	u64 len = strlen(in);

	hex_to_bytes(in, buf);
	sha3_init256(&ctx);
	sha3_update(&ctx, buf, len / 2);
	ASSERT(hex_byte_check(expected, sha3_finalize(&ctx), 32), in);
	sha3_update(&ctx, buf, len);
}

void sha3_check384(const u8* in, u8* expected) {
	Sha3Context ctx;
	u8 buf[4096] = {0};
	u64 len = strlen(in);

	hex_to_bytes(in, buf);
	sha3_init384(&ctx);
	sha3_update(&ctx, buf, len / 2);
	ASSERT(hex_byte_check(expected, sha3_finalize(&ctx), 48), in);
	sha3_update(&ctx, buf, len);
}

void sha3_check512(const u8* in, u8* expected) {
	Sha3Context ctx;
	u8 buf[4096] = {0};
	u64 len = strlen(in);

	hex_to_bytes(in, buf);
	sha3_init512(&ctx);
	sha3_update(&ctx, buf, len / 2);
	ASSERT(hex_byte_check(expected, sha3_finalize(&ctx), 64), in);
	sha3_update(&ctx, buf, len);
}

Test(sha3) {
	sha3_check256(
	    "",
	    "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A");
	sha3_check256(
	    "CC",
	    "677035391CD3701293D385F037BA32796252BB7CE180B00B582DD9B20AAAD7F0");
	sha3_check256(
	    "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F562"
	    "3CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A1535"
	    "8F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0A3D84A"
	    "2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764B2F83AAD"
	    "C66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43C70088B618"
	    "3639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D817FC2534A52"
	    "F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E085172E328807C02"
	    "D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1",
	    "C11F3522A8FB7B3532D80B6D40023A92B489ADDAD93BF5D64B23F35E9663521C");
	sha3_check384(
	    "",
	    "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee9"
	    "83a2ac3713831264adb47fb6bd1e058d5f004");
	sha3_check384(
	    "80",
	    "7541384852e10ff10d5fb6a7213a4a6c15ccc86d8bc1068ac04f6927714"
	    "2944f4ee50d91fdc56553db06b2f5039c8ab7");

	sha3_check384(
	    "fb52",
	    "d73a9d0e7f1802352ea54f3e062d3910577bf87edda48101de92a3de957"
	    "e698b836085f5f10cab1de19fd0c906e48385");

	sha3_check384(
	    "7af3feed9b0f6e9408e8c0397c9bb671d0f3f80926d2f48f68d2e814f12b3d3189"
	    "d8174897f52a0c926ccf44b9d057cc04899fdc5a32e48c043fd99862e3f761dc31"
	    "15351c8138d07a15ac23b8fc5454f0373e05ca1b7ad9f2f62d34caf5e1435c",
	    "00e95f4e8a32a03e0a3afba0fd62c7c3c7120b41e297a7ff14958c0bdf015a478f"
	    "7bab9a22082bfb0d206e88f4685117");

	sha3_check384(
	    "",
	    "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE9"
	    "83A2AC3713831264ADB47FB6BD1E058D5F004");

	sha3_check384(
	    "CC",
	    "5EE7F374973CD4BB3DC41E3081346798497FF6E36CB9352281DFE07D07F"
	    "C530CA9AD8EF7AAD56EF5D41BE83D5E543807");

	sha3_check512(
	    "",
	    "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615"
	    "B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26");
	sha3_check512(
	    "CC",
	    "3939FCC8B57B63612542DA31A834E5DCC36E2EE0F652AC72E02624FA2E5ADEECC7"
	    "DD6BB3580224B4D6138706FC6E80597B528051230B00621CC2B22999EAA205");
}

Test(aes1) {
	u8 key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	u8 in[64] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7,
		     0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca,
		     0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca,
		     0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
		     0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9,
		     0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08,
		     0x45, 0x79, 0x41, 0xa6};

	u8 iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
	u8 exp[64] = {
	    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
	    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
	    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
	    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
	    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
	    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
	AesContext ctx;

	aes_init(&ctx, key, iv);
	aes_set_iv(&ctx, iv);
	aes_ctr_xcrypt_buffer(&ctx, in, 64);

	ASSERT(!memcmp((u8*)exp, (u8*)in, 64), "aes256 test vector");
}

Test(aes1noaesni) {
	_debug_no_aesni = true;
	u8 key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	u8 in[64] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7,
		     0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca,
		     0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca,
		     0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
		     0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9,
		     0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08,
		     0x45, 0x79, 0x41, 0xa6};

	u8 iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
	u8 exp[64] = {
	    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
	    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
	    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
	    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
	    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
	    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
	AesContext ctx;

	aes_init(&ctx, key, iv);
	aes_set_iv(&ctx, iv);
	aes_ctr_xcrypt_buffer(&ctx, in, 64);

	ASSERT(!memcmp((u8*)exp, (u8*)in, 64), "aes256 test vector");
	_debug_no_aesni = false;
}

Test(aes2) {
	u8 key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	u8 in[128] = {
	    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5,
	    0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62,
	    0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 0x2b,
	    0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba,
	    0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad,
	    0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6};

	u8 iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
	AesContext ctx;

	aes_init(&ctx, key, iv);
	u8 out[128] = {0};
	aes256_ctr_encrypt_8blocks(&ctx, in, out);

	aes_set_iv(&ctx, iv);

	aes_ctr_xcrypt_buffer(&ctx, in, 128);
	ASSERT(!memcmp(out, in, 128), "equal");
}

// #include <libfam/format.h>

Test(aes3) {
	AesContext ctx;
	u8 key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	u8 in[128] = {
	    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5,
	    0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62,
	    0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 0x2b,
	    0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba,
	    0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad,
	    0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6};

	u8 iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
	aes_init(&ctx, key, iv);
	u8 out[128] = {0};
	aes256_ctr_encrypt_8blocks(&ctx, in, out);

	aes_set_iv(&ctx, iv);

	u8 dummy[128];
	i64 timer = micros();
	for (u32 i = 0; i < 1024 * 100; i++) {
		aes256_ctr_encrypt_8blocks(&ctx, in, dummy);
	}
	timer = micros() - timer;
	// println("{}", timer);
}

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
	u8 v1[32], v2[32];
	const u8 st[32] = {1, 2, 3};

	random32(v1);
	memcpy(v2, v1, 32);
	ASSERT(!memcmp(v1, v2, 32), "equal");
	random_stir(v2, st);
	ASSERT(memcmp(v1, v2, 32), "equal");
}

#define SIZE (128 * 1024)
Test(aighthash_longneighbors) {
	Rng rng;
	int size = SIZE;
	u8 a[SIZE] = {0};
	u8 b[SIZE] = {0};

	rng_test_seed(&rng, (u8[32]){0}, (u8[32]){0});

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
	Rng rng;
	int size = SIZE;
	u8 a[SIZE] = {0};
	u8 b[SIZE] = {0};

	rng_test_seed(&rng, (u8[32]){0}, (u8[32]){0});
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

Test(sym_crypt_perf) {
	i64 timer;
	u8 text[32] = {0};
	u64* v = (void*)text;
	SymCryptContext ctx;
	u64 sum = 0;

	u8* vg = getenv("VALGRIND");
	if (vg && strlen(vg) == 1 && !memcmp(vg, "1", 1)) return;

	sym_crypt_init(&ctx, (u8[32]){0}, (u8[16]){0});

	timer = micros();
	for (u32 i = 0; i < SYMCRYPT_COUNT; i++) {
		sym_crypt_xcrypt_buffer(&ctx, text);
		sum += *v;
		// println("{X}", *v);
	}
	timer = micros() - timer;
	(void)sum;
	/* println("time={},r={},avg={}ns", timer, sum,
		(timer * 1000) / SYMCRYPT_COUNT);*/
}

Test(sym_crypt_perf2) {
	i64 timer;
	__attribute__((aligned(32))) u8 buf1[64] = {0};
	__attribute__((aligned(32))) u8 buf2[64] = {0};
	__attribute__((aligned(32))) u8 buf3[64] = {0};
	__attribute__((aligned(32))) u8 buf4[64] = {0};

	SymCryptContext ctx1;
	SymCryptContext ctx2;
	SymCryptContext ctx3;
	SymCryptContext ctx4;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	u64 sum = 0;

	(void)sum;

	sym_crypt_init(&ctx1, (u8[32]){0}, (u8[16]){0});
	sym_crypt_init(&ctx2, (u8[32]){1}, (u8[16]){0});
	sym_crypt_init(&ctx3, (u8[32]){2}, (u8[16]){0});
	sym_crypt_init(&ctx4, (u8[32]){3}, (u8[16]){0});

	timer = micros();
	for (u32 i = 0; i < SYMCRYPT_COUNT; i++) {
		u8* block1 = buf1 + (i & 32);
		u8* block2 = buf2 + (i & 32);
		u8* block3 = buf3 + (i & 32);
		u8* block4 = buf4 + (i & 32);

		sym_crypt_xcrypt_buffer(&ctx1, block1);
		sum += ((u64*)block1)[0];
		sym_crypt_xcrypt_buffer(&ctx2, block2);
		sum += ((u64*)block2)[0];
		sym_crypt_xcrypt_buffer(&ctx3, block3);
		sum += ((u64*)block3)[0];
		sym_crypt_xcrypt_buffer(&ctx4, block4);
		sum += ((u64*)block4)[0];
	}
	timer = micros() - timer;

	/*
	println("time={}us, sum={}, avg={}ns", timer, sum,
		(timer * 1000) / SYMCRYPT_COUNT);
		*/
}

Test(symcrypt_longneighbors) {
	Rng rng;
	SymCryptContext ctx;
	AesContext aes;
	bool use_aes = false;
	(void)ctx;
	(void)aes;
	u8 a[32] __attribute__((aligned(32))) = {0};
	u8 b[32] __attribute__((aligned(32))) = {0};
	u8 key[32] = {0};
	u8 iv[16] = {0};
	u32 iter = 1000;
	u32 trials = 10000;
	u32 total_fail = 0;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	(void)total_fail;

	rng_init(&rng, NULL);
	rng_test_seed(&rng, (u8[32]){3}, (u8[32]){0});
	f64 max = 0.0, min = 100.0;

	for (u32 i = 0; i < iter; i++) {
		rng_gen(&rng, key, 32);
		rng_gen(&rng, iv, 16);
		if (!use_aes)
			sym_crypt_init(&ctx, key, iv);
		else
			aes_init(&aes, key, iv);
		u64 zeros[256] = {0};
		u64 ones[256] = {0};

		for (u32 j = 0; j < trials; j++) {
			fastmemcpy(b, a, 32);
			if (!use_aes)
				sym_crypt_xcrypt_buffer(&ctx, a);
			else
				aes_ctr_xcrypt_buffer(&aes, a, 32);

			u64 byte_pos = 0;
			rng_gen(&rng, &byte_pos, sizeof(u64));
			byte_pos %= 32;
			u8 bit_pos = 0;
			rng_gen(&rng, &bit_pos, sizeof(u8));
			bit_pos %= 8;

			b[byte_pos] ^= (u8)(1 << bit_pos);

			if (!use_aes)
				sym_crypt_xcrypt_buffer(&ctx, b);
			else
				aes_ctr_xcrypt_buffer(&aes, b, 32);

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

	if (use_aes)
		println("total_failed(aes)={}/{},diff={}", total_fail,
			iter * 256, max - min);
	else
		println("total_failed(sym_crypt)={}/{},diff={}", total_fail,
			iter * 256, max - min);
}

Test(symcrypt_vector) {
	SymCryptContext ctx;
	u8 key[32] = {0};
	u8 iv[16] = {0};
	u8 buf[32] = {0};

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	sym_crypt_init(&ctx, key, iv);
	sym_crypt_xcrypt_buffer(&ctx, buf);

	u8 expected[32] = {0x9e, 0xfa, 0xe2, 0xfd, 0x41, 0x15, 0xa7, 0x41,
			   0xbf, 0xdf, 0xea, 0x35, 0xa3, 0x3,  0x5,  0xdd,
			   0xf,	 0x82, 0x38, 0xcb, 0x58, 0x57, 0xe8, 0x8f,
			   0x53, 0x7f, 0xb8, 0x81, 0x9e, 0xeb, 0x8f, 0x9e};
	ASSERT(!memcmp(buf, expected, 32), "0 vector");

	sym_crypt_xcrypt_buffer(&ctx, buf);

	u8 expected2[32] = {0x92, 0xeb, 0x8f, 0xaf, 0x5f, 0xb7, 0x14, 0x9,
			    0xae, 0x24, 0x2e, 0x2c, 0x79, 0x6e, 0x1b, 0x34,
			    0x49, 0x78, 0xa,  0xe8, 0x99, 0xe6, 0x66, 0xd2,
			    0x40, 0xf0, 0xb3, 0x48, 0x3c, 0x4a, 0x2f, 0xc};
	ASSERT(!memcmp(buf, expected2, 32), "next vector");
}

Test(symcrypt_cross_half_diffusion) {
	SymCryptContext ctx;
	u8 key[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
	u8 iv[16] = {0};

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	sym_crypt_init(&ctx, key, iv);

	u8 first_high[16];
	int total_diff = 0;
	int runs = 0;

	for (int test = 1; test <= 255; test++) {
		u8 block[32] = {0};
		block[0] = (u8)test;

		u8 ct[32];
		memcpy(ct, block, 32);
		sym_crypt_xcrypt_buffer(&ctx, ct);

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
Test(symcrypt_key_recovery_integral) {
	Rng rng;

	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	rng_init(&rng, NULL);
	rng_test_seed(&rng, (u8[32]){0x37}, (u8[32]){0xEF});

	SymCryptContext ctx;
	u8 key[32];
	u8 iv[16] = {0};
	rng_gen(&rng, key, 32);

	sym_crypt_init(&ctx, key, iv);

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
		sym_crypt_xcrypt_buffer(&ctx, block);
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

Test(symcrypt_2round_integral_distinguisher) {
	u8* v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	Rng rng;
	rng_init(&rng, NULL);
	rng_test_seed(&rng, (u8[32]){0x13}, (u8[32]){0x37});

	SymCryptContext ctx;
	u8 key[32];
	u8 iv[16] = {0};

	const u32 N = 1 << 19;
	u64 xor_sum[32] = {0};

	for (u32 exp = 0; exp < 16; exp++) {
		rng_gen(&rng, key, 32);
		sym_crypt_init(&ctx, key, iv);

		for (u32 i = 0; i < N; i++) {
			__attribute__((aligned(32))) u8 block[32] = {0};

			block[0] = (u8)i;
			block[1] = 0xAA;
			block[2] = 0x55;
			block[3] = 0xCC;

			sym_crypt_xcrypt_buffer(&ctx, block);

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
