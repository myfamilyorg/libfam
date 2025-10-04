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
#include <libfam/b64.h>
#include <libfam/debug.h>
#include <libfam/errno.h>
#include <libfam/linux.h>
#include <libfam/rng.h>
#include <libfam/sha1.h>
#include <libfam/sha3.h>
#include <libfam/syscall.h>
#include <libfam/test_base.h>

Test(b64) {
	u8 buf[128];
	u8 buf2[128];
	u8 buf3[128];
	i32 len, len2, i;
	memcpy(buf, "0123456789", 10);
	len = b64_encode(buf, 10, buf2, 128);
	len2 = b64_decode(buf2, len, buf3, 128);
	ASSERT_EQ(len2, 10, "len=10");
	ASSERT_EQ(buf3[0], '0', "0");
	ASSERT_EQ(buf3[1], '1', "1");
	ASSERT_EQ(buf3[2], '2', "2");
	ASSERT_EQ(buf3[3], '3', "3");
	ASSERT_EQ(buf3[4], '4', "4");
	ASSERT_EQ(buf3[5], '5', "5");
	ASSERT_EQ(buf3[6], '6', "6");
	ASSERT_EQ(buf3[7], '7', "7");
	ASSERT_EQ(buf3[8], '8', "8");
	ASSERT_EQ(buf3[9], '9', "9");
	ASSERT(!b64_decode(NULL, 0, NULL, 0), "decode NULL");
	ASSERT(!b64_decode("test", 4, buf3, 0), "decode insufficient space");
	ASSERT(!b64_decode(buf2, len, buf3, 5),
	       "insufficient space larger buf");
	for (i = 0; i < 10; i++) buf2[i] = '*';
	ASSERT(!b64_decode(buf2, len, buf3, sizeof(buf3)), "invalid buf");
}

static void assert_b64_eq(const u8* out, const u8* expected, const u8* msg) {
	ASSERT(!strcmp((const u8*)out, expected), msg);
}

Test(b642) {
	u8 buf[128];
	u8 buf2[128];
	u8 buf3[128];
	u64 len, len2;

	memcpy(buf, "0123456789", 10);
	len = b64_encode(buf, 10, buf2, 128);
	ASSERT_EQ(len, 16, "normal_len");
	assert_b64_eq(buf2, "MDEyMzQ1Njc4OQ==", "normal_encode");
	len2 = b64_decode(buf2, len, buf3, 128);
	ASSERT_EQ(len2, 10, "normal_decode_len");
	ASSERT(!memcmp(buf3, "0123456789", 10), "normal_decode");

	memcpy(buf, "ab", 2);
	len = b64_encode(buf, 2, buf2, 128);
	ASSERT_EQ(len, 4, "two_byte_len");
	assert_b64_eq(buf2, "YWI=", "two_byte_encode");
	len2 = b64_decode(buf2, len, buf3, 128);
	ASSERT_EQ(len2, 2, "two_byte_decode_len");
	ASSERT(!memcmp(buf3, "ab", 2), "two_byte_decode");

	memcpy(buf, "x", 1);
	len = b64_encode(buf, 1, buf2, 128);
	ASSERT_EQ(len, 4, "single_byte_len");
	assert_b64_eq(buf2, "eA==", "single_byte_encode");
	len2 = b64_decode(buf2, len, buf3, 128);
	ASSERT_EQ(len2, 1, "single_byte_decode_len");

	ASSERT(!memcmp(buf3, "x", 1), "single_byte_decode");

	len = b64_encode(buf, 0, buf2, 128);
	ASSERT_EQ(len, 0, "empty_len");
	ASSERT_EQ(buf2[0], 0, "empty_no_write");

	len = b64_encode(NULL, 5, buf2, 128);
	ASSERT_EQ(len, 0, "null_in_len");
	len = b64_encode(buf, 5, NULL, 128);
	ASSERT_EQ(len, 0, "null_out_len");

	memcpy(buf, "abc", 3);
	len = b64_encode(buf, 3, buf2, 4);
	ASSERT_EQ(len, 0, "insufficient_out_len");
	ASSERT_EQ(buf2[0], 0, "insufficient_no_write");

	memcpy(buf, "abcde", 5);
	len = b64_encode(buf, 5, buf2, 128);
	ASSERT_EQ(len, 8, "five_byte_len");
	assert_b64_eq(buf2, "YWJjZGU=", "five_byte_encode");
	len2 = b64_decode(buf2, len, buf3, 128);
	ASSERT_EQ(len2, 5, "five_byte_decode_len");
	ASSERT(!memcmp(buf3, "abcde", 5), "five_byte_decode");
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
	u8 out[64] = {
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

	ASSERT(!memcmp((u8*)out, (u8*)in, 64), "aes256 test vector");
}

void hex_to_bytes(const char* hex, u8* bytes, u64 len) {
	u64 i;
	u8 high;
	u8 low;
	u8 byte;

	for (i = 0; i < len; i++) {
		high = hex[2 * i];
		low = hex[2 * i + 1];

		if (high == 0 || low == 0) {
			ASSERT(0, "bad hex value");
		}

		byte = (high <= '9' ? high - '0' : high - 'A' + 10) << 4;
		byte |= (low <= '9' ? low - '0' : low - 'A' + 10);
		bytes[i] = byte;
	}
}

Test(sha1) {
	u64 v = 123;
	u8 digest[20] = {0};
	u8 out[33] = {0};
	u8 buf4[64] = {4};
	u8 buflong[256] = {5};
	SHA1_CTX ctx = {0};
	sha1_init(&ctx);
	sha1_update(&ctx, &v, sizeof(u64));
	sha1_final(&ctx, digest);
	b64_encode(digest, 20, out, 33);
	ASSERT(!strcmp(out, "bdYNn8pZRfNzUKFV3N4reh2uX2Y="),
	       "bdYNn8pZRfNzUKFV3N4reh2uX2Y=");
	sha1_init(&ctx);
	sha1_update(&ctx, buf4, 60);
	sha1_final(&ctx, digest);
	b64_encode(digest, 20, out, 33);
	ASSERT(!strcmp(out, "pxH2MkE8YEMdKFrJl1vWVxsVRzA="),
	       "pxH2MkE8YEMdKFrJl1vWVxsVRzA=");
	sha1_init(&ctx);
	sha1_update(&ctx, buflong, 252);
	sha1_update(&ctx, buflong, 150);
	sha1_final(&ctx, digest);
	b64_encode(digest, 20, out, 33);
	ASSERT(!strcmp(out, "UPbAbd1BjBI1Q+p8zMFyP2vVIjw="),
	       "UPbAbd1BjBI1Q+p8zMFyP2vVIjw=");
}

Test(rng) {
	Rng rng;
	u8 key[32] = {0};
	u8 iv[16] = {1};
	u64 v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0, v6 = 0;
	rng_init(&rng);
	rng_gen(&rng, &v1, sizeof(u64));
	rng_gen(&rng, &v2, sizeof(u64));
	ASSERT(v1 != v2, "v1!=v2");
	ASSERT(v1 != 0, "v1!=0");
	ASSERT(v2 != 0, "v2!=0");

	rng_test_seed(&rng, key, iv);
	rng_gen(&rng, &v3, sizeof(u64));
	rng_gen(&rng, &v4, sizeof(u64));
	ASSERT_EQ(v3, 15566405176654077661UL, "v3=15566405176654077661");
	ASSERT_EQ(v4, 2865243117314082982UL, "v4=2865243117314082982");

	rng_reseed(&rng);

	rng_gen(&rng, &v5, sizeof(u64));
	rng_gen(&rng, &v6, sizeof(u64));
	ASSERT(v5 != v6, "v5!=v6");
	ASSERT(v5 != 0, "v5!=0");
	ASSERT(v6 != 0, "v6!=0");
}

/* Convert two lowercase hex chars ('0'-'9', 'a'-'f') to a u8 value */
u8 hex_to_nibble(u8 v1, u8 v2) {
	u8 high;
	u8 low;
	u8 val;

	/* Convert first char (high nibble) */
	if (v1 >= '0' && v1 <= '9') {
		high = v1 - '0'; /* '0'-'9' → 0-9 */
	} else if (v1 >= 'a' && v1 <= 'f') {
		high = v1 - 'a' + 10; /* 'a'-'f' → 10-15 */
	} else {
		high = 0; /* Invalid char, return 0 */
	}

	/* Convert second char (low nibble) */
	if (v2 >= '0' && v2 <= '9') {
		low = v2 - '0'; /* '0'-'9' → 0-9 */
	} else if (v2 >= 'a' && v2 <= 'f') {
		low = v2 - 'a' + 10; /* 'a'-'f' → 10-15 */
	} else {
		low = 0; /* Invalid char, return 0 */
	}

	/* Combine nibbles: high << 4 | low */
	val = (high << 4) | low;
	return val;
}

/* Convert a null-terminated lowercase hex string to a u8 byte array */
void hex_to_bytes2(const u8* hex, u8* bytes) {
	u32 i;
	u8 high;
	u8 low;
	u32 out_len;

	/* Initialize output index */
	out_len = 0;

	/* Process hex string in pairs until null terminator */
	for (i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
		/* Convert first char (high nibble) */
		if (hex[i] >= '0' && hex[i] <= '9') {
			high = hex[i] - '0'; /* '0'-'9' → 0-9 */
		} else {
			high = hex[i] - 'a' + 10; /* 'a'-'f' → 10-15 */
		}

		/* Convert second char (low nibble) */
		if (hex[i + 1] >= '0' && hex[i + 1] <= '9') {
			low = hex[i + 1] - '0'; /* '0'-'9' → 0-9 */
		} else {
			low = hex[i + 1] - 'a' + 10; /* 'a'-'f' → 10-15 */
		}

		/* Combine nibbles into byte */
		bytes[out_len] = (high << 4) | low;
		out_len++;
	}
}

bool hex_32_byte_check(const u8* expected_hex, const u8* value) {
	i32 i;
	bool ret = true;
	for (i = 0; i < 48; i++) {
		u8 val =
		    hex_to_nibble(expected_hex[i * 2], expected_hex[i * 2 + 1]);
		if (val != value[i]) ret = false;
	}
	return ret;
}

void sha3_check(const u8* in, u8* expected) {
	Sha3Context ctx;
	u8 buf[128] = {0};
	u64 len = strlen(in);

	hex_to_bytes2(in, buf);
	sha3_init384(&ctx);
	sha3_update(&ctx, buf, len / 2);
	ASSERT(hex_32_byte_check(expected, sha3_finalize(&ctx)), in);
	sha3_update(&ctx, buf, len); /* Exercise multiple updates */
}

Test(sha3) {
	sha3_check("",
		   "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee9"
		   "83a2ac3713831264adb47fb6bd1e058d5f004");
	sha3_check("80",
		   "7541384852e10ff10d5fb6a7213a4a6c15ccc86d8bc1068ac04f6927714"
		   "2944f4ee50d91fdc56553db06b2f5039c8ab7");

	sha3_check("fb52",
		   "d73a9d0e7f1802352ea54f3e062d3910577bf87edda48101de92a3de957"
		   "e698b836085f5f10cab1de19fd0c906e48385");

	sha3_check(
	    "7af3feed9b0f6e9408e8c0397c9bb671d0f3f80926d2f48f68d2e814f12b3d3189"
	    "d8174897f52a0c926ccf44b9d057cc04899fdc5a32e48c043fd99862e3f761dc31"
	    "15351c8138d07a15ac23b8fc5454f0373e05ca1b7ad9f2f62d34caf5e1435c",
	    "00e95f4e8a32a03e0a3afba0fd62c7c3c7120b41e297a7ff14958c0bdf015a478f"
	    "7bab9a22082bfb0d206e88f4685117");
}

Test(sha3_others) {
	Sha3Context ctx;
	const u8* out;
	sha3_init512(&ctx);
	sha3_update(&ctx, "", 0);
	out = sha3_finalize(&ctx);
	ASSERT_EQ(out[0], 166, "512-0");
	ASSERT_EQ(out[1], 159, "512-1");
	ASSERT_EQ(out[2], 115, "512-2");
	sha3_init256(&ctx);
	sha3_update(&ctx, "", 0);
	out = sha3_finalize(&ctx);
	ASSERT_EQ(out[0], 167, "256-0");
	ASSERT_EQ(out[1], 255, "256-1");
	ASSERT_EQ(out[2], 198, "256-2");
}
