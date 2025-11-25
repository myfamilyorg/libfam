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

#include <libfam/bible_hash.h>
#include <libfam/sha3.h>
#include <libfam/string.h>
#include <libfam/test_base.h>

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

Test(bible_hash) {
	u8 out[32];
	const Bible* b = bible();
	bible_pow_hash(b, "1", 1, out, 1);

	static const u8 expected_hash1[32] = {
	    144, 28,  87,  184, 50,  217, 238, 183, 229, 155, 181,
	    82,	 205, 119, 102, 122, 98,  32,  80,  21,	 99,  142,
	    61,	 136, 110, 104, 130, 22,  126, 39,  141, 75};

	ASSERT(memcmp(out, expected_hash1, 32) == 0, "hash1");
	bible_pow_hash(b, "2", 1, out, 1);

	static const u8 expected_hash2[32] = {
	    13,	 4,   38,  137, 31,  121, 222, 26, 189, 237, 27,
	    36,	 112, 197, 16,	109, 141, 119, 23, 144, 66,  210,
	    150, 122, 185, 160, 77,  10,  131, 37, 168, 161};

	ASSERT(memcmp(out, expected_hash2, 32) == 0, "hash2");

	const u8* s =
	    "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F562"
	    "3CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A1535"
	    "8F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0A3D84A"
	    "2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764B2F83AAD"
	    "C66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43C70088B618"
	    "3639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D817FC2534A52"
	    "F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E085172E328807C02"
	    "D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1";
	bible_pow_hash(b, s, strlen(s), out, 1);

	static const u8 expected_hash3[32] = {
	    147, 121, 248, 113, 102, 246, 133, 21,  121, 105, 62,
	    56,	 139, 199, 222, 183, 89,  221, 98,  102, 28,  248,
	    32,	 148, 50,  202, 47,  155, 100, 202, 12,	 246};

	ASSERT(memcmp(out, expected_hash3, 32) == 0, "hash3");
}
