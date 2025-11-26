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

#include <libfam/bible.h>
#include <libfam/linux.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

/*
Test(bible_hash) {
	u8 out[32];
	i64 timer = micros();
	const Bible* b =
	    bible_load("/home/chris/projects/libfam/resources/bible.dat");
	ASSERT(b, "load");
	timer = micros() - timer;
	write_num(2, timer);
	bible_pow_hash(b, "1", 1, out);

	static const u8 expected_hash1[32] = {
	    161, 149, 116, 140, 221, 77,  209, 188, 170, 186, 48,
	    236, 79,  233, 80,	254, 114, 76,  228, 198, 74,  120,
	    112, 132, 135, 111, 165, 156, 231, 34,  59,	 6};

	ASSERT(memcmp(out, expected_hash1, 32) == 0, "hash1");
	bible_pow_hash(b, "2", 1, out);

	static const u8 expected_hash2[32] = {
	    242, 157, 24,  139, 215, 245, 124, 178, 231, 41,  35,
	    164, 82,  215, 66,	129, 203, 232, 195, 235, 243, 239,
	    244, 107, 253, 71,	61,  202, 41,  211, 132, 187};

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
	bible_pow_hash(b, s, strlen(s), out);

	static const u8 expected_hash3[32] = {
	    102, 170, 192, 21,	116, 6,	  44, 224, 115, 8,   241,
	    185, 58,  143, 16,	206, 183, 28, 45,  0,	246, 212,
	    114, 82,  124, 236, 221, 87,  11, 192, 174, 136};

	ASSERT(memcmp(out, expected_hash3, 32) == 0, "hash3");

	bible_destroy(b);
}

*/
