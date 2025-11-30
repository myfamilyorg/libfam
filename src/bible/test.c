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
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/mine.h>
#include <libfam/test_base.h>

#define BDAT_PATH "resources/test_bible.dat"

const Bible *b = NULL;
static void init_bible(void) {
	i32 fd;
	if (b) return;

	fd = open(BDAT_PATH, O_RDONLY, 0);
	if (fd < 0) {
		b = bible_gen();
		bible_store(b, BDAT_PATH);
	} else
		b = bible_load(BDAT_PATH);
	if (fd > 0) close(fd);
}

Test(bible1) {
	u8 out[32];
	u64 sbox[256];

	generate_sbox8_64(sbox);
	init_bible();

	bible_pow_hash(b, "", 0, out, sbox);
	u8 exp1[] = {203, 5,   87,  183, 8,   170, 190, 181, 213, 77,  229,
		     105, 122, 22,  239, 188, 79,  183, 233, 207, 236, 1,
		     15,  159, 223, 74,	 247, 13,  199, 73,  219, 179, 215,
		     196, 209, 49,  233, 23,  66,  146, 201, 140, 99,  239,
		     155, 171, 19,  155, 83,  118, 111, 73,  13,  188, 243,
		     184, 195, 139, 113, 139, 38,  244, 39,  148};

	ASSERT(!memcmp(exp1, out, 32), "hash1");
	bible_pow_hash(b, "1", 1, out, sbox);

	ASSERT(!memcmp(exp1 + 32, out, 32), "hash2");
	bible_destroy(b);
	b = NULL;
}

Test(mine1) {
	u32 nonce;
	u8 h1[HEADER_LEN] = {38};
	u8 t1[32], out[32];
	u64 sbox[256];

	generate_sbox8_64(sbox);

	memset(t1, 0xFF, 32);
	t1[0] = 0x00;
	init_bible();
	i64 timer = micros();
	mine_block(b, h1, t1, out, &nonce, U32_MAX, sbox);
	timer = micros() - timer;
	(void)timer;

	/*
	write_num(2, timer);
	pwrite(2, "\n", 1, 0);
	write_num(2, nonce);
	pwrite(2, "\n", 1, 0);
	*/

	bible_destroy(b);
	b = NULL;
}
