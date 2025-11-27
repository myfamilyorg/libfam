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

#define BDAT_PATH "resources/bible.dat"

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

	init_bible();

	bible_pow_hash(b, "", 0, out);
	u8 exp1[] = {106, 189, 246, 61,	 164, 204, 113, 221, 254, 23,  31,
		     163, 12,  190, 142, 203, 121, 98,	239, 212, 200, 205,
		     190, 67,  65,  196, 204, 56,  249, 21,  161, 185};
	ASSERT(!memcmp(exp1, out, 32), "hash1");

	bible_pow_hash(b, "1", 1, out);
	u8 exp2[] = {101, 170, 46,  185, 51,  240, 38, 249, 251, 184, 169,
		     44,  8,   102, 178, 8,   183, 91, 98,  247, 57,  156,
		     254, 207, 49,  188, 218, 173, 58, 0,   24,	 140};

	ASSERT(!memcmp(exp2, out, 32), "hash2");
	bible_destroy(b);
	b = NULL;
}

Test(mine1) {
	u32 nonce;
	u8 h1[HEADER_LEN] = {37};
	u8 t1[32], out[32];
	memset(t1, 0xFF, 32);
	t1[0] = 0x00;
	t1[1] = 0x0F;
	init_bible();
	mine_block(b, h1, t1, out, &nonce, U32_MAX);
	bible_destroy(b);
	b = NULL;
}
