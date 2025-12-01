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
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
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
	u8 input1[HASH_INPUT_LEN] = {0};
	u8 input2[HASH_INPUT_LEN] = {1};

	generate_sbox8_64(sbox);
	init_bible();

	bible_pow_hash(b, input1, out, sbox);
	u8 exp1[] = {58,  228, 51,  119, 163, 164, 246, 160, 239, 217, 146,
		     213, 7,   76,  207, 255, 245, 38,	55,  232, 235, 232,
		     249, 244, 128, 198, 171, 94,  114, 157, 208, 187, 10,
		     42,  154, 28,  72,	 25,  120, 142, 17,  83,  203, 198,
		     26,  110, 58,  67,	 110, 158, 70,	89,  145, 132, 109,
		     185, 121, 201, 25,	 71,  38,  131, 139, 82};

	ASSERT(!memcmp(exp1, out, 32), "hash1");

	// for (u32 i = 0; i < 32; i++) println("{},", out[i]);

	bible_pow_hash(b, input2, out, sbox);
	// for (u32 i = 0; i < 32; i++) println("{},", out[i]);

	ASSERT(!memcmp(exp1 + 32, out, 32), "hash2");
	bible_destroy(b);
	b = NULL;
}

Test(mine1) {
	u32 nonce;
	u8 h1[HASH_INPUT_LEN] = {38};
	u8 t1[32], out[32];
	u64 sbox[256];

	generate_sbox8_64(sbox);

	memset(t1, 0xFF, 32);
	t1[0] = 0x00;
	t1[1] = 0x00;
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
