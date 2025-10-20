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
#include <libfam/debug.h>
#include <libfam/sha3.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>
#include <libfam/xxdir_dat.h>

Bible __bible = {.text = xxdir_file_0};

const u8 BIBLE_HASH[] = {0x4a, 0xfa, 0xea, 0xfb, 0x35, 0xd6, 0x5f, 0x62,
			 0x35, 0xc8, 0x80, 0x63, 0x55, 0x62, 0x60, 0x27,
			 0x54, 0xb9, 0xc2, 0xf8, 0xcb, 0xeb, 0x38, 0x1a,
			 0xfd, 0xe6, 0x6a, 0xf9, 0x49, 0xdf, 0x16, 0x4};

STATIC i32 bible_check_hash(const u8 *text, u64 len) {
	Sha3Context sha3;
	i32 res;
	sha3_init256(&sha3);
	sha3_update(&sha3, text, len);
	res = memcmp(sha3_finalize(&sha3), BIBLE_HASH, sizeof(BIBLE_HASH));
	if (res) {
		errno = EINVAL;
		return -1;
	} else {
		return 0;
	}
}

STATIC void bible_build_offsets(Bible *bible) {
	u64 i, j = 1, len = 0;
	bible->offsets[0] = 0;
	for (i = 0; i < bible->length; i++) {
		if (bible->text[i] == '\n') {
			bible->offsets[j] = i + 1;
			bible->lengths[j - 1] = len - 1;
			j++;
			len = 0;
		} else
			len++;
	}
	bible->lengths[j - 1] = len;
}

void init_bible(void) {
	const u8 *msg = "Bible hash did not match! Halting!\n";
#if TEST == 1
	bool _debug = _debug_bible_invalid_hash;
#else
	bool _debug = false;
#endif /* TEST */

	bool v = _debug
		     ? true
		     : bible_check_hash(xxdir_file_0, xxdir_file_size_0) != 0;
	if (v) {
		i32 __attribute__((unused)) _v;
		_v = write(2, msg, strlen(msg));
		_famexit(-1);
		return;
	}
	__bible.length = xxdir_file_size_0;
	bible_build_offsets(&__bible);
}

void bible_verse(const Bible *bible, u16 verse, u8 buf[MAX_VERSE_LEN]) {
	u16 len = bible->lengths[verse];
	const u8 *text = bible->text + bible->offsets[verse];
	while (len--) *buf++ = *text++;
	*buf = 0;
}

const Bible *bible(void) { return &__bible; }
