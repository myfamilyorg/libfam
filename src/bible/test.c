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
#include <libfam/test.h>

void __attribute__((constructor)) __init_bible(void) { init_bible(); }

Test(bible1) {
	u8 buf[MAX_VERSE_LEN];
	const Bible *b = bible();
	bible_verse(b, 0, buf);
	ASSERT(!strcmp(buf,
		       "Genesis||1||1||In the beginning God created the heaven "
		       "and the earth."),
	       "gen11");
	bible_verse(b, BIBLE_VERSE_COUNT - 1, buf);
	ASSERT(!strcmp(buf,
		       "Revelation||22||21||The grace of our Lord Jesus Christ "
		       "be with you all. Amen."),
	       "rev2221");
}

i32 bible_check_hash(const u8 *text, u64 len);
void __init_bible(void);

Test(bible2) {
	ASSERT_EQ(bible_check_hash("testtest", 8), -1, "invalid hash");
	_debug_no_exit = true;
	_debug_no_write = true;
	_debug_bible_invalid_hash = true;

	__init_bible();

	_debug_bible_invalid_hash = false;
	_debug_no_exit = false;
	_debug_no_write = false;
}
