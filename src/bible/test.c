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
#include <libfam/sysext.h>
#include <libfam/test_base.h>

Test(bible1) {
	const Bible *b1 = bible();
	__attribute__((aligned(32))) u8 out[BIBLE_LOOKUP_SIZE];
	bible_lookup(b1, 0, out);
	ASSERT(
	    !memcmp(out, "Genesis||1||1||In the beginning ", BIBLE_LOOKUP_SIZE),
	    "v1");

	bible_lookup(b1, 1, out);

	ASSERT(
	    !memcmp(out, "God created the heaven and the e", BIBLE_LOOKUP_SIZE),
	    "v2");

	bible_lookup(b1, (4634240 >> 5) - 1, out);
	ASSERT(!memcmp(out, "e with you all. Amen.         \r\n",
		       BIBLE_LOOKUP_SIZE),
	       "last verse");

	bible_lookup(b1, (4634240 >> 5), out);
	ASSERT(
	    !memcmp(out, "Genesis||1||1||In the beginning ", BIBLE_LOOKUP_SIZE),
	    "v1 wrap");
}
