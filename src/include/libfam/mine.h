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

#ifndef _MINE_H
#define _MINE_H

#include <libfam/bible.h>
#include <libfam/string.h>
#include <libfam/test_base.h>
#include <libfam/types.h>

#define HEADER_LEN 128

static inline i32 mine_block(const Bible *bible, const u8 header[HEADER_LEN],
			     const u8 target[32], u8 out[32], u32 *nonce,
			     u32 max_iter) {
	u8 header_copy[HEADER_LEN];
	*nonce = 0;
	memcpy(header_copy, header, HEADER_LEN);
	do {
		((u32 *)header_copy)[31] = *nonce;
		bible_pow_hash(bible, header_copy, HEADER_LEN, out);
	} while (memcmp(target, out, 32) < 0 && ++(*nonce) < max_iter);
	return *nonce == max_iter ? -1 : 0;
}

#endif /* _MINE_H */
