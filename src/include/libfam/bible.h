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

#ifndef _BIBLE_H
#define _BIBLE_H

#include <libfam/types.h>

#define BIBLE_LOOKUP_SIZE 32
#define BIBLE_SIZE 4634240
#define BIBLE_INDICES (BIBLE_SIZE >> 5)
#define EXTENDED_BIBLE_SIZE (256 * 1024 * 1024)
#define BIBLE_EXTENDED_INDICES (EXTENDED_BIBLE_SIZE >> 5)

typedef struct {
	u8 *text;
} Bible;

const Bible *bible(void);
void bible_extend(void);

static inline void bible_lookup(const Bible *bible, u64 r,
				u8 out[BIBLE_LOOKUP_SIZE]) {
	r = (r % BIBLE_INDICES) << 5;
	__builtin_memcpy(out, bible->text + r, BIBLE_LOOKUP_SIZE);
}

static inline void bible_extended_lookup(const Bible *bible, u64 r,
					 u8 out[BIBLE_LOOKUP_SIZE]) {
	r = (r % BIBLE_EXTENDED_INDICES) << 5;
	__builtin_memcpy(out, bible->text + r, BIBLE_LOOKUP_SIZE);
}

#endif /* _BIBLE_H */
