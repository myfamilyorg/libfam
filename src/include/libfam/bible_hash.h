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

#ifndef _BIBLE_HASH_H
#define _BIBLE_HASH_H

#include <libfam/types.h>

#define BIBLE_HASH_DATA_SIZE 1534
#define SPONGE_WORDS (((BIBLE_HASH_DATA_SIZE) / 8) / sizeof(u64))

typedef struct {
	u64 saved;
	union {
		u64 s[SPONGE_WORDS];
		u8 sb[SPONGE_WORDS * 8];
	} u;
	u32 byteIndex;
	u32 wordIndex;
	u32 capacityWords;
} BibleHash;

void bible_hash_init(BibleHash *ctx);
void bible_hash_update(BibleHash *ctx, void const *in, u64 len);
const void *bible_hash_finalize(BibleHash *ctx);

#endif /* _BIBLE_HASH_H */
