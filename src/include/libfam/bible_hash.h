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

#include <libfam/bible.h>
#include <libfam/types.h>

#define GOLDEN_PRIME 0x517cc1b727220a95ULL

static inline void bible_pow_hash(const Bible *b, const u8 *input,
				  u64 input_len, u8 out[32]) {
	__attribute__((aligned(32))) u8 s[32] = {0};
	__attribute__((aligned(32))) u8 bdata[32];
	u64 v1, v2, v3, v4;

	for (u64 i = 0; i < input_len; i++) s[i & 31] ^= input[i];
	for (u8 i = 0; i < 32;) {
		bible_lookup(b, s[i & 31], bdata);
		v1 = *(u64 *)bdata;
		v2 = *(u64 *)(bdata + 8);
		v3 = *(u64 *)(bdata + 16);
		v4 = *(u64 *)(bdata + 24);
		i++;
		s[i & 31] ^= v1 ^ v2 ^ v3 ^ v4;
		s[i & 31] *= GOLDEN_PRIME;
	}

	__builtin_memcpy(out, s, 32);
}

#endif /* _BIBLE_HASH_H */
