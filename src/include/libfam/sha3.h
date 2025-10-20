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

#ifndef _SHA3_H
#define _SHA3_H

#include <libfam/types.h>

/* 'Words' here refers to u64 */
#define SHA3_KECCAK_SPONGE_WORDS (((1600) / 8 /*bits to byte*/) / sizeof(u64))
typedef struct Sha3Context_ {
	u64 saved; /* the portion of the input message that we
		    * didn't consume yet */
	union {	   /* Keccak's state */
		u64 s[SHA3_KECCAK_SPONGE_WORDS];
		u8 sb[SHA3_KECCAK_SPONGE_WORDS * 8];
	} u;
	u32 byteIndex;	   /* 0..7--the next byte after the set one
			    * (starts from 0; 0--none are buffered) */
	u32 wordIndex;	   /* 0..24--the next word to integrate input
			    * (starts from 0) */
	u32 capacityWords; /* the double size of the hash output in
			    * words (e.g. 16 for Keccak 512) */
} Sha3Context;

void sha3_init256(void *priv);
void sha3_init384(void *priv);
void sha3_init512(void *priv);
i32 sha3_init(void *priv, u32 bit_size);
void sha3_update(void *priv, void const *bufIn, u64 len);
void const *sha3_finalize(void *priv);

#endif /* _SHA3_H */
