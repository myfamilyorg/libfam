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

#ifndef _HUFF_H
#define _HUFF_H

#include <libfam/compress_impl.h>
#include <libfam/types.h>

#define LOOKUP_SIZE (1 << (MAX_CODE_LENGTH << 1))

typedef struct {
	u8 match_extra_offset1 : 5;
	u8 match_extra_offset2 : 5;
	u8 match_flags : 4;
	u8 bits_consumed : 5;
	u8 out_incr : 2;
	union {
		u32 output;
		u8 output_bytes[4];
	} output;
} HuffSymbols;

void huff_lookup(HuffSymbols lookup[LOOKUP_SIZE],
		 const u8 lengths[SYMBOL_COUNT], const u16 codes[SYMBOL_COUNT]);

#endif /* _HUFF_H */
