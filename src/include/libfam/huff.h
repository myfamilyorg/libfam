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

#include <libfam/types.h>

#define MAX_CODE_LENGTH 9
#define LOOKUP_BITS (MAX_CODE_LENGTH << 1)
#define LEN_SHIFT 4
#define DIST_MASK 0xF
#define LOOKUP_SIZE (1 << LOOKUP_BITS)
#define SYMBOL_TERM 256
#define MATCH_OFFSET (SYMBOL_TERM + 1)
#define MAX_MATCH_CODE 127
#define SYMBOL_COUNT (MATCH_OFFSET + MAX_MATCH_CODE + 1)

typedef struct {
	u8 match_flags;
	u8 bits_consumed;
	u8 out_bytes;
	u8 eb_offset;
	union {
		u32 output;
		u8 output_bytes[4];
	} output;
} HuffSymbols;

static inline u8 length_extra_bits(u8 match_code) {
	return match_code >> LEN_SHIFT;
}

static inline u8 distance_extra_bits(u8 match_code) {
	return match_code & DIST_MASK;
}

static inline u8 extra_bits(u8 match_code) {
	return (match_code >> LEN_SHIFT) + (match_code & DIST_MASK);
}

void huff_lookup(HuffSymbols lookup_table[LOOKUP_SIZE],
		 const u8 lengths[SYMBOL_COUNT], const u16 codes[SYMBOL_COUNT]);

#endif /* _HUFF_H */
