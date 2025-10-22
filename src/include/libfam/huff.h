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

#include <libfam/builtin.h>
#include <libfam/types.h>

#define MAX_CODE_LENGTH 9
#define MAX_BOOK_CODES (MAX_CODE_LENGTH + 4)
#define LOOKUP_BITS 12
#define LEN_SHIFT 4
#define DIST_MASK 0xF
#define LOOKUP_SIZE (1 << LOOKUP_BITS)
#define SYMBOL_TERM 256
#define MATCH_OFFSET (SYMBOL_TERM + 1)
#define MAX_MATCH_CODE 127
#define SYMBOL_COUNT (MATCH_OFFSET + MAX_MATCH_CODE + 1)

static inline u16 get_match_code(u16 len, u32 dist) {
	u32 len_bits = 31 - clz_u32(len - 3);
	u32 dist_bits = 31 - clz_u32(dist);
	return ((len_bits << LEN_SHIFT) | dist_bits);
}

static inline u8 length_extra_bits(u8 match_code) {
	return match_code >> LEN_SHIFT;
}

static inline u8 distance_extra_bits(u8 match_code) {
	return match_code & DIST_MASK;
}

static inline u8 length_base(u16 match_code) {
	u8 len_bits = match_code >> LEN_SHIFT;
	return (1 << len_bits) - 1;
}

static inline u16 distance_base(u16 match_code) {
	u8 distance_bits = match_code & DIST_MASK;
	return 1 << distance_bits;
}

static inline u8 length_extra_bits_value(u16 code, u16 actual_length) {
	u8 base_length = length_base(code);
	return actual_length - base_length - 4;
}

static inline u16 distance_extra_bits_value(u16 code, u16 actual_distance) {
	u32 distance_bits = code & DIST_MASK;
	u16 base_distance = 1 << distance_bits;
	return actual_distance - base_distance;
}

static inline u8 extra_bits(u8 match_code) {
	return (match_code >> LEN_SHIFT) + (match_code & DIST_MASK);
}

#endif /* _HUFF_H */
