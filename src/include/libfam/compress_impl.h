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

#ifndef _COMPRESS_IMPL_H
#define _COMPRESS_IMPL_H

#include <libfam/limits.h>
#include <libfam/types.h>

#define LZ_HASH_ENTRIES (1 << 16)
#define HASH_CONSTANT 0x9e3779b9U
#define HASH_SHIFT 16
#define MAX_MATCH_LEN 256
#define MIN_MATCH_LEN 4
#define MAX_MATCH_DIST U16_MAX
#define MIN_MATCH_DIST 1
#define MAX_MATCH_CODE 127
#define LEN_SHIFT 4
#define DIST_MASK 0xF
#define SYMBOL_TERM 256
#define MATCH_OFFSET (SYMBOL_TERM + 1)
#define SYMBOL_COUNT (MATCH_OFFSET + MAX_MATCH_CODE + 1)
#define MAX_CODE_LENGTH 9
#define MAX_COMPRESS32_LEN (1 << 18)

#define WRITE(strm, value, bits)                              \
	do {                                                  \
		if ((strm)->bits_in_buffer + (bits) > 64)     \
			bitstream_writer_flush(strm);         \
		bitstream_writer_push(strm, (value), (bits)); \
	} while (0);

#define TRY_READ(strm, bits)                                                   \
	({                                                                     \
		if ((strm)->bits_in_buffer < (bits)) {                         \
			bitstream_reader_load(strm);                           \
			if ((strm)->bits_in_buffer < (bits)) ERROR(EOVERFLOW); \
		}                                                              \
		i32 _ret__ = bitstream_reader_read((strm), (bits));            \
		bitstream_reader_clear((strm), (bits));                        \
		_ret__;                                                        \
	})

typedef struct {
	u16 table[LZ_HASH_ENTRIES];
} LzHash;

typedef struct {
	u16 dist;
	u16 len;
} MatchInfo;

typedef struct HuffmanNode {
	u16 symbol;
	u64 freq;
	struct HuffmanNode *left, *right;
} HuffmanNode;

typedef struct {
	HuffmanNode *nodes[SYMBOL_COUNT * 2];
	u64 size;
} HuffmanMinHeap;

STATIC void compress_find_matches(const u8 *in, u32 len,
				  u8 match_array[4 * MAX_COMPRESS32_LEN + 1],
				  u32 frequencies[SYMBOL_COUNT]);

#endif /* _COMPRESS_IMPL_H */
