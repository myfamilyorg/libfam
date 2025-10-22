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

#include <libfam/huff.h>
#include <libfam/limits.h>
#include <libfam/types.h>

#define LZ_HASH_ENTRIES (1 << 16)
#define HASH_CONSTANT 0x9e3779b9U
#define HASH_SHIFT 16
#define MAX_MATCH_LEN 256
#define MIN_MATCH_LEN 4
#define MAX_MATCH_DIST U16_MAX
#define MIN_MATCH_DIST 1
#define MAX_COMPRESS_LEN (1 << 18)
#define MAX_COMPRESS_BOUND_LEN \
	(MAX_COMPRESS_LEN + (MAX_COMPRESS_LEN >> 5) + 1024)
#define MAX_AVX_OVERWRITE 32

#define PROC_MATCH_ARRAY()                                               \
	if (match_array[i] == 1)                                         \
		break;                                                   \
	else if (match_array[i] == 0) {                                  \
		u8 symbol = match_array[i + 1];                          \
		u16 code = codes[symbol];                                \
		u8 length = lengths[symbol];                             \
		bitstream_writer_push(&strm, code, length);              \
		i += 2;                                                  \
	} else {                                                         \
		u8 match_code = match_array[i] - 2;                      \
		u16 symbol = (u16)match_code + MATCH_OFFSET;             \
		CodeLength cl = code_lengths[symbol];                    \
		u32 combined_extra = ((u32 *)(match_array + i))[0] >> 8; \
		u8 len_extra_bits = length_extra_bits(match_code);       \
		u8 dist_extra_bits = distance_extra_bits(match_code);    \
		u8 total_extra_bits = len_extra_bits + dist_extra_bits;  \
		bitstream_writer_push(&strm, cl.code, cl.length);        \
		bitstream_writer_push(&strm, combined_extra,             \
				      total_extra_bits);                 \
		i += 4;                                                  \
	}

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
	HuffmanNode *nodes[SYMBOL_COUNT * 2 + 1];
	u64 size;
} HuffmanMinHeap;

typedef struct {
	u64 file_size;
	u64 mtime;
	u64 atime;
	u16 permissions;
	u16 version;
} CompressHeader;

typedef struct {
	u16 symbol;
	u16 length;
	u8 dist_extra_bits;
	u8 len_extra_bits;
	u16 base_dist;
	u8 base_len;
} HuffmanLookup;

typedef struct {
	u16 code;
	u16 length;
} CodeLength;

#endif /* _COMPRESS_IMPL_H */
