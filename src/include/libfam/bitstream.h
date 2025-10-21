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

#ifndef _BITSTREAM_H
#define _BITSTREAM_H

#include <libfam/types.h>
#include <libfam/utils.h>

static const u128 bitstream_masks[129] = {
    (u128)0x0000000000000000ULL, /* num_bits = 0 */
    (u128)0x0000000000000001ULL, /* num_bits = 1 */
    (u128)0x0000000000000003ULL, /* num_bits = 2 */
    (u128)0x0000000000000007ULL, /* num_bits = 3 */
    (u128)0x000000000000000FULL, /* num_bits = 4 */
    (u128)0x000000000000001FULL, /* num_bits = 5 */
    (u128)0x000000000000003FULL, /* num_bits = 6 */
    (u128)0x000000000000007FULL, /* num_bits = 7 */
    (u128)0x00000000000000FFULL, /* num_bits = 8 */
    (u128)0x00000000000001FFULL, /* num_bits = 9 */
    (u128)0x00000000000003FFULL, /* num_bits = 10 */
    (u128)0x00000000000007FFULL, /* num_bits = 11 */
    (u128)0x0000000000000FFFULL, /* num_bits = 12 */
    (u128)0x0000000000001FFFULL, /* num_bits = 13 */
    (u128)0x0000000000003FFFULL, /* num_bits = 14 */
    (u128)0x0000000000007FFFULL, /* num_bits = 15 */
    (u128)0x000000000000FFFFULL, /* num_bits = 16 */
    (u128)0x000000000001FFFFULL, /* num_bits = 17 */
    (u128)0x000000000003FFFFULL, /* num_bits = 18 */
    (u128)0x000000000007FFFFULL, /* num_bits = 19 */
    (u128)0x00000000000FFFFFULL, /* num_bits = 20 */
    (u128)0x00000000001FFFFFULL, /* num_bits = 21 */
    (u128)0x00000000003FFFFFULL, /* num_bits = 22 */
    (u128)0x00000000007FFFFFULL, /* num_bits = 23 */
    (u128)0x0000000000FFFFFFULL, /* num_bits = 24 */
    (u128)0x0000000001FFFFFFULL, /* num_bits = 25 */
    (u128)0x0000000003FFFFFFULL, /* num_bits = 26 */
    (u128)0x0000000007FFFFFFULL, /* num_bits = 27 */
    (u128)0x000000000FFFFFFFULL, /* num_bits = 28 */
    (u128)0x000000001FFFFFFFULL, /* num_bits = 29 */
    (u128)0x000000003FFFFFFFULL, /* num_bits = 30 */
    (u128)0x000000007FFFFFFFULL, /* num_bits = 31 */
    (u128)0x00000000FFFFFFFFULL, /* num_bits = 32 */
    (u128)0x00000001FFFFFFFFULL, /* num_bits = 33 */
    (u128)0x00000003FFFFFFFFULL, /* num_bits = 34 */
    (u128)0x00000007FFFFFFFFULL, /* num_bits = 35 */
    (u128)0x0000000FFFFFFFFFULL, /* num_bits = 36 */
    (u128)0x0000001FFFFFFFFFULL, /* num_bits = 37 */
    (u128)0x0000003FFFFFFFFFULL, /* num_bits = 38 */
    (u128)0x0000007FFFFFFFFFULL, /* num_bits = 39 */
    (u128)0x000000FFFFFFFFFFULL, /* num_bits = 40 */
    (u128)0x000001FFFFFFFFFFULL, /* num_bits = 41 */
    (u128)0x000003FFFFFFFFFFULL, /* num_bits = 42 */
    (u128)0x000007FFFFFFFFFFULL, /* num_bits = 43 */
    (u128)0x00000FFFFFFFFFFFULL, /* num_bits = 44 */
    (u128)0x00001FFFFFFFFFFFULL, /* num_bits = 45 */
    (u128)0x00003FFFFFFFFFFFULL, /* num_bits = 46 */
    (u128)0x00007FFFFFFFFFFFULL, /* num_bits = 47 */
    (u128)0x0000FFFFFFFFFFFFULL, /* num_bits = 48 */
    (u128)0x0001FFFFFFFFFFFFULL, /* num_bits = 49 */
    (u128)0x0003FFFFFFFFFFFFULL, /* num_bits = 50 */
    (u128)0x0007FFFFFFFFFFFFULL, /* num_bits = 51 */
    (u128)0x000FFFFFFFFFFFFFULL, /* num_bits = 52 */
    (u128)0x001FFFFFFFFFFFFFULL, /* num_bits = 53 */
    (u128)0x003FFFFFFFFFFFFFULL, /* num_bits = 54 */
    (u128)0x007FFFFFFFFFFFFFULL, /* num_bits = 55 */
    (u128)0x00FFFFFFFFFFFFFFULL, /* num_bits = 56 */
    (u128)0x01FFFFFFFFFFFFFFULL, /* num_bits = 57 */
    (u128)0x03FFFFFFFFFFFFFFULL, /* num_bits = 58 */
    (u128)0x07FFFFFFFFFFFFFFULL, /* num_bits = 59 */
    (u128)0x0FFFFFFFFFFFFFFFULL, /* num_bits = 60 */
    (u128)0x1FFFFFFFFFFFFFFFULL, /* num_bits = 61 */
    (u128)0x3FFFFFFFFFFFFFFFULL, /* num_bits = 62 */
    (u128)0x7FFFFFFFFFFFFFFFULL, /* num_bits = 63 */
    (u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 64 */
    ((u128)((1ULL << (65 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 65 */
    ((u128)((1ULL << (66 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 66 */
    ((u128)((1ULL << (67 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 67 */
    ((u128)((1ULL << (68 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 68 */
    ((u128)((1ULL << (69 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 69 */
    ((u128)((1ULL << (70 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 70 */
    ((u128)((1ULL << (71 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 71 */
    ((u128)((1ULL << (72 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 72 */
    ((u128)((1ULL << (73 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 73 */
    ((u128)((1ULL << (74 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 74 */
    ((u128)((1ULL << (75 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 75 */
    ((u128)((1ULL << (76 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 76 */
    ((u128)((1ULL << (77 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 77 */
    ((u128)((1ULL << (78 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 78 */
    ((u128)((1ULL << (79 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 79 */
    ((u128)((1ULL << (80 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 80 */
    ((u128)((1ULL << (81 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 81 */
    ((u128)((1ULL << (82 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 82 */
    ((u128)((1ULL << (83 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 83 */
    ((u128)((1ULL << (84 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 84 */
    ((u128)((1ULL << (85 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 85 */
    ((u128)((1ULL << (86 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 86 */
    ((u128)((1ULL << (87 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 87 */
    ((u128)((1ULL << (88 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 88 */
    ((u128)((1ULL << (89 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 89 */
    ((u128)((1ULL << (90 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 90 */
    ((u128)((1ULL << (91 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 91 */
    ((u128)((1ULL << (92 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 92 */
    ((u128)((1ULL << (93 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 93 */
    ((u128)((1ULL << (94 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 94 */
    ((u128)((1ULL << (95 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 95 */
    ((u128)((1ULL << (96 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 96 */
    ((u128)((1ULL << (97 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 97 */
    ((u128)((1ULL << (98 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 98 */
    ((u128)((1ULL << (99 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 99 */
    ((u128)((1ULL << (100 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 100 */
    ((u128)((1ULL << (101 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 101 */
    ((u128)((1ULL << (102 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 102 */
    ((u128)((1ULL << (103 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 103 */
    ((u128)((1ULL << (104 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 104 */
    ((u128)((1ULL << (105 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 105 */
    ((u128)((1ULL << (106 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 106 */
    ((u128)((1ULL << (107 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 107 */
    ((u128)((1ULL << (108 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 108 */
    ((u128)((1ULL << (109 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 109 */
    ((u128)((1ULL << (110 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 110 */
    ((u128)((1ULL << (111 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 111 */
    ((u128)((1ULL << (112 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 112 */
    ((u128)((1ULL << (113 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 113 */
    ((u128)((1ULL << (114 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 114 */
    ((u128)((1ULL << (115 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 115 */
    ((u128)((1ULL << (116 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 116 */
    ((u128)((1ULL << (117 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 117 */
    ((u128)((1ULL << (118 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 118 */
    ((u128)((1ULL << (119 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 119 */
    ((u128)((1ULL << (120 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 120 */
    ((u128)((1ULL << (121 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 121 */
    ((u128)((1ULL << (122 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 122 */
    ((u128)((1ULL << (123 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 123 */
    ((u128)((1ULL << (124 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 124 */
    ((u128)((1ULL << (125 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 125 */
    ((u128)((1ULL << (126 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 126 */
    ((u128)((1ULL << (127 - 64)) - 1) << 64) |
	(u128)0xFFFFFFFFFFFFFFFFULL, /* num_bits = 127 */
    ((u128)0xFFFFFFFFFFFFFFFFULL) << 64 |
	(u128)0xFFFFFFFFFFFFFFFFULL /* num_bits = 128 */
};

typedef struct {
	const u8 *data;
	u64 max_size;
	u64 bit_offset;
	u64 buffer;
	u8 bits_in_buffer;
} BitStreamReader;

typedef struct {
	u8 *data;
	u64 bit_offset;
	u128 buffer;
	u8 bits_in_buffer;
} BitStreamWriter;

void bitstream_writer_flush(BitStreamWriter *strm);
i32 bitstream_reader_load(BitStreamReader *strm);

static inline void bitstream_writer_push(BitStreamWriter *strm, u128 bits,
					 u8 num_bits) {
	strm->buffer |= bits << strm->bits_in_buffer;
	strm->bits_in_buffer += num_bits;
}

static inline __attribute__((always_inline)) u64
bitstream_reader_read(const BitStreamReader *strm, u8 num_bits) {
	return strm->buffer & bitstream_masks[num_bits];
}

static inline __attribute__((always_inline)) void bitstream_reader_clear(
    BitStreamReader *strm, u8 num_bits) {
	strm->buffer = strm->buffer >> num_bits;
	strm->bits_in_buffer = strm->bits_in_buffer - num_bits;
}

#endif /* _BITSTREAM_H */
