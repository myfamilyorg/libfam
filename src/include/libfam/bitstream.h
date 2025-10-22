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

static const u64 bitstream_masks[65] = {
    0x0000000000000000ULL, /* num_bits = 0 */
    0x0000000000000001ULL, /* num_bits = 1 */
    0x0000000000000003ULL, /* num_bits = 2 */
    0x0000000000000007ULL, /* num_bits = 3 */
    0x000000000000000FULL, /* num_bits = 4 */
    0x000000000000001FULL, /* num_bits = 5 */
    0x000000000000003FULL, /* num_bits = 6 */
    0x000000000000007FULL, /* num_bits = 7 */
    0x00000000000000FFULL, /* num_bits = 8 */
    0x00000000000001FFULL, /* num_bits = 9 */
    0x00000000000003FFULL, /* num_bits = 10 */
    0x00000000000007FFULL, /* num_bits = 11 */
    0x0000000000000FFFULL, /* num_bits = 12 */
    0x0000000000001FFFULL, /* num_bits = 13 */
    0x0000000000003FFFULL, /* num_bits = 14 */
    0x0000000000007FFFULL, /* num_bits = 15 */
    0x000000000000FFFFULL, /* num_bits = 16 */
    0x000000000001FFFFULL, /* num_bits = 17 */
    0x000000000003FFFFULL, /* num_bits = 18 */
    0x000000000007FFFFULL, /* num_bits = 19 */
    0x00000000000FFFFFULL, /* num_bits = 20 */
    0x00000000001FFFFFULL, /* num_bits = 21 */
    0x00000000003FFFFFULL, /* num_bits = 22 */
    0x00000000007FFFFFULL, /* num_bits = 23 */
    0x0000000000FFFFFFULL, /* num_bits = 24 */
    0x0000000001FFFFFFULL, /* num_bits = 25 */
    0x0000000003FFFFFFULL, /* num_bits = 26 */
    0x0000000007FFFFFFULL, /* num_bits = 27 */
    0x000000000FFFFFFFULL, /* num_bits = 28 */
    0x000000001FFFFFFFULL, /* num_bits = 29 */
    0x000000003FFFFFFFULL, /* num_bits = 30 */
    0x000000007FFFFFFFULL, /* num_bits = 31 */
    0x00000000FFFFFFFFULL, /* num_bits = 32 */
    0x00000001FFFFFFFFULL, /* num_bits = 33 */
    0x00000003FFFFFFFFULL, /* num_bits = 34 */
    0x00000007FFFFFFFFULL, /* num_bits = 35 */
    0x0000000FFFFFFFFFULL, /* num_bits = 36 */
    0x0000001FFFFFFFFFULL, /* num_bits = 37 */
    0x0000003FFFFFFFFFULL, /* num_bits = 38 */
    0x0000007FFFFFFFFFULL, /* num_bits = 39 */
    0x000000FFFFFFFFFFULL, /* num_bits = 40 */
    0x000001FFFFFFFFFFULL, /* num_bits = 41 */
    0x000003FFFFFFFFFFULL, /* num_bits = 42 */
    0x000007FFFFFFFFFFULL, /* num_bits = 43 */
    0x00000FFFFFFFFFFFULL, /* num_bits = 44 */
    0x00001FFFFFFFFFFFULL, /* num_bits = 45 */
    0x00003FFFFFFFFFFFULL, /* num_bits = 46 */
    0x00007FFFFFFFFFFFULL, /* num_bits = 47 */
    0x0000FFFFFFFFFFFFULL, /* num_bits = 48 */
    0x0001FFFFFFFFFFFFULL, /* num_bits = 49 */
    0x0003FFFFFFFFFFFFULL, /* num_bits = 50 */
    0x0007FFFFFFFFFFFFULL, /* num_bits = 51 */
    0x000FFFFFFFFFFFFFULL, /* num_bits = 52 */
    0x001FFFFFFFFFFFFFULL, /* num_bits = 53 */
    0x003FFFFFFFFFFFFFULL, /* num_bits = 54 */
    0x007FFFFFFFFFFFFFULL, /* num_bits = 55 */
    0x00FFFFFFFFFFFFFFULL, /* num_bits = 56 */
    0x01FFFFFFFFFFFFFFULL, /* num_bits = 57 */
    0x03FFFFFFFFFFFFFFULL, /* num_bits = 58 */
    0x07FFFFFFFFFFFFFFULL, /* num_bits = 59 */
    0x0FFFFFFFFFFFFFFFULL, /* num_bits = 60 */
    0x1FFFFFFFFFFFFFFFULL, /* num_bits = 61 */
    0x3FFFFFFFFFFFFFFFULL, /* num_bits = 62 */
    0x7FFFFFFFFFFFFFFFULL, /* num_bits = 63 */
    0xFFFFFFFFFFFFFFFFULL  /* num_bits = 64 */
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
	u64 buffer;
	u8 bits_in_buffer;
} BitStreamWriter;

void bitstream_writer_push(BitStreamWriter *strm, u64 bits, u8 num_bits);
void bitstream_writer_flush(BitStreamWriter *strm);

i32 bitstream_reader_load(BitStreamReader *strm);

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
