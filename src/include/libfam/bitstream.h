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

/*
 * Constant: bitstream_partial_masks
 * Precomputed byte masks for partial byte writes during flush.
 * values:
 *         bitstream_partial_masks[byte_offset][bits_to_write]
 * notes:
 *         Used internally by bitstream_writer_flush to mask out unwanted
 *         bits in the final byte when writing incomplete bytes.
 *         Each row corresponds to a starting bit offset within a byte (0–7).
 *         Each column corresponds to number of bits to write (1–8).
 *         Last column (index 8) is 0 for padding.
 */
static const u8 bitstream_partial_masks[8][9] = {
    {255, 254, 252, 248, 240, 224, 192, 128, 0},
    {255, 253, 249, 241, 225, 193, 129, 1, 1},
    {255, 251, 243, 227, 195, 131, 3, 3, 3},
    {255, 247, 231, 199, 135, 7, 7, 7, 7},
    {255, 239, 207, 143, 15, 15, 15, 15, 15},
    {255, 223, 159, 31, 31, 31, 31, 31, 31},
    {255, 191, 63, 63, 63, 63, 63, 63, 63},
    {255, 127, 127, 127, 127, 127, 127, 127, 127}};

/*
 * Constant: bitstream_masks
 * Precomputed 64-bit masks for extracting up to 64 bits.
 * values:
 *         bitstream_masks[n] = (1ULL << n) - 1
 * notes:
 *         bitstream_masks[0] = 0, bitstream_masks[64] = ~0ULL.
 *         Used by bitstream_reader_read to extract the low n bits from buffer.
 *         Indexed directly by number of bits requested (1 to 64).
 */
static const u64 bitstream_masks[65] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000007ULL, 0x000000000000000FULL, 0x000000000000001FULL,
    0x000000000000003FULL, 0x000000000000007FULL, 0x00000000000000FFULL,
    0x00000000000001FFULL, 0x00000000000003FFULL, 0x00000000000007FFULL,
    0x0000000000000FFFULL, 0x0000000000001FFFULL, 0x0000000000003FFFULL,
    0x0000000000007FFFULL, 0x000000000000FFFFULL, 0x000000000001FFFFULL,
    0x000000000003FFFFULL, 0x000000000007FFFFULL, 0x00000000000FFFFFULL,
    0x00000000001FFFFFULL, 0x00000000003FFFFFULL, 0x00000000007FFFFFULL,
    0x0000000000FFFFFFULL, 0x0000000001FFFFFFULL, 0x0000000003FFFFFFULL,
    0x0000000007FFFFFFULL, 0x000000000FFFFFFFULL, 0x000000001FFFFFFFULL,
    0x000000003FFFFFFFULL, 0x000000007FFFFFFFULL, 0x00000000FFFFFFFFULL,
    0x00000001FFFFFFFFULL, 0x00000003FFFFFFFFULL, 0x00000007FFFFFFFFULL,
    0x0000000FFFFFFFFFULL, 0x0000001FFFFFFFFFULL, 0x0000003FFFFFFFFFULL,
    0x0000007FFFFFFFFFULL, 0x000000FFFFFFFFFFULL, 0x000001FFFFFFFFFFULL,
    0x000003FFFFFFFFFFULL, 0x000007FFFFFFFFFFULL, 0x00000FFFFFFFFFFFULL,
    0x00001FFFFFFFFFFFULL, 0x00003FFFFFFFFFFFULL, 0x00007FFFFFFFFFFFULL,
    0x0000FFFFFFFFFFFFULL, 0x0001FFFFFFFFFFFFULL, 0x0003FFFFFFFFFFFFULL,
    0x0007FFFFFFFFFFFFULL, 0x000FFFFFFFFFFFFFULL, 0x001FFFFFFFFFFFFFULL,
    0x003FFFFFFFFFFFFFULL, 0x007FFFFFFFFFFFFFULL, 0x00FFFFFFFFFFFFFFULL,
    0x01FFFFFFFFFFFFFFULL, 0x03FFFFFFFFFFFFFFULL, 0x07FFFFFFFFFFFFFFULL,
    0x0FFFFFFFFFFFFFFFULL, 0x1FFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

/*
 * Type: BitStreamReader
 * Stateful reader for bit-level data from a byte stream.
 * members:
 *         const u8 *data         - input byte stream.
 *         u64 max_size           - total size of data in bytes.
 *         u64 bit_offset         - current bit position in the stream.
 *         u64 buffer             - bit buffer (holds up to 64 bits).
 *         u8 bits_in_buffer      - number of valid bits in buffer.
 * notes:
 *         Must be initialized externally before use.
 *         Use bitstream_reader_load to refill buffer when needed.
 *         bit_offset advances as bits are consumed.
 *         Typical initialization:
 *         u8 data[BITSTREAM_SIZE];
 *         BitStreamReader r = {data, sizeof(data)};
 */
typedef struct {
	const u8 *data;
	u64 max_size;
	u64 bit_offset;
	u64 buffer;
	u8 bits_in_buffer;
} BitStreamReader;

/*
 * Type: BitStreamWriter
 * Stateful writer for bit-level data into a byte stream.
 * members:
 *         u8 *data               - output byte stream.
 *         u64 bit_offset         - current bit position in the stream.
 *         u64 buffer             - bit buffer (holds up to 64 bits).
 *         u8 bits_in_buffer      - number of valid bits in buffer.
 * notes:
 *         Must be initialized externally before use.
 *         Use bitstream_writer_push to add bits.
 *         Call bitstream_writer_flush to write partial byte.
 *         bit_offset advances as bits are flushed.
 *         Typical initialization:
 *         u8 data[BITSTREAM_SIZE];
 *         BitStreamWriter w = {data};
 */
typedef struct {
	u8 *data;
	u64 bit_offset;
	u64 buffer;
	u8 bits_in_buffer;
} BitStreamWriter;

/*
 * Function: bitstream_writer_flush
 * Flushes any remaining bits in the buffer to the output stream.
 * inputs:
 *         BitStreamWriter *strm - pointer to initialized writer.
 * return value: None.
 * errors: None.
 * notes:
 *         strm must be non-null and properly initialized.
 *         Writes partial byte using bitstream_partial_masks.
 *         Advances bit_offset by bits_in_buffer. After call, bits_in_buffer ==
 *         0. Must be called at end of stream to avoid data loss.
 */
void bitstream_writer_flush(BitStreamWriter *restrict strm);

/*
 * Function: bitstream_reader_load
 * Loads up to 64 bits from the input stream into the buffer.
 * inputs:
 *         BitStreamReader *strm - pointer to initialized reader.
 * return value: i32 - 0 on success, or -1 on error.
 * errors:
 *         EOVERFLOW - if end of stream reached or strm is invalid.
 * notes:
 *         strm must be non-null and properly initialized.
 *         Consumes whole bytes from data[bit_offset >> 3].
 *         Updates bit_offset and bits_in_buffer.
 *         Returns 0 if no more data available.
 *         Caller must check return value before using buffer.
 */
i32 bitstream_reader_load(BitStreamReader *restrict strm);

/*
 * Function: bitstream_writer_push
 * Pushes bits into the writer's buffer (inline).
 * inputs:
 *         BitStreamWriter *strm - pointer to initialized writer.
 *         u64 bits              - bits to write (low-order bits used).
 *         u8 num_bits           - number of bits to write (1 to 64).
 * return value: None.
 * errors: None.
 * notes:
 *         strm must be non-null.
 *         num_bits must be > 0 and <= 64 - bits_in_buffer.
 *         Automatically flushes all bits in the buffer.
 *         Uses little-endian bit ordering within bytes.
 *         Always inlined for performance.
 */
static inline __attribute__((always_inline)) void bitstream_writer_push(
    BitStreamWriter *restrict strm, u64 bits, u8 num_bits) {
	strm->buffer |= bits << strm->bits_in_buffer;
	strm->bits_in_buffer += num_bits;
}

/*
 * Function: bitstream_reader_read
 * Reads bits from the reader's buffer without consuming them.
 * inputs:
 *         const BitStreamReader *strm - pointer to loaded reader.
 *         u8 num_bits                 - number of bits to read (1 to 64).
 * return value: u64 - the low-order num_bits from buffer.
 * errors: None.
 * notes:
 *         strm must be non-null and have at least num_bits in buffer.
 *         Uses bitstream_masks[num_bits] to mask result.
 *         Does not modify bit_offset or bits_in_buffer.
 *         Always inlined for performance.
 */
static inline __attribute__((always_inline)) u64
bitstream_reader_read(const BitStreamReader *restrict strm, u8 num_bits) {
	return strm->buffer & bitstream_masks[num_bits];
}

/*
 * Function: bitstream_reader_clear
 * Consumes (clears) bits from the reader's buffer.
 * inputs:
 *         BitStreamReader *strm - pointer to loaded reader.
 *         u8 num_bits           - number of bits to consume.
 * return value: None.
 * errors: None.
 * notes:
 *         strm must be non-null and have at least num_bits in buffer.
 *         Shifts buffer right by num_bits and decrements bits_in_buffer.
 *         Always inlined for performance.
 */
static inline __attribute__((always_inline)) void bitstream_reader_clear(
    BitStreamReader *restrict strm, u8 num_bits) {
	strm->buffer = strm->buffer >> num_bits;
	strm->bits_in_buffer = strm->bits_in_buffer - num_bits;
}

#endif /* _BITSTREAM_H */
