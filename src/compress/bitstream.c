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

#include <libfam/bitstream.h>
#include <libfam/limits.h>
#include <libfam/utils.h>

void bitstream_writer_flush(BitStreamWriter *strm) {
	u64 bit_offset = strm->bit_offset & 0x7;
	u64 byte_pos = strm->bit_offset >> 3;
	__builtin_prefetch(strm->data + byte_pos, 1, 3);
	strm->bit_offset += strm->bits_in_buffer;

	u64 bits_to_write = 8 - bit_offset;
	bits_to_write = min(bits_to_write, strm->bits_in_buffer);
	u8 new_bits = (u8)(strm->buffer & bitstream_masks[bits_to_write]);
	new_bits <<= bit_offset;
	u8 mask = bitstream_partial_masks[bit_offset][bits_to_write];
	u8 current_byte = strm->data[byte_pos];
	strm->data[byte_pos] = (current_byte & mask) | new_bits;
	strm->buffer >>= bits_to_write;
	strm->bits_in_buffer -= bits_to_write;
	byte_pos++;

	u64 bits_mask = bitstream_masks[strm->bits_in_buffer];
	u64 *data64 = (u64 *)(strm->data + byte_pos);
	u64 existing = *data64;
	*data64 = (existing & ~bits_mask) | (strm->buffer & bits_mask);
	strm->buffer = strm->bits_in_buffer = 0;
}

i32 bitstream_reader_load(BitStreamReader *strm) {
	u64 bit_offset = strm->bit_offset;
	u64 bits_to_load = 64 - strm->bits_in_buffer;
	u64 end_byte = (bit_offset + bits_to_load + 7) >> 3;
	u64 byte_pos = bit_offset >> 3;
	__builtin_prefetch(strm->data + byte_pos, 1, 3);
	u8 bit_remainder = bit_offset & 0x7;
	if (end_byte > strm->max_size) {
		errno = EOVERFLOW;
		return -1;
	}
	u64 new_bits = *(u64 *)(strm->data + byte_pos);
	u64 high = strm->data[byte_pos + 8];
	new_bits = (new_bits >> bit_remainder) | (high << (64 - bit_remainder));
	new_bits &= bitstream_masks[bits_to_load];

	strm->buffer |= (new_bits << strm->bits_in_buffer);
	strm->bit_offset += bits_to_load;
	strm->bits_in_buffer += bits_to_load;
	return 0;
}

