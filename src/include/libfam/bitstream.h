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

void bitstream_reader_load(BitStreamReader *strm);
u64 bitstream_reader_read(const BitStreamReader *strm, u8 num_bits);
void bitstream_reader_clear(BitStreamReader *strm, u8 num_bits);

#endif /* _BITSTREAM_H */
