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

#include <libfam/bytestream.h>
#include <libfam/string.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif /* __AVX2__ */

void bytestream_push(ByteStream *strm, u8 b) {
	strm->buffer[strm->bytes_in_buffer++] = b;
}

i32 bytestream_flush(ByteStream *strm) {
	u16 i = 0;
	u64 needed = strm->bytes_in_buffer + strm->offset;
	if (needed > strm->max_size) return -1;
#ifdef __AVX2__
	else if (strm->offset + 32 < strm->max_size) {
		_mm256_storeu_si256((__m256i *)(strm->data + strm->offset),
				    *(__m256i *)&strm->buffer);
		strm->offset += strm->bytes_in_buffer;
		strm->bytes_in_buffer = 0;
	}
#endif /* __AVX2__ */
	else
		while (strm->bytes_in_buffer--)
			strm->data[strm->offset++] = strm->buffer[i++];
	return 0;
}
