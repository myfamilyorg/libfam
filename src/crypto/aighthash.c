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

#include <libfam/aighthash.h>
#include <libfam/utils.h>

u32 aighthash(const void* data, u64 len, u32 seed) {
	const u8* p = (const u8*)data;
	u32 tail = 0, h = seed ^ 0x9E3779B9U;

	while (len >= 4) {
		u32 w = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
		h ^= w;
		h *= 0x85EBCA6BU;
		h = (h << 13) | (h >> 19);
		p += 4;
		len -= 4;
	}
	while (len--) tail = (tail << 8) | *p++;
	h ^= tail;
	h += (u32)len;
	h ^= h >> 16;
	h *= 0x85EBCA6BU;
	h ^= h >> 15;
	return h;
}
