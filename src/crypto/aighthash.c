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

#define AIGHT_INIT 0x9E3779B9U
#define AIGHT_P1 0xc2b2ae35u
#define AIGHT_P2 0x85ebca6bu

u32 aighthash(const void* data, u64 len, u32 seed) {
	const u8* p = (const u8*)data;
	u32 h = seed ^ AIGHT_INIT, tail = 0;

	while (len >= 8) {
		u64 v = (u64)p[0] | ((u64)p[1] << 8) | ((u64)p[2] << 16) |
			((u64)p[3] << 24) | ((u64)p[4] << 32) |
			((u64)p[5] << 40) | ((u64)p[6] << 48) |
			((u64)p[7] << 56);

		h = (h ^ (u32)v) * AIGHT_P2;
		h ^= h >> 16;
		h = (h ^ (u32)(v >> 32)) * AIGHT_P1;
		h ^= h >> 15;

		p += 8;
		len -= 8;
	}
	while (len--) tail = (tail << 8) | *p++;
	h = (h + (u32)len) ^ tail;
	h = (h ^ (h >> 16)) * AIGHT_P2;
	return h ^ (h >> 15);
}
