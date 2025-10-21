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

#include <libfam/atomic.h>
#include <libfam/bitmap.h>
#include <libfam/builtin.h>
#include <libfam/limits.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

#define INVALID_RELEASE "Invalid bit release!\n"
#define DOUBLE_FREE "Double free!\n"

struct BitMap {
	u64 last_free_word;
	u64 words;
	u64 bits;
	u64 data[];
};

i32 bitmap_init(BitMap *bmap, u64 bits) {
INIT:
	if (!bmap || bits > U64_MAX - 7) ERROR(EINVAL);
	bmap->bits = bits;
	bmap->words = (bits + 63) >> 6;
CLEANUP:
	RETURN;
}

i64 bitmap_find_free_bit(BitMap *bmap) {
	i64 i, ret = -1;
	u64 last_free_word = __aload64(&bmap->last_free_word);
	for (i = 0; i < bmap->words; i++) {
		u64 index = (i + last_free_word) % bmap->words;
		u64 cur = bmap->data[index];
		if (cur != U64_MAX) {
			u64 first_free_bit = ctz_u64(~cur);
			i64 candidate = first_free_bit + (index << 6);
			if (candidate < bmap->bits) {
				u64 new = cur | (1UL << first_free_bit);
				if (__cas64(&bmap->data[index], &cur, new)) {
					ret = candidate;
					if (new != U64_MAX)
						__astore64(
						    &bmap->last_free_word,
						    index);
					break;
				}
			}
		}
	}
	return ret;
}

void bitmap_release_bit(BitMap *bmap, u64 bit) {
	u64 index = bit >> 6;
	u64 bit_to_zero = (1UL << (bit & 0x3F));
	u64 cur;

	if (index >= bmap->words) {
		write(2, INVALID_RELEASE, strlen(INVALID_RELEASE));
		_famexit(-1);
		errno = EINVAL;
		return;
	}
	do {
		cur = __aload64(&bmap->data[index]);
		if (!(cur & bit_to_zero)) {
			write(2, DOUBLE_FREE, strlen(DOUBLE_FREE));
			_famexit(-1);
			errno = EINVAL;
			return;
		}
	} while (!__cas64(&bmap->data[index], &cur, cur & ~bit_to_zero));
	__astore64(&bmap->last_free_word, index);
}

u64 bitmap_size(BitMap *bmp) { return bitmap_bound(bmp->bits); }

u64 bitmap_bound(u64 bits) {
	if (bits > U64_MAX - 7) return U64_MAX;
	u64 required = ((bits + 63) >> 3) + sizeof(BitMap);
	u64 pages = (required + PAGE_SIZE - 1) / PAGE_SIZE;
	return pages * PAGE_SIZE;
}
