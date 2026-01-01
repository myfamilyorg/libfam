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

#ifndef _ALLOC_IMPL_H
#define _ALLOC_IMPL_H

#include <libfam/alloc.h>

#define SLAB_COUNT 18
#define MAX_SLAB_SIZE (1024 * 1024)
#define CHUNK_SIZE (4 * 1024 * 1024)
#define MAGIC 0x9e3779b9
#define TOTAL_SIZE(chunks) \
	(bitmap_bound(chunks) + chunks * CHUNK_SIZE + sizeof(Alloc))
#define MAGIC_ERROR "Invalid magic! Memory corrupted!\n"
#define ALLOC_AND_COPY(a, new_size, ptr, old_size, new_ptr)           \
	do {                                                          \
		(new_ptr) = balloc((a), (new_size));                  \
		if (!(new_ptr)) break;                                \
		if ((new_size) < (old_size)) (old_size) = (new_size); \
		fastmemcpy((new_ptr), (ptr), (old_size));             \
	} while (0)

static const u64 BITS_PER_SLAB_INDEX[] = {
    516094, 260095, 130559, 65343, 32703, 16367, 8183, 4091, 2045,
    1022,   511,    255,    127,   63,	  31,	 15,   7,    3};

struct Alloc {
	u64 chunks;
	i64 slab_pointers[SLAB_COUNT];
	u64 allocated_bytes;
	AllocType t;
	u8 padding[12];
};

typedef struct {
	u64 slab_size;
	i64 next;
} Chunk;

typedef struct {
	u64 size;
	u64 magic;
} MmapChunk;

u64 calculate_slab_index(u64 value);
u64 calculate_slab_size(u64 value);

#endif /* _ALLOC_IMPL_H */
