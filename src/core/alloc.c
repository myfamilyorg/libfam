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

#include <libfam/alloc.h>
#include <libfam/alloc_impl.h>
#include <libfam/atomic.h>
#include <libfam/bitmap.h>
#include <libfam/builtin.h>
#include <libfam/debug.h>
#include <libfam/limits.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#if TEST == 1
#ifndef MEM_TRACKING
#define MEM_TRACKING
#endif /* MEM_TRACKING */
#endif /* TEST */

#define _p(msg)                                         \
	do {                                            \
		pwrite(STDERR_FD, msg, strlen(msg), 0); \
		_exit(-1);                              \
		return;                                 \
	} while (0);

STATIC Chunk *alloc_chunk_for_offset(Alloc *a, i64 offset) {
	return (Chunk *)((u8 *)a + sizeof(Alloc) + bitmap_bound(a->chunks) +
			 offset * CHUNK_SIZE);
}

STATIC i64 alloc_chunk_offset(Alloc *a, i64 *ptr, u64 slab_size, u64 index) {
	i64 cur = -1;
	while ((cur = __aload64(ptr)) < 0) {
		BitMap *bmp = (BitMap *)((u8 *)a + sizeof(Alloc));
		if ((cur = bitmap_find_free_bit(bmp)) < 0) break;
		i64 expected = -1;
#if TEST == 1
		if (!_debug_alloc_cas_loop && __cas64(ptr, &expected, cur)) {
#else
		if (__cas64(ptr, &expected, cur)) {
#endif
			Chunk *chunk = alloc_chunk_for_offset(a, cur);
			chunk->slab_size = slab_size;
			BitMap *cbmp = (BitMap *)((u8 *)chunk + sizeof(Chunk));
			bitmap_init(cbmp, BITS_PER_SLAB_INDEX[index]);
			chunk->next = -1;
			mfence();
			break;
		}
#if TEST == 1
		if (_debug_alloc_cas_loop) _debug_alloc_cas_loop--;
#endif
		bitmap_release_bit(bmp, cur);
	}
	return cur;
}

STATIC void *alloc_from_chunk(Chunk *chunk) {
	BitMap *bmp = (BitMap *)((u8 *)chunk + sizeof(Chunk));
	i64 bit = bitmap_find_free_bit(bmp);
	return bit >= 0 ? ((u8 *)chunk) + sizeof(Chunk) + bitmap_size(bmp) +
			      bit * chunk->slab_size
			: NULL;
}

STATIC void *alloc_slab(Alloc *a, u64 size) {
	void *ret = NULL;
	u64 slab_size = calculate_slab_size(size);
	if (!slab_size) return NULL;
	u64 index = calculate_slab_index(size);
	i64 *ptr = &a->slab_pointers[index];
	i64 cur;
	while ((cur = alloc_chunk_offset(a, ptr, slab_size, index)) >= 0) {
		Chunk *chunk = alloc_chunk_for_offset(a, cur);
		while (__aload64(&chunk->next) == 0);
		if ((ret = alloc_from_chunk(chunk))) break;
		ptr = &chunk->next;
	}
#ifdef MEM_TRACKING
	if (ret) __aadd64(&a->allocated_bytes, slab_size);
#endif /* MEM_TRACKING */
	return ret;
}

STATIC void release_slab(Alloc *a, void *ptr) {
	BitMap *bmp = (BitMap *)((u8 *)a + sizeof(Alloc));
	u64 base = (u64)((u8 *)a + sizeof(Alloc)) + bitmap_size(bmp);
	u64 offset = (u64)ptr - base;
	u64 chunk_offset = offset / CHUNK_SIZE;
	Chunk *chunk = (Chunk *)((u8 *)base + chunk_offset * CHUNK_SIZE);
	BitMap *chunk_bmp = (BitMap *)((u8 *)chunk + sizeof(Chunk));
	u64 slab_size = chunk->slab_size;
	u64 bmp_size = bitmap_size(chunk_bmp);
	u64 index =
	    ((u64)ptr - ((u64)chunk + sizeof(Chunk) + bmp_size)) / slab_size;
	bitmap_release_bit(chunk_bmp, index);
#ifdef MEM_TRACKING
	__asub64(&a->allocated_bytes, slab_size);
#endif /* MEM_TRACKING */
}

STATIC void *alloc_map(Alloc *a, u64 size) {
	MmapChunk *chunk = NULL;
	if (a->t == AllocMap)
		chunk = map(size + sizeof(MmapChunk));
	else if (a->t == AllocSmap)
		chunk = smap(size + sizeof(MmapChunk));
	if (chunk) {
		chunk->size = size;
		chunk->magic = MAGIC;
#ifdef MEM_TRACKING
		__aadd64(&a->allocated_bytes, size);
#endif /* MEM_TRACKING */
		return (u8 *)chunk + sizeof(MmapChunk);
	} else {
		errno = ENOMEM;
		return NULL;
	}
}

STATIC void release_map(Alloc *a, void *ptr) {
	MmapChunk *chunk = (MmapChunk *)((u8 *)ptr - sizeof(MmapChunk));
#ifdef MEM_TRACKING
	__asub64(&a->allocated_bytes, chunk->size);
#endif /* MEM_TRACKING */

	if (chunk->magic != MAGIC) _p(MAGIC_ERROR);
	if (munmap(chunk, chunk->size) < 0) _p("munmap1");
}

STATIC u64 current_size(Alloc *a, void *ptr) {
	if ((u8 *)ptr > (u8 *)a &&
	    (u8 *)ptr < (u8 *)a + TOTAL_SIZE(a->chunks)) {
		BitMap *bmp = (BitMap *)((u8 *)a + sizeof(Alloc));
		u64 base = (u64)((u8 *)a + sizeof(Alloc)) + bitmap_size(bmp);
		u64 offset = (u64)ptr - base;
		u64 chunk_offset = offset / CHUNK_SIZE;
		Chunk *chunk =
		    (Chunk *)((u8 *)base + chunk_offset * CHUNK_SIZE);
		return chunk->slab_size;
	} else {
		MmapChunk *chunk = (MmapChunk *)((u8 *)ptr - sizeof(MmapChunk));
		return chunk->size;
	}
}

u64 calculate_slab_index(u64 value) {
	if (value <= 8) return 0;
	value--;
	return (64 - clz_u64(value)) - 3;
}

u64 calculate_slab_size(u64 value) {
	if (value > MAX_SLAB_SIZE) return 0;
	if (value <= 8) return 8;
	value--;
	return 1UL << (64 - clz_u64(value));
}

Alloc *alloc_init(AllocType t, u64 chunks) {
	Alloc *ret = NULL;
	u64 needed = TOTAL_SIZE(chunks);
	if (t == AllocMap)
		ret = map(needed);
	else if (t == AllocSmap)
		ret = smap(needed);
	if (ret) {
		i32 i;
		ret->chunks = chunks;
		for (i = 0; i < SLAB_COUNT; i++) ret->slab_pointers[i] = -1;
#ifdef MEM_TRACKING
		ret->allocated_bytes = 0;
#endif /* MEM_TRACKING */
		ret->t = t;
		BitMap *bmp = (BitMap *)((u8 *)ret + sizeof(Alloc));
		bitmap_init(bmp, chunks);
	}

	return ret;
}

void alloc_destroy(Alloc *a) {
	if (!a) return;
	u64 total_size = TOTAL_SIZE(a->chunks);
	if (munmap(a, total_size) < 0) _p("munmap2");
}

void *balloc(Alloc *a, u64 size) {
#if TEST == 1
	if (_debug_alloc_failure) return NULL;
#endif /* TEST */
	void *ret = alloc_slab(a, size);
	if (!ret) ret = alloc_map(a, size);
	return ret;
}

void brelease(Alloc *a, void *ptr) {
	if (!ptr) return;
	if ((u8 *)ptr > (u8 *)a &&
	    (u8 *)ptr < (u8 *)a + TOTAL_SIZE(a->chunks)) {
		release_slab(a, ptr);
	} else {
		release_map(a, ptr);
	}
}

void *bresize(Alloc *a, void *ptr, u64 new_size) {
	void *ret = NULL;
	if (!ptr) return balloc(a, new_size);
	if (!new_size) {
		brelease(a, ptr);
		return ret;
	}
	u64 old_size = current_size(a, ptr);
	if (new_size < MAX_SLAB_SIZE) {
		u64 new_slab_size = calculate_slab_size(new_size);
		if (new_slab_size == old_size) return ptr;
	}
	ALLOC_AND_COPY(a, new_size, ptr, old_size, ret);
	if (ret) brelease(a, ptr);
	return ret;
}

u64 alloc_allocated_bytes(const Alloc *a) {
	return __aload64(&a->allocated_bytes);
}

void alloc_reset_allocated_bytes(Alloc *a) {
	__astore64(&a->allocated_bytes, 0);
	mfence();
}

