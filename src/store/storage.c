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

#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/memory.h>
#include <libfam/storage.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#define PAGE_SIZE 4096
#define HASH_CONSTANT 0x9e3779b9U

typedef struct LRUEntry {
	u64 sector;
	u8 *page;
	u32 next_chain;
	u32 next_lru;
	u32 prev_lru;
} LRUEntry;

struct Storage {
	LRUEntry *entries;
	u32 *hashmap;
	u32 hashmap_size;
	u32 oldest;
	u32 newest;
	i32 fd;
	IoUring *iou;
};

i32 storage_open(Storage **storage, const char *path, u32 cache_size,
		 u32 queue_size) {
	u64 hashmap_size = cache_size * 2;
	Storage *ret = NULL;
	IoUring *iou = NULL;
INIT:
	ret = alloc(sizeof(Storage));
	if (!ret) ERROR();

	if (iouring_init(&iou, queue_size) < 0) ERROR();
	ret->fd = open(path, O_RDWR | O_DIRECT, 0600);
	if (ret->fd < 0) ERROR();
	ret->iou = iou;
	ret->entries = alloc(sizeof(LRUEntry) * cache_size);
	if (!ret->entries) ERROR();
	ret->hashmap = alloc(sizeof(u32) * hashmap_size);
	if (!ret->hashmap) ERROR();
	memset(ret->hashmap, 0xFF, sizeof(u32) * hashmap_size);
	ret->hashmap_size = hashmap_size;

	ret->oldest = cache_size - 1;
	ret->newest = 0;
	for (u32 i = 0; i < cache_size; i++) {
		ret->entries[i].next_lru = i + 1;
		ret->entries[i].prev_lru = i - 1;
		ret->entries[i].next_chain = U32_MAX;
		ret->entries[i].sector = U64_MAX;
		ret->entries[i].page = NULL;
	}
	ret->entries[cache_size - 1].next_lru = U32_MAX;

	*storage = ret;
CLEANUP:
	if (!IS_OK) storage_destroy(ret);
	RETURN;
}

void storage_destroy(Storage *s) {
	if (s) {
		if (s->entries) release(s->entries);
		if (s->hashmap) release(s->hashmap);
		if (s->iou) iouring_destroy(s->iou);
		if (s->fd > 0) close(s->fd);
		s->fd = -1;
		s->iou = NULL;
		s->hashmap = NULL;
		s->entries = NULL;
		release(s);
	}
}

void *storage_load(Storage *s, u64 sector) {
	u32 hash = (sector * HASH_CONSTANT) % s->hashmap_size;
	u32 index = s->hashmap[hash];
	LRUEntry *cur = &s->entries[index];
	while (true) {
		if (cur->sector == U64_MAX) break;
		if (cur->sector == sector) return cur->page;
		cur = &s->entries[cur->next_chain];
	}
	return NULL;
}
