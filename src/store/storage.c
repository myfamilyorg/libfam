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

#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/memory.h>
#include <libfam/storage.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

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

struct StorageWriteBatch {
	u64 next;
	Storage *s;
};

STATIC void storage_lru_touch(Storage *s, u32 idx) {
	if (s->newest != idx) {
		LRUEntry *e = &s->entries[idx];
		if (e->prev_lru != U32_MAX)
			s->entries[e->prev_lru].next_lru = e->next_lru;
		if (e->next_lru != U32_MAX)
			s->entries[e->next_lru].prev_lru = e->prev_lru;
		if (s->oldest == idx) s->oldest = e->next_lru;

		e->prev_lru = U32_MAX;
		e->next_lru = s->newest;
		s->entries[s->newest].next_lru = idx;
		s->newest = idx;
	}
}

i32 storage_open(Storage **storage, const char *path, u32 cache_size,
		 u32 queue_size) {
	u64 hashmap_size = cache_size * 2;
	Storage *ret = NULL;
	IoUring *iou = NULL;
	u8 *pages = NULL;
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

	ret->oldest = 0;
	ret->newest = cache_size - 1;
	pages = smap(PAGE_SIZE * cache_size);
	if (!pages) ERROR();
	for (u32 i = 0; i < cache_size; i++) {
		ret->entries[i].page = pages + PAGE_SIZE * i;
		ret->entries[i].next_lru = i + 1;
		ret->entries[i].prev_lru = i - 1;
		ret->entries[i].next_chain = U32_MAX;
		ret->entries[i].sector = U64_MAX;
	}
	ret->entries[cache_size - 1].next_lru = U32_MAX;

	*storage = ret;
CLEANUP:
	if (!IS_OK) {
		storage_destroy(ret);
		if (pages) release(pages);
	}
	RETURN;
}

void storage_destroy(Storage *s) {
	if (s) {
		if (s->entries) {
			if (s->entries[0].page)
				munmap(s->entries[0].page, s->hashmap_size / 2);
			release(s->entries);
		}
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
	u32 idx = s->hashmap[hash];

	while (idx != U32_MAX) {
		LRUEntry *e = &s->entries[idx];
		if (e->sector == sector) {
			storage_lru_touch(s, idx);
			return e->page;
		}
		idx = e->next_chain;
	}

	u32 victim = s->oldest;
	LRUEntry *victim_entry = &s->entries[victim];

	i64 res =
	    pread64(s->fd, victim_entry->page, PAGE_SIZE, sector * PAGE_SIZE);
	if (res < 0) return NULL;
	if (res != PAGE_SIZE) {
		errno = EIO;
		return NULL;
	}

	s->oldest = victim_entry->next_lru;
	LRUEntry *oldest_entry = &s->entries[s->oldest];
	oldest_entry->prev_lru = U32_MAX;

	idx = s->hashmap[hash];
	if (idx == U32_MAX)
		s->hashmap[hash] = victim;
	else {
		while (true) {
			u32 next = s->entries[idx].next_chain;
			if (next == U32_MAX) {
				s->entries[idx].next_chain = victim;
				break;
			}
		}
	}

	u64 orig_sector = victim_entry->sector;
	storage_lru_touch(s, victim);
	victim_entry->sector = sector;

	if (orig_sector != U64_MAX) {
		u32 old_hash =
		    (victim_entry->sector * HASH_CONSTANT) % s->hashmap_size;
		u32 prev = U32_MAX;
		u32 curr = s->hashmap[old_hash];
		while (curr != U32_MAX) {
			if (curr == victim) {
				if (prev == U32_MAX)
					s->hashmap[old_hash] =
					    victim_entry->next_chain;
				else
					s->entries[prev].next_chain =
					    victim_entry->next_chain;

				break;
			}
			prev = curr;
			curr = s->entries[curr].next_chain;
		}
	}

	return victim_entry->page;
}

i32 storage_write_batch_init(Storage *s, StorageWriteBatch **batch) {
	StorageWriteBatch *ret = NULL;
INIT:
	ret = alloc(sizeof(StorageWriteBatch));
	if (!ret) ERROR();
	ret->s = s;
	ret->next = 0;
	*batch = ret;
CLEANUP:
	RETURN;
}

void storage_write_batch_destroy(StorageWriteBatch *batch) { release(batch); }

i32 storage_sched_write(StorageWriteBatch *batch, const void *page,
			u64 sector) {
INIT:
	println("init write fd={},page={X},size={},offset={},id={}",
		batch->s->fd, (u64)page, PAGE_SIZE, sector * PAGE_SIZE,
		batch->next);
	if (iouring_init_write(batch->s->iou, batch->s->fd, page, PAGE_SIZE,
			       sector * PAGE_SIZE, batch->next) < 0)
		ERROR();
	batch->next++;
CLEANUP:
	RETURN;
}

i32 storage_write_complete(StorageWriteBatch *batch) {
	u64 id, complete_count = 0;
	i32 res;
	u8 *complete = NULL;
INIT:
	if (!batch->next) OK(0);

	/*
	if (iouring_init_fsync(batch->s->iou, batch->s->fd, batch->next) < 0)
		ERROR();

	batch->next++;
	*/

	complete = alloc(sizeof(u8) * batch->next);
	if (!complete) ERROR();
	memset(complete, 0, sizeof(u8) * batch->next);

	println("iouring submit with next={}", batch->next);
	if (iouring_submit(batch->s->iou, batch->next) < 0) ERROR();
	while (complete_count < batch->next) {
		res = iouring_spin(batch->s->iou, &id);
		if (res < 0) perror("iouring_spin");
		println("res={},id={}", res, id);
		if (res < 0) ERROR();
		if (id >= batch->next) ERROR(EINVAL);

		if (id != batch->next - 1) {
			if (res < PAGE_SIZE) ERROR(EIO);
			if (complete[id]) ERROR(EINVAL);
			complete[id] = 1;
		}

		complete_count++;
	}
CLEANUP:
	release(complete);
	batch->next = 0;
	RETURN;
}

