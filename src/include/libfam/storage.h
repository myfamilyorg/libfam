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

#ifndef _STORAGE_H
#define _STORAGE_H

#include <libfam/types.h>

#define PAGE_SIZE 4096

typedef struct Storage Storage;
typedef struct StorageWriteBatch StorageWriteBatch;

i32 storage_open(Storage **storage, const char *path, u32 cache_size,
		 u32 queue_size);
void storage_destroy(Storage *s);
void *storage_load(Storage *s, u64 sector);
i32 storage_prefetch(Storage *s, u64 sector);
i32 storage_write_batch_init(Storage *s, StorageWriteBatch **batch);
void storage_write_batch_destroy(StorageWriteBatch *batch);
i32 storage_sched_write(StorageWriteBatch *batch, const void *page, u64 sector);
i32 storage_write_complete(StorageWriteBatch *batch);

#endif /* _STORAGE_H */
