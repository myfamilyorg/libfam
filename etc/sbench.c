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
#include <libfam/memory.h>
#include <libfam/storage.h>
#include <libfam/sysext.h>
#include <libfam/types.h>

#define SECTORS 256

i32 main(i32 argc, char **argv) {
	Storage *s = NULL;
	init_global_allocator(64);
	/*u8 __attribute__((aligned(4096))) page[PAGE_SIZE] = {0};*/

	if (argc != 2) panic("Usage: ./sbench <path>");

	if (storage_open(&s, argv[1], 64, 512) < 0)
		panic("Storage open failed: {}", strerror(errno));

	u8 *page = storage_get_registered_buffer(s);

	i64 timer = micros();
	for (u32 i = 0; i < SECTORS; i++) {
		page[0] = 'A' + (i % 26);
		StorageWriteBatch *wb = NULL;
		storage_write_batch_init(s, &wb);
		storage_sched_write(wb, page, i);
		storage_write_complete(wb);
		storage_write_batch_destroy(wb);
	}
	i64 store_time = micros() - timer;

	for (u32 i = 0; i < SECTORS; i++) {
		u8 *lp = storage_load(s, i);
		if (lp[0] != ('A' + (i % 26))) panic("mismatch at {}", i);
	}
	timer = micros() - timer;
	println("success: {} micros, store time = {}", timer, store_time);

	storage_unregister_buffers(s);
	munmap(page, PAGE_SIZE);
	storage_destroy(s);
	return 0;
}
