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

#include <libfam/storage.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

Test(store1) {
	void *values[74];
	const u8 *path = "/tmp/store1.dat";
	void *ptr;
	Storage *s1 = NULL;
	unlink(path);
	i32 fd = file(path);
	fresize(fd, 4096 * 128);
	close(fd);
	ASSERT(!storage_open(&s1, path, 64, 512), "storage_open");
	ASSERT(s1, "s1");

	for (u32 i = 0; i < 74; i++) {
		ptr = storage_load(s1, i);
		values[i] = ptr;
		ASSERT(ptr, "storage_load {}", i);

		if (i == 50) {
			ptr = storage_load(s1, 40);
			ASSERT(ptr, "storage load 40 (cached)");
			ASSERT_EQ(ptr, values[40], "values[40]");
		}
	}

	ptr = storage_load(s1, 0);
	ASSERT(ptr, "storage_load 0");
	ASSERT(ptr != values[0], "cache removed");

	storage_destroy(s1);
	unlink(path);
	ASSERT_BYTES(0);
}

Test(store2) {
	const u8 *path = "/tmp/store2.dat";
	Storage *s1 = NULL;
	StorageWriteBatch *b1;
	unlink(path);
	i32 fd = file(path);
	fresize(fd, 4096 * 128);
	close(fd);
	ASSERT(!storage_open(&s1, path, 64, 512), "storage_open");
	ASSERT(s1, "s1");

	u8 page[PAGE_SIZE] = {0};
	page[0] = 1;
	page[1] = 2;
	page[2] = 3;

	ASSERT(!storage_write_batch_init(s1, &b1), "batch_init");
	ASSERT(!storage_sched_write(b1, page, 0), "storage_sched_write");
	ASSERT(!storage_write_complete(b1), "write_complete");

	u8 *ptr = storage_load(s1, 0);
	ASSERT(ptr, "ptr");
	ASSERT_EQ(ptr[0], 1, "ptr[0]");
	ASSERT_EQ(ptr[1], 2, "ptr[1]");
	ASSERT_EQ(ptr[2], 3, "ptr[2]");
	ASSERT_EQ(ptr[3], 0, "ptr[3]");

	storage_write_batch_destroy(b1);
	storage_destroy(s1);
	unlink(path);
	ASSERT_BYTES(0);
}
