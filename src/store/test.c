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
	const u8 *path = "/tmp/storage1.dat";
	Storage *s1 = NULL;
	unlink(path);
	i32 fd = file(path);
	fresize(fd, 4096 * 128);
	close(fd);
	ASSERT(!storage_open(&s1, path, 64, 512), "storage_open");
	ASSERT(s1, "s1");

	for (u32 i = 0; i < 64; i++) {
		void *ptr = storage_load(s1, i);
		ASSERT(ptr, "storage_load 0");
		/*println("i={},ptr={X}", i, ptr);*/
	}

	storage_destroy(s1);
	unlink(path);
	ASSERT_BYTES(0);
}
