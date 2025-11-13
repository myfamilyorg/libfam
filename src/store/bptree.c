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

#include <libfam/bitmap.h>
#include <libfam/bptree.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#define PAGE_SIZE 4096

typedef struct {
	u64 file_size;
} BpTreeSuperBlock;

STATIC u64 bptree_bitmap_size(u64 size) {
	u64 bits, bitmap_size, bytes_needed;
	bits = (size / PAGE_SIZE) - 2;
	bitmap_size = bitmap_bound(bits);
	bytes_needed = bitmap_size + (1 + bits) * PAGE_SIZE;
	while (bytes_needed > size) {
		bits--;
		bitmap_size = bitmap_bound(bits);
		bytes_needed = bitmap_size + (1 + bits) * PAGE_SIZE;
	}

	return ((bitmap_size + (PAGE_SIZE - 1)) / PAGE_SIZE) * PAGE_SIZE;
}

STATIC i32 bptree_init(BpTreeSuperBlock *super, u64 size) {
INIT:
	super->file_size = size;
CLEANUP:
	RETURN;
}

STATIC i32 bptree_check_size(BpTree *tree, u64 size) {
	BpTreeSuperBlock *super = (void *)tree;
INIT:
	if (super->file_size == size) OK(0);
	if (!super->file_size) {
		if (bptree_init(super, size) < 0) ERROR();
	} else {
		ERROR(EINVAL);
	}
CLEANUP:
	RETURN;
}

i32 bptree_open(BpTree **tree, const u8 *path) {
	BpTreeSuperBlock *ret = NULL;
	i32 fd = 0;
	i64 size;
	u64 bitmap_size;
INIT:
	if (!exists(path)) ERROR(EINVAL);
	if ((fd = file(path)) < 0) ERROR();
	if ((size = fsize(fd)) < sizeof(BpTreeSuperBlock)) ERROR(EINVAL);
	bitmap_size = bptree_bitmap_size(size);
	if (!(ret = fmap(fd, bitmap_size + sizeof(BpTreeSuperBlock), 0)))
		ERROR();
	if (bptree_check_size((void *)ret, size) < 0) ERROR();
	if (msync(ret, sizeof(BpTreeSuperBlock), MS_SYNC) < 0) ERROR();
	*tree = (void *)ret;
CLEANUP:
	if (fd > 0) close(fd);
	if (!IS_OK && ret) munmap(ret, size);
	RETURN;
}

i32 bptree_destroy(BpTree *tree);

