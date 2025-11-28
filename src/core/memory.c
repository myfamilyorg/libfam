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
#include <libfam/atomic.h>
#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/errno.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

Alloc *global_allocator = NULL;

STATIC i32 try_set_global_allocator(Alloc *allocator) {
	u64 *expected = NULL;
	i32 cas_res = __cas64((void *)&global_allocator, (void *)&expected,
			      (u64)allocator);
	return cas_res ? 0 : -1;
}

PUBLIC i32 init_global_allocator(u64 chunks) {
	if (__aload64((u64 *)&global_allocator)) return -1;
	Alloc *allocator = alloc_init(AllocSmap, chunks);
	if (!allocator) return -1;

	i32 cas_res = try_set_global_allocator(allocator);
	if (cas_res < 0) alloc_destroy(allocator);
	return cas_res;
}

PUBLIC void *alloc(u64 size) { return balloc(global_allocator, size); }
PUBLIC void *resize(void *ptr, u64 new_size) {
	return bresize(global_allocator, ptr, new_size);
}
PUBLIC void release(void *ptr) { brelease(global_allocator, ptr); }

PUBLIC u64 allocated_bytes(void) {
	return alloc_allocated_bytes(global_allocator);
}

PUBLIC void reset_allocated_bytes(void) {
	alloc_reset_allocated_bytes(global_allocator);
}

