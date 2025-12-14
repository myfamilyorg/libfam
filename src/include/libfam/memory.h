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

#ifndef _MEMORY_H
#define _MEMORY_H

#include <libfam/types.h>

/*
 * Function: init_global_allocator
 * Initializes the global memory allocator with the given initial chunk count.
 * inputs:
 *         u64 chunks - initial number of allocation chunks to pre-allocate.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if chunks == 0.
 *         ENOMEM         - if initial allocation fails.
 * notes:
 *         Must be called once before any alloc/resize/release calls.
 *         Automatically called via INIT_GLOBAL_ALLOCATOR if used.
 *         Idempotent: safe to call multiple times (subsequent calls are
 * no-ops). Sets up internal Alloc instance (see alloc.h).
 */
i32 init_global_allocator(u64 chunks);

/*
 * Function: alloc
 * Allocates a block of memory from the global allocator.
 * inputs:
 *         u64 size - number of bytes to allocate (must be > 0).
 * return value: void * - pointer to allocated memory, or NULL on failure.
 * errors:
 *         ENOMEM         - if allocation fails.
 * notes:
 *         Memory is uninitialized.
 *         Use release to free.
 *         Thread-safe if init_global_allocator was called.
 *         Equivalent to balloc(&global_alloc, size).
 */
void *alloc(u64 size);

/*
 * Function: resize
 * Resizes a previously allocated block.
 * inputs:
 *         void *ptr     - pointer returned by alloc or resize (or NULL).
 *         u64 new_size  - desired new size in bytes (must be > 0).
 * return value: void * - pointer to resized block, or NULL on failure.
 * errors:
 *         ENOMEM         - if reallocation fails.
 * notes:
 *         If ptr is NULL, behaves like alloc(new_size).
 *         Contents up to min(old_size, new_size) are preserved.
 *         Returned pointer may differ from ptr; old pointer becomes invalid.
 *         Use release on the *new* pointer when done.
 *         Equivalent to bresize(&global_alloc, ptr, new_size).
 */
void *resize(void *ptr, u64 new_size);

/*
 * Function: release
 * Releases a previously allocated block back to the global allocator.
 * inputs:
 *         void *ptr - pointer returned by alloc or resize.
 * return value: None.
 * errors: None.
 * notes:
 *         ptr must be a valid, live pointer from this allocator.
 *         Passing NULL is safe (no-op).
 *         Passing invalid or already-freed pointer results in undefined
 * behavior. After release, ptr must not be accessed. Equivalent to
 * brelease(&global_alloc, ptr).
 */
void release(void *ptr);

/*
 * Function: allocated_bytes
 * Returns the total number of bytes currently allocated.
 * inputs: None.
 * return value: u64 - total bytes in use by live allocations.
 * errors: None.
 * notes:
 *         Value is exact at the time of call; may change immediately after.
 *         Useful for memory usage tracking and leak detection.
 *         Equivalent to alloc_allocated_bytes(&global_alloc).
 *         Requires build with --mem_tracking enabled or test.
 */
u64 allocated_bytes(void);

/*
 * Function: reset_allocated_bytes
 * Resets the internal byte counter without freeing memory.
 * inputs: None.
 * return value: None.
 * errors: None.
 * notes:
 *         Does *not* free any allocations; only clears the counter used by
 *         allocated_bytes.
 *         Intended for use in testing or restarting tracking.
 *         Equivalent to alloc_reset_allocated_bytes(&global_alloc).
 *         Requires build with --mem_tracking enabled or test.
 */
void reset_allocated_bytes(void);

/*
 * Macro: INIT_GLOBAL_ALLOCATOR
 * Automatically initializes the global allocator at program startup.
 * inputs:
 *         chunks - initial number of chunks (4mb blocks) to pre-allocate.
 * notes:
 *         Uses a constructor function to call init_global_allocator(chunks).
 *         Must be placed at file scope in exactly one translation unit.
 *         Ensures allocator is ready before main() or any static initializers.
 *         Example:
 *           INIT_GLOBAL_ALLOCATOR(1024);
 */
#define INIT_GLOBAL_ALLOCATOR(chunks)                                       \
	void __attribute__((constructor)) __init_global_allocator__(void) { \
		init_global_allocator(chunks);                              \
	}

#endif /* _MEMORY_H */
