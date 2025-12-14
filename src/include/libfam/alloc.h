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

#ifndef _ALLOC_H
#define _ALLOC_H

#include <libfam/types.h>

/*
 * Enum: AllocType
 * Selects the underlying allocation strategy for an Alloc instance.
 * values:
 *         AllocMap  - private map allocation (single process only)
 *         AllocSmap - shared map allocation (can be shared between processes)
 *         AllocFmap - file based mapping (maps a file to memory)
 */
typedef enum {
	AllocMap,
	AllocSmap,
	AllocFmap,
} AllocType;

/*
 * Type: Alloc
 * Opaque handle to an allocator instance.
 * notes:
 *         Created with alloc_init and destroyed with alloc_destroy.
 *         All allocation functions (balloc, brelease, bresize) operate on
 *         memory managed by this instance.
 */
typedef struct Alloc Alloc;

/*
 * Function: alloc_init
 * Creates and initializes a new allocator of the requested type.
 * inputs:
 *         AllocType t - the allocation strategy to use.
 *         u64 chunks  - initial number of internal chunks to pre-allocate.
 * return value: Alloc * - pointer to the new allocator, or NULL on failure
 *                        with errno set.
 * errors:
 *         EINVAL         - if t is invalid or chunks == 0.
 *         ENOMEM         - if unable to allocate initial memory.
 * notes:
 *         chunks controls initial capacity; each
 *         chunk is 4 mb large. allocator grows automatically.
 *         Must call alloc_destroy when finished to free all resources.
 *         Returned pointer must not be freed directly.
 */
Alloc *alloc_init(AllocType t, u64 chunks);

/*
 * Function: alloc_destroy
 * Destroys an allocator and releases all associated memory.
 * inputs:
 *         Alloc *a - pointer to the allocator to destroy.
 * return value: None.
 * errors: None.
 * notes:
 *         a must have been returned by a successful alloc_init.
 *         All pointers obtained via balloc/bresize become invalid.
 *         Safe to call on a NULL pointer (no-op).
 *         After destruction, a must not be used again.
 */
void alloc_destroy(Alloc *a);

/*
 * Function: balloc
 * Allocates a block of memory from the allocator.
 * inputs:
 *         Alloc *a    - pointer to the initialized allocator.
 *         u64 size    - number of bytes to allocate (must be > 0).
 * return value: void * - pointer to the allocated memory, or NULL on failure
 *                        with errno set.
 * errors:
 *         EINVAL         - if a is NULL or size == 0.
 *         ENOMEM         - if allocation fails (out of memory).
 * notes:
 *         Returned memory is uninitialized.
 *         Use brelease to free the memory.
 *         Thread-safe.
 */
void *balloc(Alloc *a, u64 size);

/*
 * Function: brelease
 * Releases a previously allocated block back to the allocator.
 * inputs:
 *         Alloc *a    - pointer to the allocator that owns the block.
 *         void *ptr   - pointer returned by balloc or bresize.
 * return value: None.
 * errors: None.
 * notes:
 *         ptr must be a valid, live pointer from this allocator.
 *         Passing NULL is safe (no-op).
 *         Passing a pointer from another allocator or already freed
 *         results in undefined behavior.
 *         After release, ptr must not be accessed.
 */
void brelease(Alloc *a, void *ptr);

/*
 * Function: bresize
 * Resizes a previously allocated block to a new size.
 * inputs:
 *         Alloc *a        - pointer to the allocator that owns the block.
 *         void *ptr       - pointer to the existing block (or NULL).
 *         u64 new_size    - desired new size in bytes (must be > 0).
 * return value: void * - pointer to the resized block (may be moved),
 *                        or NULL on failure with errno set.
 * errors:
 *         EINVAL         - if a is NULL or new_size == 0.
 *         ENOMEM         - if reallocation fails.
 * notes:
 *         If ptr is NULL, behaves like balloc(a, new_size).
 *         If successful, contents up to the smaller of old and new size
 *         are preserved.
 *         The returned pointer may differ from ptr; old pointer becomes
 *         invalid.
 *         Use brelease on the *new* pointer when done.
 */
void *bresize(Alloc *a, void *ptr, u64 new_size);

/*
 * Function: alloc_allocated_bytes
 * Returns the total number of bytes currently allocated.
 * inputs:
 *         const Alloc *a - pointer to the initialized allocator.
 * return value: u64 - total bytes in use by live allocations.
 * errors: None.
 * notes:
 *         a must not be NULL and must be valid.
 *         Value is exact at the time of call; may change immediately after.
 *         Useful for memory usage tracking and leak detection.
 *         Requires build with --mem_tracking enabled or test.
 */
u64 alloc_allocated_bytes(const Alloc *a);

/*
 * Function: alloc_reset_allocated_bytes
 * Resets the internal byte counter without freeing memory.
 * inputs:
 *         Alloc *a - pointer to the initialized allocator.
 * return value: None.
 * errors: None.
 * notes:
 *         Does *not* free any allocations; only clears the counter used by
 *         alloc_allocated_bytes.
 *         Intended for use in testing or when restarting tracking.
 *         a must not be NULL.
 *         Requires build with --mem_tracking enabled or test.
 */
void alloc_reset_allocated_bytes(Alloc *a);

#endif /* _ALLOC_H */
