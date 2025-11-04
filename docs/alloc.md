# Overview

Libfam has its own memory allocator (alloc/release). These are comparable to malloc/free from libc. However, they are more performant. They outperform libc and jemalloc by using a slab allocator that uses arena allocation using lock-free methods to allocate memory.

# Using alloc/release

Using alloc/release is pretty straight forward. Simply link to libfam (-lfam) and call init_global_allocator(u64 num_chunks);
where num_chunks is the number of 4 megabyte chunks to preallocate. This will allocate a shared memory block that can be accessed by any of the child processes of the current process and that process itself. For example:

```
#include <libfam/memory.h>

i32 main(i32 argc, char **argv) {
	init_global_allocator(64);
	void *tmp = alloc(1024);
	release(tmp);
	return 0;
}
```

Save as test.c. Then compile/link to libfam:

```
clang -lfam -L/usr/lib/libfam-1.0.0 test.c
```

alloc/release/resize can be used exactly like malloc/free/realloc.

# Design/Architecture

```
┌────────────────────┐
│  Global Allocator  │ ← init_global_allocator(64)
├────────────────────┤
│  Slab[8]  Slab[16] │ ← 4 MB each
│  Slab[32] Slab[64] │
│  ...     Slab[1M]  │
└────────────────────┘
        ↓
     alloc(128)
        ↓
   CAS on bitmap → instant slot
        ↓
   return aligned pointer
```
alloc/release/resize (which correspond to malloc/free/realloc) are implement lock-free using arena scheduling. The basic approach is to request a 4mb 'chunk' for each slab size. Slab sizes range from 8 bytes to 1mb (each power of two in that range). When you 'alloc', a new chunk is allocated if it has not been allocated for that size. Then CAS (compare and swap) operations are used to efficiently allocate memory. This allow for thread safe allocation/deallocation and the above performance numbers. If a memory allocation of above the maximum slab size (1mb) is required, mmap is used directly with a header. mmap is also used in the event that no new chunks are available and the existing chunks of the required size are already full of allocations.
