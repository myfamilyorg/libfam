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

#ifndef _IO_URING_H
#define _IO_URING_H

#include <libfam/types.h>

/*
 * Type: IoUring
 * Opaque handle to an io_uring instance.
 * notes:
 *         Created with iouring_init and destroyed with iouring_destroy.
 *         All operations are asynchronous; use iouring_spin
 *         to check completion.
 */
typedef struct IoUring IoUring;

/*
 * required type for the open system call.
 */
struct open_how;

/*
 * Function: iouring_init
 * Initializes a new io_uring instance with the given queue depth.
 * inputs:
 *         IoUring **iou        - pointer to store the new IoUring handle.
 *         u32 queue_depth      - number of submission/completion queue entries.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if queue_depth is 0 or too large.
 *         EIO            - if io_uring setup fails (kernel support missing).
 * notes:
 *         *iou is set to the new handle on success.
 *         queue_depth must be a power of 2 and <= IORING_MAX_ENTRIES.
 *         Must call iouring_destroy when finished.
 */
i32 iouring_init(IoUring **iou, u32 queue_depth);

/*
 * Function: iouring_init_pread
 * Queues an asynchronous read operation.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 fd               - file descriptor to read from.
 *         void *buf            - buffer to store read data.
 *         u64 len              - number of bytes to read.
 *         u64 foffset          - file offset to read from.
 *         u64 id               - user-defined identifier for the operation.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if iou is null, fd invalid, or len == 0.
 *         EBUSY          - if too many requests have been queued.
 * notes:
 *         Operation is queued but not submitted until iouring_submit.
 *         id must be unique among pending operations.
 *         Use iouring_wait or iouring_spin to check completion.
 *         On completion, len bytes are read into buf (or fewer on EOF).
 */
i32 iouring_init_pread(IoUring *iou, i32 fd, void *buf, u64 len, u64 foffset,
		       u64 id);

/*
 * Function: iouring_init_pwrite
 * Queues an asynchronous write operation.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 fd               - file descriptor to pwrite to.
 *         const void *buf      - buffer containing data to write.
 *         u64 len              - number of bytes to write.
 *         u64 foffset          - file offset to write to
 *         u64 id               - user-defined identifier for the operation.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if iou is null, fd invalid, or len == 0.
 *         EBUSY          - if too many requests have been queued.
 * notes:
 *         Operation is queued but not submitted until iouring_submit.
 *         id must be unique among pending operations.
 *         Use iouring_wait or iouring_spin to check completion.
 *         On completion, len bytes are written from buf (or fewer on error).
 */
i32 iouring_init_pwrite(IoUring *iou, i32 fd, const void *buf, u64 len,
			u64 foffset, u64 id);

/*
 * Function: iouring_init_fsync
 * Queues an asynchronous fsync operation.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 fd               - file descriptor to fsync.
 *         u64 id               - user-defined identifier for the operation.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if iou is null, fd invalid.
 *         EBUSY          - if too many requests have been queued.
 * notes:
 *         Operation is queued but not submitted until iouring_submit.
 *         id must be unique among pending operations.
 *         Use iouring_wait or iouring_spin to check completion.
 *         On completion, file is fsynced.
 */
i32 iouring_init_fsync(IoUring *iou, i32 fd, u64 id);

/*
 * Function: iouring_init_openat
 * Queues an asynchronous openat operation using the extended open_how
 * interface.
 *
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 dirfd            - directory file descriptor (or AT_FDCWD).
 *         const char *path     - pathname relative to dirfd.
 *         struct open_how *how - pointer to struct open_how specifying flags,
 * mode, resolve flags, etc. u64 id               - user-defined identifier for
 * the operation.
 *
 * return value: i32 - 0 on success, -1 on error with errno set.
 *
 * errors:
 *         EINVAL         - if iou is NULL, path is NULL, how is NULL, or
 * invalid parameters.
 *         EBUSY          - if too many requests have been queued.
 *
 * notes:
 *         Operation is queued but not submitted until iouring_submit() is
 * called. id must be unique among pending operations.
 * Use iouring_wait or iouring_spin to retrieve the completion.
 */
i32 iouring_init_openat(IoUring *iou, i32 dirfd, const char *path,
			struct open_how *how, u64 id);

/*
 * Function: iouring_init_close
 * Queues an asynchronous close operation for a file descriptor.
 *
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 fd               - file descriptor to close.
 *         u64 id               - user-defined identifier for the operation.
 *
 * return value: i32 - 0 on success, -1 on error with errno set.
 *
 * errors:
 *         EINVAL         - if iou is NULL or fd is negative.
 *         EBUSY          - if too many requests have been queued.
 *
 * notes:
 *         Operation is queued but not submitted until iouring_submit() is
 * called. id must be unique among pending operations.
 * Use iouring_wait or iouring_spin to check completion.
 */
i32 iouring_init_close(IoUring *iou, i32 fd, u64 id);

/*
 * Function: iouring_init_fallocate
 * Queues an asynchronous fallocate operation to preallocate or deallocate
 * space.
 *
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         i32 fd               - open file descriptor (must be seekable).
 *         u64 new_size         - desired new file size in bytes (used with
 * FALLOC_FL_KEEP_SIZE or as length). u64 id               - user-defined
 * identifier for the operation.
 *
 * return value: i32 - 0 on success, -1 on error with errno set.
 *
 * errors:
 *         EINVAL         - if iou is NULL, fd invalid, or unsupported flags.
 *         EBUSY          - if too many requests have been queued.
 *
 * notes:
 *         Operation is queued but not submitted until iouring_submit() is
 * called. id must be unique among pending operations. Uses IORING_OP_FALLOCATE.
 */
i32 iouring_init_fallocate(IoUring *iou, i32 fd, u64 new_size, u64 id);

/*
 * Function: iouring_submit
 * Submits queued operations to the kernel.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         u32 count            - number of operations to submit (0 = all).
 * return value: i32 - number of operations submitted, or -1 on error.
 * errors:
 *         EINVAL         - if iou is null or count exceeds queued ops.
 *         EIO            - if kernel submission fails.
 * notes:
 *         Returns the actual number of operations submitted.
 *         Must be called after iouring_init_pread/pwrite and before checking
 *         completion with iouring_spin or iouring_wait.
 */
i32 iouring_submit(IoUring *iou, u32 count);

/*
 * Function: iouring_spin
 * Waits for and returns the id of a completed operation.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         u64 *id              - pointer to store the completed operation id.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if iou or id is null.
 *         EIO            - if kernel completion queue error.
 * notes:
 *         Spinlocks until at least one operation completes.
 *         On success, *id is set to the user-defined id of the completed op.
 *         The result (success/failure) of the operation is not returned here.
 *         Call repeatedly to drain all completions.
 */
i32 iouring_spin(IoUring *iou, u64 *id);

/*
 * Function: iouring_wait
 * Waits for and returns the id of a completed operation. Identical to
 * iouring_spin, except that it blocks instead of spin/yield.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 *         u64 *id              - pointer to store the completed operation id.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if iou or id is null.
 *         EIO            - if kernel completion queue error.
 * notes:
 *         Waits until at least one operation completes.
 *         On success, *id is set to the user-defined id of the completed op.
 *         The result (success/failure) of the operation is not returned here.
 *         Call repeatedly to drain all completions.
 */
i32 iouring_wait(IoUring *iou, u64 *id);

/*
 * Function: iouring_destroy
 * Destroys an io_uring instance and releases all resources.
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 * return value: None.
 * errors: None.
 * notes:
 *         iou must not be null and must be from iouring_init.
 *         Waits for all pending operations to complete before destroying.
 *         Safe to call multiple times (no-op after first).
 *         After destruction, iou must not be used.
 */
void iouring_destroy(IoUring *iou);

/*
 * Function: iouring_ring_fd
 * Returns the underlying iouring file descriptor
 * inputs:
 *         IoUring *iou         - initialized io_uring handle.
 * return value: the ring_fd.
 * errors: None.
 */
i32 iouring_ring_fd(IoUring *iou);

bool iouring_pending(IoUring *iou, u64 id);
bool iouring_pending_all(IoUring *iou);

#endif /* _IO_URING_H */
