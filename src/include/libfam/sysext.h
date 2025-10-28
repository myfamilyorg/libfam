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

#ifndef _SYSEXT_H
#define _SYSEXT_H

#include <libfam/types.h>

/*
 * Function: pipe
 * Creates a unidirectional pipe.
 * inputs:
 *         i32 fds[2] - array to store read (fds[0]) and write (fds[1]) file
 * descriptors. return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EMFILE         - too many file descriptors.
 *         ENFILE         - system limit reached.
 * notes:
 *         Equivalent to pipe2(fds, 0).
 *         Use close() on both fds when done.
 */
i32 pipe(i32 fds[2]);

/*
 * Function: await
 * Waits for a child process to change state.
 * inputs:
 *         i32 pid - process ID to wait for (0 = any, -1 = any in group).
 * return value: i32 - child PID on success, -1 on error.
 * errors:
 *         ECHILD         - no child processes.
 * notes:
 *         Blocks until a child exits or is signaled.
 */
i32 await(i32 pid);

/*
 * Function: reap
 * Reaps a terminated child process (non-blocking).
 * inputs:
 *         i32 pid - process ID to reap (0 = any, -1 = any in group).
 * return value: i32 - reaped PID on success, 0 if none, -1 on error.
 * errors:
 *         ECHILD         - no child processes.
 * notes:
 *         Does not block.
 *         Prevents zombie processes.
 */
i32 reap(i32 pid);

/*
 * Function: open
 * Opens a file in the current working directory.
 * inputs:
 *         const u8 *pathname - null-terminated file path.
 *         i32 flags          - O_RDONLY, O_WRONLY, O_CREAT, etc.
 *         u32 mode           - file mode if O_CREAT (ignored otherwise).
 * return value: i32 - file descriptor, or -1 on error.
 * errors:
 *         ENOENT         - file not found.
 *         EACCES         - permission denied.
 * notes:
 *         Equivalent to openat(AT_FDCWD, pathname, flags, mode).
 */
i32 open(const u8 *pathname, i32 flags, u32 mode);

/*
 * Function: getentropy
 * Fills a buffer with cryptographically secure random bytes.
 * inputs:
 *         void *buffer   - output buffer.
 *         u64 length     - number of bytes to fill (max 256).
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EIO            - entropy source failed.
 * notes:
 *         Uses getrandom(buffer, length, 0).
 *         Blocks if entropy pool is empty.
 */
i32 getentropy(void *buffer, u64 length);

/*
 * Function: yield
 * Yields the CPU to other threads.
 * inputs: None.
 * return value: i32 - 0 on success.
 * errors: None.
 * notes:
 *         Equivalent to sched_yield().
 *         Useful in spin loops.
 */
i32 yield(void);

/*
 * Function: map
 * Allocates anonymous memory.
 * inputs:
 *         u64 length - size of mapping in bytes.
 * return value: void * - pointer to mapped memory, or NULL on error.
 * errors:
 *         ENOMEM         - out of address space.
 * notes:
 *         Equivalent to mmap(NULL, length, PROT_READ|PROT_WRITE,
 * MAP_PRIVATE|MAP_ANONYMOUS, -1, 0). Use munmap() to free.
 */
void *map(u64 length);

/*
 * Function: fmap
 * Maps a file into memory.
 * inputs:
 *         i32 fd     - file descriptor.
 *         i64 size   - size to map (0 = entire file).
 *         i64 offset - file offset to start mapping.
 * return value: void * - pointer to mapped memory, or NULL on error.
 * errors:
 *         EINVAL         - invalid fd or offset.
 *         ENOMEM         - out of address space.
 * notes:
 *         size == 0 uses fsize(fd).
 *         Use munmap() to unmap.
 */
void *fmap(i32 fd, i64 size, i64 offset);

/*
 * Function: smap
 * Allocates shared anonymous memory.
 * inputs:
 *         u64 length - size of mapping in bytes.
 * return value: void * - pointer to mapped memory, or NULL on error.
 * errors:
 *         ENOMEM         - out of address space.
 * notes:
 *         Equivalent to mmap(NULL, length, PROT_READ|PROT_WRITE,
 * MAP_SHARED|MAP_ANONYMOUS, -1, 0). Use munmap() to free.
 */
void *smap(u64 length);

/*
 * Function: exists
 * Checks if a path exists.
 * inputs:
 *         const u8 *path - null-terminated file path.
 * return value: i32 - 1 if exists, 0 if not, -1 on error.
 * errors:
 *         EACCES         - permission denied.
 * notes:
 *         Uses fstatat(AT_FDCWD, path, ..., AT_SYMLINK_NOFOLLOW).
 */
i32 exists(const u8 *path);

/*
 * Function: file
 * Opens a file in read/write mode with the open system call.
 * inputs:
 *         const u8 *path - null-terminated file path.
 * return value: i32 - The file descriptor on success, -1 on error.
 * errors:
 *         ENOENT         - file not found.
 *         EACCES         - permission denied.
 * notes:
 *         Uses fstatat() and checks S_ISREG.
 */
i32 file(const u8 *path);

/*
 * Function: fsize
 * Returns the size of an open file.
 * inputs:
 *         i32 fd - file descriptor.
 * return value: i64 - file size in bytes, or -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 * notes:
 *         Uses lseek() and returns st_size.
 */
i64 fsize(i32 fd);

/*
 * Function: fresize
 * Resizes an open file.
 * inputs:
 *         i32 fd     - file descriptor.
 *         i64 length - new file size.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EINVAL         - invalid length.
 * notes:
 *         Equivalent to ftruncate(fd, length).
 */
i32 fresize(i32 fd, i64 length);

/*
 * Function: flush
 * Flushes file buffers to disk.
 * inputs:
 *         i32 fd - file descriptor.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 * notes:
 *         Equivalent to fdatasync(fd).
 */
i32 flush(i32 fd);

/*
 * Function: micros
 * Returns current time in microseconds since epoch.
 * inputs: None.
 * return value: i64 - microseconds.
 * errors: None.
 * notes:
 *         Uses gettimeofday().
 *         Monotonic if clock is.
 */
i64 micros(void);

/*
 * Function: msleep
 * Sleeps for the given number of milliseconds.
 * inputs:
 *         u64 millis - milliseconds to sleep.
 * return value: i32 - 0 on success, -1 if interrupted.
 * errors:
 *         EINTR          - interrupted by signal.
 * notes:
 *         Uses nanosleep().
 */
i32 msleep(u64 millis);

/*
 * Function: Calls clone3 with shared file descriptors. Two processes will be
 * created at this point just like fork but with shared file descriptor tables.
 * Returns .
 * inputs: None.
 * return value: i32 - 0 for the child process and the pid for the parent.
 * errors:
 *         EAGAIN         - resource limit.
 *         ENOMEM         - out of memory.
 * notes:
 *        Uses clone3() with shared file descriptor table.
 */
i32 two(void);

/*
 * Function: fork
 * Creates a child process.
 * inputs: None.
 * return value: i32 - 0 in child, PID in parent, -1 on error.
 * errors:
 *         EAGAIN         - resource limit.
 *         ENOMEM         - out of memory.
 * notes:
 *         Uses clone3() with default flags.
 */
i32 fork(void);

/*
 * Function: abort
 * Terminates the program abnormally.
 * inputs: None.
 * return value: None (does not return).
 * notes:
 *         Exits from process.
 *         Use for assertion failures.
 */
void abort(void);

/*
 * Function: restorer
 * Signal restorer function.
 * inputs: None.
 * return value: None.
 * notes:
 *         Required for rt_sigaction.
 *         Do not call directly.
 */
void restorer(void);

/*
 * Function: unlink
 * Deletes a file.
 * inputs:
 *         const char *path - null-terminated file path.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         ENOENT         - file not found.
 *         EACCES         - permission denied.
 * notes:
 *         Equivalent to unlinkat(AT_FDCWD, path, 0).
 */
i32 unlink(const char *path);

#endif /* _SYSEXT_H */
