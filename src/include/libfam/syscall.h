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

#ifndef _SYSCALL_H
#define _SYSCALL_H

#include <libfam/types.h>

/*
 * Type: timevalfam
 * Time structure with microsecond precision.
 * notes:
 *         Equivalent to struct timeval but uses u64 for seconds.
 *         Used to avoid dependency on <sys/time.h>.
 */
struct timevalfam;

/*
 * Type: clone_args
 * Arguments for clone3() system call.
 * notes:
 *         Matches kernel's struct clone_args.
 *         Used for advanced process creation.
 */
struct clone_args;

/*
 * Type: sockaddr
 * Generic socket address structure.
 * notes:
 *         Base type for all socket address families.
 */
struct sockaddr;

/*
 * Type: timespecfam
 * Time structure with nanosecond precision.
 * notes:
 *         Equivalent to struct timespec but uses u64 for seconds.
 */
struct timespecfam;

/*
 * Type: epoll_event
 * Event structure for epoll.
 * notes:
 *         Contains events mask and user data.
 */
struct epoll_event;

/*
 * Type: sigset_t
 * Signal set type.
 * notes:
 *         Used for signal masking in epoll_pwait, etc.
 */
struct sigset_t;

/*
 * Type: rt_sigaction
 * Real-time signal action structure.
 * notes:
 *         Used by rt_sigaction syscall.
 */
struct rt_sigaction;

/*
 * Type: stat
 * File status structure.
 * notes:
 *         Returned by fstat, fstatat.
 */
struct stat;

/*
 * Type: io_uring_params
 * Parameters for io_uring_setup.
 * notes:
 *         Used to configure io_uring instance.
 */
struct io_uring_params;

/*
 * Function: pipe2
 * Creates a pipe with optional flags.
 * inputs:
 *         i32 fds[2] - array to store read/write file descriptors.
 *         i32 flags  - O_CLOEXEC, O_NONBLOCK, etc.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EMFILE         - too many file descriptors.
 *         ENFILE         - system limit reached.
 *         EINVAL         - invalid flags.
 */
i32 pipe2(i32 fds[2], i32 flags);

/*
 * Function: getpid
 * Returns the current process ID.
 * inputs: None.
 * return value: i32 - process ID.
 * errors: None.
 */
i32 getpid(void);

/*
 * Function: write
 * Writes data to a file descriptor.
 * inputs:
 *         i32 fd         - file descriptor.
 *         const void *buf - data to write.
 *         u64 len        - number of bytes to write.
 * return value: i64 - bytes written, or -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EPIPE          - broken pipe.
 *         EAGAIN         - non-blocking and would block.
 */
i64 write(i32 fd, const void *buf, u64 len);

/*
 * Function: gettimeofday
 * Gets current time with microsecond precision.
 * inputs:
 *         struct timevalfam *tv - pointer to store time.
 *         void *tz              - ignored (must be NULL).
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EINVAL         - tv is null.
 */
i32 gettimeofday(struct timevalfam *tv, void *tz);

/*
 * Function: kill
 * Sends a signal to a process.
 * inputs:
 *         i32 pid    - process ID (or 0 for current, -1 for broadcast).
 *         i32 signal - signal number.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         ESRCH          - no such process.
 *         EPERM          - permission denied.
 */
i32 kill(i32 pid, i32 signal);

/*
 * Function: unlinkat
 * Deletes a file by name relative to a directory fd.
 * inputs:
 *         i32 dfd        - directory file descriptor (AT_FDCWD for cwd).
 *         const char *path - file path.
 *         i32 flags      - AT_REMOVEDIR to remove directory.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         ENOENT         - file not found.
 *         EPERM          - permission denied.
 */
i32 unlinkat(i32 dfd, const char *path, i32 flags);

/*
 * Function: read
 * Reads data from a file descriptor.
 * inputs:
 *         i32 fd     - file descriptor.
 *         void *buf  - buffer to store data.
 *         u64 count  - maximum bytes to read.
 * return value: i64 - bytes read, 0 on EOF, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EAGAIN         - non-blocking and no data.
 */
i64 read(i32 fd, void *buf, u64 count);

/*
 * Function: sched_yield
 * Yields the CPU to other threads.
 * inputs: None.
 * return value: i32 - 0 on success, -1 on error (rare).
 * errors: None.
 */
i32 sched_yield(void);

/*
 * Function: mmap
 * Maps files or devices into memory.
 * inputs:
 *         void *addr     - suggested address (NULL for any).
 *         u64 length     - length of mapping.
 *         i32 prot       - PROT_READ, PROT_WRITE, etc.
 *         i32 flags      - MAP_PRIVATE, MAP_SHARED, etc.
 *         i32 fd         - file descriptor (-1 for anonymous).
 *         i64 offset     - file offset.
 * return value: void * - mapped address, or MAP_FAILED on error.
 * errors:
 *         ENOMEM         - out of address space.
 *         EINVAL         - invalid parameters.
 */
void *mmap(void *addr, u64 length, i32 prot, i32 flags, i32 fd, i64 offset);

/*
 * Function: munmap
 * Unmaps memory.
 * inputs:
 *         void *addr - start of mapping.
 *         u64 len    - length of mapping.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EINVAL         - invalid address or length.
 */
i32 munmap(void *addr, u64 len);

/*
 * Function: close
 * Closes a file descriptor.
 * inputs:
 *         i32 fd - file descriptor.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 */
i32 close(i32 fd);

/*
 * Function: fcntl
 * File control operations.
 * inputs:
 *         i32 fd  - file descriptor.
 *         i32 op  - operation (F_GETFL, F_SETFL, etc.).
 *         ...     - operation-specific argument.
 * return value: i32 - depends on operation, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EINVAL         - invalid op.
 */
i32 fcntl(i32 fd, i32 op, ...);

/*
 * Function: clone3
 * Creates a child process with extended arguments.
 * inputs:
 *         struct clone_args *args - clone arguments.
 *         u64 size                - size of args structure.
 * return value: i32 - 0 in child, PID in parent, -1 on error.
 * errors:
 *         EINVAL         - invalid args.
 *         ENOMEM         - out of memory.
 */
i32 clone3(struct clone_args *args, u64 size);

/*
 * Function: fdatasync
 * Synchronizes file data (not metadata).
 * inputs:
 *         i32 fd - file descriptor.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 */
i32 fdatasync(i32 fd);

/*
 * Function: ftruncate
 * Truncates a file to a specified length.
 * inputs:
 *         i32 fd     - file descriptor.
 *         i64 length - new file size.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EINVAL         - invalid length.
 */
i32 ftruncate(i32 fd, i64 length);

/*
 * Function: getrandom
 * Reads from kernel entropy pool.
 * inputs:
 *         void *buffer   - output buffer.
 *         u64 length     - number of bytes to read.
 *         u32 flags      - GRND_RANDOM, GRND_NONBLOCK.
 * return value: i32 - bytes read, or -1 on error.
 * errors:
 *         EAGAIN         - non-blocking and no entropy.
 */
i32 getrandom(void *buffer, u64 length, u32 flags);

/*
 * Function: connect
 * Connects a socket to a remote address.
 * inputs:
 *         i32 sockfd             - socket file descriptor.
 *         const struct sockaddr *addr - remote address.
 *         u32 addrlen            - size of addr.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         ECONNREFUSED   - connection refused.
 *         ETIMEDOUT      - timeout.
 */
i32 connect(i32 sockfd, const struct sockaddr *addr, u32 addrlen);

/*
 * Function: setsockopt
 * Sets socket option.
 * inputs:
 *         i32 sockfd     - socket fd.
 *         i32 level      - protocol level.
 *         i32 optname    - option name.
 *         const void *optval - option value.
 *         u32 optlen     - size of optval.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 setsockopt(i32 sockfd, i32 level, i32 optname, const void *optval,
	       u32 optlen);

/*
 * Function: getsockopt
 * Gets socket option.
 * inputs:
 *         i32 sockfd     - socket fd.
 *         i32 level      - protocol level.
 *         i32 optname    - option name.
 *         void *optval   - buffer for value.
 *         u32 *optlen    - in: size of buffer, out: size of value.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 getsockopt(i32 sockfd, i32 level, i32 optname, void *optval, u32 *optlen);

/*
 * Function: bind
 * Binds a socket to a local address.
 * inputs:
 *         i32 sockfd             - socket fd.
 *         const struct sockaddr *addr - local address.
 *         u32 addrlen            - size of addr.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EADDRINUSE     - address in use.
 */
i32 bind(i32 sockfd, const struct sockaddr *addr, u32 addrlen);

/*
 * Function: listen
 * Enables connections on a socket.
 * inputs:
 *         i32 sockfd     - socket fd.
 *         i32 backlog    - maximum pending connections.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 listen(i32 sockfd, i32 backlog);

/*
 * Function: getsockname
 * Gets local address of a socket.
 * inputs:
 *         i32 sockfd             - socket fd.
 *         struct sockaddr *addr  - buffer for address.
 *         u32 *addrlen           - in: buffer size, out: address size.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 getsockname(i32 sockfd, struct sockaddr *addr, u32 *addrlen);

/*
 * Function: accept
 * Accepts an incoming connection.
 * inputs:
 *         i32 sockfd             - listening socket.
 *         struct sockaddr *addr  - buffer for peer address.
 *         u32 *addrlen           - in: buffer size, out: address size.
 * return value: i32 - new socket fd, or -1 on error.
 * errors:
 *         EAGAIN         - no pending connections.
 */
i32 accept(i32 sockfd, struct sockaddr *addr, u32 *addrlen);

/*
 * Function: shutdown
 * Shuts down socket send/receive.
 * inputs:
 *         i32 sockfd     - socket fd.
 *         i32 how        - SHUT_RD, SHUT_WR, SHUT_RDWR.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 shutdown(i32 sockfd, i32 how);

/*
 * Function: socket
 * Creates a socket.
 * inputs:
 *         i32 domain     - AF_INET, AF_UNIX, etc.
 *         i32 type       - SOCK_STREAM, SOCK_DGRAM.
 *         i32 protocol   - usually 0.
 * return value: i32 - socket fd, or -1 on error.
 * errors:
 *         EAFNOSUPPORT   - domain not supported.
 */
i32 socket(i32 domain, i32 type, i32 protocol);

/*
 * Function: nanosleep
 * Sleeps for specified time.
 * inputs:
 *         const struct timespecfam *req - requested sleep time.
 *         struct timespecfam *rem       - remaining time if interrupted.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EINTR          - interrupted by signal.
 */
i32 nanosleep(const struct timespecfam *req, struct timespecfam *rem);

/*
 * Function: epoll_create1
 * Creates an epoll instance.
 * inputs:
 *         i32 flags      - EPOLL_CLOEXEC, etc.
 * return value: i32 - epoll fd, or -1 on error.
 * errors:
 *         ENOMEM         - out of memory.
 */
i32 epoll_create1(i32 flags);

/*
 * Function: epoll_pwait
 * Waits for epoll events with signal mask.
 * inputs:
 *         i32 epfd               - epoll fd.
 *         struct epoll_event *events - array to store events.
 *         i32 maxevents          - size of events array.
 *         i32 timeout            - milliseconds (-1 = infinite).
 *         const struct sigset_t *sigmask - signal mask.
 *         u64 size               - size of sigmask.
 * return value: i32 - number of events, 0 on timeout, -1 on error.
 */
i32 epoll_pwait(i32 epfd, struct epoll_event *events, i32 maxevents,
		i32 timeout, const struct sigset_t *sigmask, u64 size);

/*
 * Function: epoll_ctl
 * Controls epoll file descriptors.
 * inputs:
 *         i32 epfd               - epoll fd.
 *         i32 op                 - EPOLL_CTL_ADD, DEL, MOD.
 *         i32 fd                 - target fd.
 *         struct epoll_event *event - event data.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 epoll_ctl(i32 epfd, i32 op, i32 fd, struct epoll_event *event);

/*
 * Function: openat
 * Opens a file relative to a directory fd.
 * inputs:
 *         i32 dfd        - directory fd (AT_FDCWD for cwd).
 *         const u8 *pathname - file path.
 *         i32 flags      - O_RDONLY, O_CREAT, etc.
 *         u32 mode       - file mode if O_CREAT.
 * return value: i32 - file descriptor, or -1 on error.
 * errors:
 *         ENOENT         - file not found.
 *         EACCES         - permission denied.
 */
i32 openat(i32 dfd, const u8 *pathname, i32 flags, u32 mode);

/*
 * Function: lseek
 * Repositions file offset.
 * inputs:
 *         i32 fd     - file descriptor.
 *         i64 offset - offset.
 *         i32 whence - SEEK_SET, SEEK_CUR, SEEK_END.
 * return value: i64 - new offset, or -1 on error.
 * errors:
 *         EBADF          - invalid fd.
 *         EINVAL         - invalid whence.
 */
i64 lseek(i32 fd, i64 offset, i32 whence);

/*
 * Function: rt_sigaction
 * Examines and changes signal action.
 * inputs:
 *         i32 signum             - signal number.
 *         const struct rt_sigaction *act - new action.
 *         struct rt_sigaction *oldact - old action.
 *         u64 sigsetsize         - size of sigset.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 rt_sigaction(i32 signum, const struct rt_sigaction *act,
		 struct rt_sigaction *oldact, u64 sigsetsize);

/*
 * Function: futex
 * Fast userspace mutex.
 * inputs:
 *         u32 *uaddr             - futex address.
 *         i32 futex_op           - operation.
 *         u32 val                - value.
 *         const struct timespecfam *timeout - timeout.
 *         u32 *uaddr2            - second address.
 *         u32 val3               - third value.
 * return value: i64 - depends on operation.
 */
i64 futex(u32 *uaddr, i32 futex_op, u32 val, const struct timespecfam *timeout,
	  u32 *uaddr2, u32 val3);

/*
 * Function: msync
 * Synchronizes mapped memory with file.
 * inputs:
 *         void *addr     - start of mapping.
 *         u64 length     - length.
 *         i32 flags      - MS_SYNC, MS_ASYNC.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 msync(void *addr, u64 length, i32 flags);

/*
 * Function: _famexit
 * Terminates the program.
 * inputs:
 *         i32 status - exit status.
 * return value: None (does not return).
 * notes:
 *         Calls exit_group() — terminates all threads.
 */
void _famexit(i32 status);

/*
 * Function: utimesat
 * Changes file access/modification times.
 * inputs:
 *         i32 dirfd              - directory fd.
 *         const u8 *path         - file path.
 *         const struct timevalfam *times - new times.
 *         i32 flags              - AT_SYMLINK_NOFOLLOW.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 utimesat(i32 dirfd, const u8 *path, const struct timevalfam *times,
	     i32 flags);

/*
 * Function: fstatat
 * Gets file status relative to directory fd.
 * inputs:
 *         i32 dirfd              - directory fd.
 *         const u8 *pathname     - file path.
 *         struct stat *buf       - output buffer.
 *         i32 flags              - AT_SYMLINK_NOFOLLOW.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 fstatat(i32 dirfd, const u8 *pathname, struct stat *buf, i32 flags);

/*
 * Function: fchmod
 * Changes file mode.
 * inputs:
 *         i32 fd     - file descriptor.
 *         u32 mode   - new mode.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 fchmod(i32 fd, u32 mode);

/*
 * Function: io_uring_setup
 * Creates an io_uring instance.
 * inputs:
 *         u32 entries            - queue depth.
 *         struct io_uring_params *params - setup parameters.
 * return value: i32 - io_uring fd, or -1 on error.
 */
i32 io_uring_setup(u32 entries, struct io_uring_params *params);

/*
 * Function: io_uring_enter2
 * Submits and/or waits for io_uring operations.
 * inputs:
 *         u32 fd                 - io_uring fd.
 *         u32 to_submit          - number of SQEs to submit.
 *         u32 min_complete       - minimum CQEs to wait for.
 *         u32 flags              - IORING_ENTER_* flags.
 *         void *arg              - sigset for signal delivery.
 *         u64 sz                 - size of sigset.
 * return value: i32 - number of CQEs, or -1 on error.
 */
i32 io_uring_enter2(u32 fd, u32 to_submit, u32 min_complete, u32 flags,
		    void *arg, u64 sz);

/*
 * Function: io_uring_register
 * Registers files/buffers with io_uring.
 * inputs:
 *         u32 fd                 - io_uring fd.
 *         u32 opcode             - IORING_REGISTER_*.
 *         void *arg              - argument.
 *         u32 nr_args            - number of arguments.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 io_uring_register(u32 fd, u32 opcode, void *arg, u32 nr_args);

/*
 * Function: fstat
 * Gets file status.
 * inputs:
 *         i32 fd                 - file descriptor.
 *         struct stat *buf       - output buffer.
 * return value: i32 - 0 on success, -1 on error.
 */
i32 fstat(i32 fd, struct stat *buf);

/*
 * Function: pread64
 * reads the bytes at specified offset
 * inputs:
 *         i32 fd                 - file descriptor.
 *         void *buf              - location to write data to.
 *         u64 count              - number of bytes to write.
 *         u64 offset             - offset within the file.
 * return value: i32 - 0 on success, -1 on error.
 */
i64 pread64(i32 fd, void *buf, u64 count, u64 offset);

#endif /* _SYSCALL_H */
