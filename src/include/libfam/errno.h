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

#ifndef _ERRNO_H
#define _ERRNO_H

#include <libfam/types.h>

/*
 * Function: __error
 * Returns a pointer to the thread-local errno location.
 * inputs: None.
 * return value: i32 * - pointer to current thread's errno.
 * errors: None.
 * notes:
 *         Used internally to implement the errno macro.
 *         Never call directly; use errno instead.
 *         Value is thread-local and initialized to 0.
 */
i32 *__error(void);
#define errno (*__error())

/*
 * Function: strerror
 * Converts an errno code to a human-readable string.
 * inputs:
 *         i32 err_code - error code to convert (e.g., EINVAL).
 * return value: char * - null-terminated string describing the error.
 * errors: None.
 * notes:
 *         Returned pointer is static and must not be freed.
 *         Unknown codes return "Unknown error".
 *         Thread-safe.
 */
char *strerror(i32 err_code);

/*
 * Function: perror
 * Prints a message to stderr describing the current errno.
 * inputs:
 *         const char *s - optional prefix string (may be NULL).
 * return value: None.
 * errors: None.
 * notes:
 *         Format: "<s>: <error message>\n"
 *         If s is NULL or empty, prints only the error message.
 *         Uses current value of errno.
 *         Does not modify errno.
 */
void perror(const char *s);

/*
 * Constant: SUCCESS
 * Success error code (0).
 */
#define SUCCESS 0

/*
 * Constant: EPERM
 * Operation not permitted (1).
 */
#define EPERM 1

/*
 * Constant: ENOENT
 * No such file or directory (2).
 */
#define ENOENT 2

/*
 * Constant: EINTR
 * Interrupted system call (4).
 */
#define EINTR 4

/*
 * Constant: EIO
 * I/O error (5).
 */
#define EIO 5

/*
 * Constant: EBADF
 * Bad file descriptor (9).
 */
#define EBADF 9

/*
 * Constant: ECHILD
 * No child processes (10).
 */
#define ECHILD 10

/*
 * Constant: EAGAIN
 * Resource temporarily unavailable (11).
 */
#define EAGAIN 11

/*
 * Constant: ENOMEM
 * Out of memory (12).
 */
#define ENOMEM 12

/*
 * Constant: EFAULT
 * Bad address (14).
 */
#define EFAULT 14

/*
 * Constant: EBUSY
 * Device or resource busy (16).
 */
#define EBUSY 16

/*
 * Constant: EEXIST
 * File exists (17).
 */
#define EEXIST 17

/*
 * Constant: ENOTDIR
 * Not a directory (20).
 */
#define ENOTDIR 20

/*
 * Constant: EISDIR
 * Is a directory (21).
 */
#define EISDIR 21

/*
 * Constant: EINVAL
 * Invalid argument (22).
 */
#define EINVAL 22

/*
 * Constant: ENFILE
 * File table overflow (23).
 */
#define ENFILE 23

/*
 * Constant: EMFILE
 * Too many open files (24).
 */
#define EMFILE 24

/*
 * Constant: ENOSPC
 * No space left on device (28).
 */
#define ENOSPC 28

/*
 * Constant: ESPIPE
 * Illegal seek (29).
 */
#define ESPIPE 29

/*
 * Constant: EPIPE
 * Broken pipe (32).
 */
#define EPIPE 32

/*
 * Constant: ERANGE
 * Result too large (34).
 */
#define ERANGE 34

/*
 * Constant: EDEADLK
 * Resource deadlock would occur (35).
 */
#define EDEADLK 35

/*
 * Constant: ENOSYS
 * Function not implemented (38).
 */
#define ENOSYS 38

/*
 * Constant: ENOTEMPTY
 * Directory not empty (39).
 */
#define ENOTEMPTY 39

/*
 * Constant: EPROTO
 * Protocol error (71).
 */
#define EPROTO 71

/*
 * Constant: EOVERFLOW
 * Value too large for defined data type (75).
 */
#define EOVERFLOW 75

/*
 * Constant: ENOTSUP
 * Operation not supported (95).
 */
#define ENOTSUP 95

/*
 * Constant: EAFNOSUPPORT
 * Address family not supported by protocol (97).
 */
#define EAFNOSUPPORT 97

/*
 * Constant: EADDRINUSE
 * Address already in use (98).
 */
#define EADDRINUSE 98

/*
 * Constant: ENETUNREACH
 * Network is unreachable (101).
 */
#define ENETUNREACH 101

/*
 * Constant: ECONNREFUSED
 * Connection refused (111).
 */
#define ECONNREFUSED 111

/*
 * Constant: ETIMEDOUT
 * Connection timed out (110).
 */
#define ETIMEDOUT 110

/*
 * Constant: EINPROGRESS
 * Operation now in progress (115).
 */
#define EINPROGRESS 115

/*
 * Constant: EBADFD
 * File descriptor in bad state (77).
 */
#define EBADFD 77

/*
 * Constant: EWOULDBLOCK
 * Operation would block (same as EAGAIN on Linux).
 */
#define EWOULDBLOCK EAGAIN

/*
 * Constant: EDUPLICATE
 * Duplicate entry (1001).
 * notes:
 *         Custom error code used by this project.
 */
#define EDUPLICATE 1001

/*
 * Constant: ETODO
 * Feature not implemented (1002).
 * notes:
 *         Custom error code used by this project.
 */
#define ETODO 1002

#endif /* _ERRNO_H */
