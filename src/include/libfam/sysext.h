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

void yield(void);
i64 write(i32 fd, const void *buf, u64 len);
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

#endif /* _SYSEXT_H */
