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

struct timeval;
struct clone_args;
struct rt_sigaction;
struct io_uring_params;
struct timezone;

i32 getpid(void);
i32 waitid(i32 idtype, i32 id, void *infop, i32 options);
i32 gettimeofday(struct timeval *tv, void *tz);
i32 settimeofday(const struct timeval *tv, const struct timezone *tz);
i32 kill(i32 pid, i32 signal);
void *mmap(void *addr, u64 length, i32 prot, i32 flags, i32 fd, i64 offset);
i32 munmap(void *addr, u64 len);
i32 clone3(struct clone_args *args, u64 size);
i32 rt_sigaction(i32 signum, const struct rt_sigaction *act,
		 struct rt_sigaction *oldact, u64 sigsetsize);
void _exit(i32 status);
i32 io_uring_setup(u32 entries, struct io_uring_params *params);
i32 io_uring_enter2(u32 fd, u32 to_submit, u32 min_complete, u32 flags,
		    void *arg, u64 sz);
i32 io_uring_register(u32 fd, u32 opcode, void *arg, u32 nr_args);

#endif /* _SYSCALL_H */
