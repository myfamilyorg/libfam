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

#include <libfam/debug.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>
#include <libfam/utils.h>

IoUring *__global_iou__ = NULL;

void yield(void) {
#if defined(__x86_64__)
	__asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
	__asm__ __volatile__("yield" ::: "memory");
#endif
}

PUBLIC i64 write(i32 fd, const void *buf, u64 len) {
	u64 id;
	i64 res;
#if TEST == 1
	if ((fd == 1 || fd == 2) && _debug_no_write) return len;
#endif /* TEST */

	if (!__global_iou__) iouring_init(&__global_iou__, 1);
	if (!__global_iou__) return -1;
	res = iouring_init_write(__global_iou__, fd, buf, len, 0, U64_MAX);
	if (res < 0) return -1;
	if (iouring_submit(__global_iou__, 1) < 0) return -1;
	return iouring_wait(__global_iou__, &id);
}

PUBLIC i64 micros(void) {
	struct timeval tv;
	if (gettimeofday(&tv, NULL) < 0) return -1;
	return (i64)tv.tv_sec * 1000000L + (i64)tv.tv_usec;
}

PUBLIC i32 fork(void) {
	i32 ret = clone(SIGCHLD, 0);
	return (i32)ret;
}

PUBLIC i32 two(void) {
	i32 ret = clone(CLONE_FILES | SIGCHLD, 0);
	return (i32)ret;
}

