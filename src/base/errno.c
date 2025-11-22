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

#include <libfam/errno.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

i32 __err_value = 0;
i32 *__error(void) { return &__err_value; }
i32 *__err_location(void) { return &__err_value; }

void perror(const char *s) {
	const u8 *err_msg;
	i32 __attribute__((unused)) _v;
	if (s) {
		u64 len = strlen(s);
		if (pwrite(STDERR_FD, s, len, 0) < len) return;
		if (pwrite(STDERR_FD, ": ", 2, 0) < 2) return;
	}
	err_msg = strerror(errno);
	_v = pwrite(STDERR_FD, err_msg, strlen(err_msg), 0);
	_v = pwrite(STDERR_FD, "\n", 1, 0);
}

char *strerror(i32 err_code) {
	switch (err_code) {
		case SUCCESS:
			return "Success";
		case EPERM:
			return "Operation not permitted";
		case ENOENT:
			return "No such file or directory";
		case EINTR:
			return "Interrupted system call";
		case EIO:
			return "Input/output error";
		case EBADF:
			return "Bad file descriptor";
		case ECHILD:
			return "No child processes";
		case EAGAIN:
			return "Resource temporarily unavailable";
		case ENOMEM:
			return "Out of memory";
		case EFAULT:
			return "Bad address";
		case EBUSY:
			return "Resource busy or locked";
		case EINVAL:
			return "Invalid argument";
		case ENOSPC:
			return "No space left on device";
		case EPIPE:
			return "Broken pipe";
		case EPROTO:
			return "Protocol error";
		case EOVERFLOW:
			return "Value too large for defined data type";
		case EDUPLICATE:
			return "Duplicate entries";
		case ETODO:
			return "todo/work in progress";
		default:
			return "Unknown error";
	}
}

