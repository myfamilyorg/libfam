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

#ifndef _TEST_BASE_H
#define _TEST_BASE_H

#include <libfam/syscall.h>
#include <libfam/types.h>
#include <libfam/utils.h>

static i64 __attribute__((unused)) write_num(i32 fd, u64 num) {
	u8 buf[21];
	u8 *p;
	u64 len;
	i64 written;
INIT:
	if (fd < 0) ERROR(EBADF);
	p = buf + sizeof(buf) - 1;
	*p = '\0';

	if (num == 0)
		*--p = '0';
	else
		while (num > 0) {
			*--p = '0' + (num % 10);
			num /= 10;
		}

	len = buf + sizeof(buf) - 1 - p;
	written = write(fd, p, len);
	if (written < 0) ERROR();
	if ((u64)written != len) ERROR(EIO);
CLEANUP:
	RETURN;
}

#endif /* _TEST_BASE_H */
