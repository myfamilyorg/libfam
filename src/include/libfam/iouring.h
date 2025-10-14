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

#include <libfam/types.h>

typedef struct IoUring IoUring;

i32 iouring_init(IoUring **iou, u32 queue_depth);
i32 iouring_init_read(IoUring *iou, i32 fd, const void *buf, u64 len,
		      u64 foffset, u64 id);
i32 iouring_init_write(IoUring *iou, i32 fd, void *buf, u64 len, u64 foffset,
		       u64 id);
i32 iouring_submit(IoUring *iou, u32 count);
bool iouring_pending(IoUring *iou, u64 id);
i32 iouring_wait(IoUring *iou, u64 *id);
i32 iouring_spin(IoUring *iou, u64 *id);
void iouring_destroy(IoUring *iou);

#endif /* _IO_URING_H */
