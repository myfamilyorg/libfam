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

#include <libfam/atomic.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/memory.h>
#include <libfam/spin.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

struct IoUring {
	u32 queue_depth;
	struct io_uring_params params;
	i32 ring_fd;
	u8 *sq_ring;
	u8 *cq_ring;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	u64 sq_ring_size;
	u64 cq_ring_size;
	u64 sqes_size;
	u32 *sq_tail;
	u32 *sq_array;
	u32 *cq_head;
	u32 *cq_tail;
	u32 *sq_mask;
	u32 *cq_mask;
	SpinLock lock;
};

i32 iouring_init(IoUring **iou, u32 queue_depth) {
INIT:
	*iou = NULL;
	if (!(*iou = alloc(sizeof(IoUring)))) ERROR();
	(*iou)->sq_ring = NULL;
	(*iou)->cq_ring = NULL;
	(*iou)->sqes = NULL;
	(*iou)->ring_fd = io_uring_setup(queue_depth, &(*iou)->params);
	if ((*iou)->ring_fd < 0) ERROR();

	(*iou)->sq_ring_size = (*iou)->params.sq_off.array +
			       (*iou)->params.sq_entries * sizeof(u32);
	(*iou)->cq_ring_size =
	    (*iou)->params.cq_off.cqes +
	    (*iou)->params.cq_entries * sizeof(struct io_uring_cqe);
	(*iou)->sqes_size =
	    (*iou)->params.sq_entries * sizeof(struct io_uring_sqe);
	(*iou)->sq_ring =
	    mmap(NULL, (*iou)->sq_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		 (*iou)->ring_fd, IORING_OFF_SQ_RING);
	if ((*iou)->sq_ring == MAP_FAILED) ERROR();
	(*iou)->cq_ring =
	    mmap(NULL, (*iou)->cq_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		 (*iou)->ring_fd, IORING_OFF_CQ_RING);
	if ((*iou)->cq_ring == MAP_FAILED) ERROR();
	(*iou)->sqes = mmap(NULL, (*iou)->sqes_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, (*iou)->ring_fd, IORING_OFF_SQES);
	if ((*iou)->sqes == MAP_FAILED) ERROR();

	(*iou)->sq_tail = (u32 *)((*iou)->sq_ring + (*iou)->params.sq_off.tail);
	(*iou)->sq_array =
	    (u32 *)((*iou)->sq_ring + (*iou)->params.sq_off.array);
	(*iou)->cq_head = (u32 *)((*iou)->cq_ring + (*iou)->params.cq_off.head);
	(*iou)->cq_tail = (u32 *)((*iou)->cq_ring + (*iou)->params.cq_off.tail);
	(*iou)->sq_mask =
	    (u32 *)((*iou)->sq_ring + (*iou)->params.sq_off.ring_mask);

	(*iou)->cq_mask =
	    (u32 *)((*iou)->cq_ring + (*iou)->params.cq_off.ring_mask);
	(*iou)->cqes = (struct io_uring_cqe *)((*iou)->cq_ring +
					       (*iou)->params.cq_off.cqes);

	(*iou)->queue_depth = queue_depth;
	(*iou)->lock.value = 0;
CLEANUP:
	if (!IS_OK) {
		iouring_destroy(*iou);
		*iou = NULL;
	}
	RETURN;
}

struct io_uring_sqe *iouring_get_sqe(IoUring *iou) {
	u32 tail = __aload32(iou->sq_tail);
	u32 head = __aload32(iou->cq_head);
	if (tail - head >= iou->queue_depth) return NULL;
	u32 index = tail & *iou->sq_mask;
	iou->sq_array[index] = index;
	return &iou->sqes[index];
}

i32 iouring_init_read(IoUring *iou, i32 fd, const void *buf, u64 len,
		      u64 foffset, u64 id) {
	struct io_uring_sqe *sqe;

	spin_lock(&iou->lock);
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		spin_unlock(&iou->lock);
		errno = EBUSY;
		return -1;
	}
	sqe->opcode = IORING_OP_READ;
	sqe->flags = 0;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	spin_unlock(&iou->lock);
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_write(IoUring *iou, i32 fd, void *buf, u64 len, u64 foffset,
		       u64 id) {
	struct io_uring_sqe *sqe;
	spin_lock(&iou->lock);
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		spin_unlock(&iou->lock);
		errno = EBUSY;
		return -1;
	}
	sqe->opcode = IORING_OP_WRITE;
	sqe->flags = 0;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	spin_unlock(&iou->lock);
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_submit(IoUring *iou, u32 count) {
	return io_uring_enter2(iou->ring_fd, count, 0, 0, NULL, 0);
}

i32 iouring_wait(IoUring *iou, u64 *id) {
	u32 mask = *iou->cq_mask;
	u32 hval, tval;
	i32 res;
	u64 user_data;
	do {
		i32 r;
	begin_loop:
		r = io_uring_enter2(iou->ring_fd, 0, 1, IORING_ENTER_GETEVENTS,
				    NULL, 0);
		if (r < 0) return -1;
		hval = __aload32(iou->cq_head);
		tval = __aload32(iou->cq_tail);
		if (hval == tval) goto begin_loop;
		i32 cqe_idx = hval & mask;
		res = iou->cqes[cqe_idx].res;
		user_data = iou->cqes[cqe_idx].user_data;
	} while (!__cas32(iou->cq_head, &hval, hval + 1));

	*id = user_data;
	return res;
}

i32 iouring_spin(IoUring *iou, u64 *id) {
	u32 mask = *iou->cq_mask;
	i32 res;
	u32 hval;
	u64 user_data;
	do {
	begin_loop:
		hval = __aload32(iou->cq_head);
		u32 tval = __aload32(iou->cq_tail);

		if (hval == tval) {
			yield();
			goto begin_loop;
		}

		i32 cqe_idx = hval & mask;
		res = iou->cqes[cqe_idx].res;
		user_data = iou->cqes[cqe_idx].user_data;
	} while (!__cas32(iou->cq_head, &hval, hval + 1));
	*id = user_data;
	return res;
}

bool iouring_pending_all(IoUring *iou) {
	return __aload32(iou->cq_head) != __aload32(iou->sq_tail);
}

bool iouring_pending(IoUring *iou, u64 id) {
	u32 hval = __aload32(iou->cq_head);
	u32 tval = __aload32(iou->sq_tail);
	u32 mask = *iou->sq_mask;
	u32 index = hval;
	while (index < tval) {
		u32 sqe_idx = iou->sq_array[index & mask];
		if (iou->sqes[sqe_idx].user_data == id) return true;
		index++;
	}

	return false;
}

void iouring_destroy(IoUring *iou) {
	if (!iou) return;
	if (iou->sq_ring) munmap(iou->sq_ring, iou->sq_ring_size);
	if (iou->cq_ring) munmap(iou->cq_ring, iou->cq_ring_size);
	if (iou->sqes) munmap(iou->sqes, iou->sqes_size);
	iou->sq_ring = NULL;
	iou->cq_ring = NULL;
	iou->sqes = NULL;
	if (iou->ring_fd > 0) close(iou->ring_fd);
	release(iou);
}

