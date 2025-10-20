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
#include <libfam/compress.h>
#include <libfam/compress_stream.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/sysext.h>

STATIC i32 stream_write_header(IoUring *iou, i32 out_fd, struct stat *st) {
	u16 permissions = 0644;
	u64 id, mtime, atime;
	i32 res, wsum = 0;
INIT:
	if (S_ISLNK(st->st_mode) || S_ISDIR(st->st_mode) ||
	    S_ISBLK(st->st_mode)) {
		ERROR(EINVAL);
	}
	if (S_ISREG(st->st_mode)) {
		permissions = st->st_mode & 0777;
		mtime = st->st_mtime;
		atime = st->st_atime;
	} else {
		mtime = atime = micros() / 1000000;
	}

	StreamHeader header = {.magic = MAGIC,
			       .version = VERSION,
			       .permissions = permissions,
			       .mtime = mtime,
			       .atime = atime};
	while (wsum < sizeof(StreamHeader)) {
		res = iouring_init_write(iou, out_fd, (u8 *)&header,
					 sizeof(StreamHeader) - wsum, wsum, 0);
		if (res < 0) ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();
		res = iouring_spin(iou, &id);
		if (res < 0 || id != 0) ERROR();
		wsum += res;
	}
CLEANUP:
	RETURN;
}

STATIC i32 stream_read_header(IoUring *iou, i32 in_fd, StreamHeader *header) {
	u8 buf[sizeof(StreamHeader)];
	u64 id, wsum = 0;
	i32 res;
INIT:
	while (wsum < sizeof(StreamHeader)) {
		res = iouring_init_read(iou, in_fd, buf,
					sizeof(StreamHeader) - wsum, wsum, 0);
		if (res < 0) ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();
		res = iouring_spin(iou, &id);
		if (res < 0 || id != 0) ERROR();
		wsum += res;
	}

	*header = *(StreamHeader *)buf;
CLEANUP:
	RETURN;
}

STATIC i32 stream_sched_read(i32 in_fd, IoUring *iou, StreamState *state,
			     u32 tid, u64 id, u8 *in_chunk, u64 offset) {
INIT:
	if (iouring_init_read(iou, in_fd, in_chunk, CHUNK_SIZE, offset, id) < 0)
		ERROR();
	if (iouring_submit(iou, 1) < 0) ERROR();
CLEANUP:
	RETURN;
}

STATIC i32 stream_spin_read(i32 in_fd, IoUring *iou, StreamState *state,
			    u64 id) {
	i32 res;
INIT:
	if (iouring_pending(iou, id)) {
		while (true) {
			res = iouring_spin(iou, &id);
			if (res < 0) ERROR();
			break;
		}
	}
CLEANUP:
	RETURN;
}

STATIC i32 stream_compress_thread(i32 in_fd, IoUring *iou, StreamState *state) {
	u8 in_chunks[CR_BUFS][CHUNK_SIZE],
	    out_chunks[CW_BUFS][COMPRESSED_CHUNK_SIZE];
	u32 tid;
	u64 next_read;
	u8 buf_id = 0;
INIT:
	tid = __aadd32(&state->tid, 1);
	next_read = tid;
	println("compress {}", tid);

	if (stream_sched_read(in_fd, iou, state, tid, next_read,
			      in_chunks[buf_id], tid * CHUNK_SIZE) < 0)
		ERROR();

	while (true) {
		if (stream_spin_read(in_fd, iou, state, next_read) < 0) ERROR();
		msleep(5);
		println("next_read={},buf_id={}", next_read, buf_id % CR_BUFS);
		if (next_read > 20) break;
		buf_id++;
		next_read += CTHREADS;
	}

	(void)in_chunks;
	(void)out_chunks;
CLEANUP:
	RETURN;
}

STATIC void stream_init_state(StreamState *state) {
	state->tid = 0;
	state->io_lock = U32_MAX;
}

PUBLIC i32 decompress_stream(i32 in_fd, i32 out_fd) {
	StreamHeader header;
	IoUring *iou = NULL;
INIT:
	if (iouring_init(&iou, 4) < 0) ERROR();
	if (stream_read_header(iou, in_fd, &header) < 0) ERROR();
	println("magic={X},v={},mt={},at={},perm={x}", header.magic,
		header.version, header.mtime, header.atime, header.permissions);

CLEANUP:
	iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 compress_stream(i32 in_fd, i32 out_fd) {
	IoUring *iou = NULL;
	i32 pids[CTHREADS - 1];
	struct stat st;
	StreamState *state = NULL;
INIT:
	if (fstat(in_fd, &st) < 0) ERROR();
	if (iouring_init(&iou, CTHREADS * (CR_BUFS + CW_BUFS)) < 0) ERROR();
	if (stream_write_header(iou, out_fd, &st) < 0) ERROR();
	if (!(state = smap(sizeof(StreamState)))) ERROR();
	stream_init_state(state);

	for (u8 i = 0; i < CTHREADS - 1; i++)
		if (!(pids[i] = two()))
			stream_compress_thread(in_fd, iou, state), _exit(0);
	stream_compress_thread(in_fd, iou, state);

	for (u8 i = 0; i < CTHREADS - 1; i++) await(pids[i]);
	println("complete");

CLEANUP:
	if (state) munmap(state, sizeof(StreamState));
	iouring_destroy(iou);
	RETURN;
}
