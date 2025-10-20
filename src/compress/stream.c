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

#include <libfam/compress.h>
#include <libfam/compress_stream.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/sysext.h>

STATIC i32 write_stream_header(IoUring *iou, i32 out_fd, struct stat *st) {
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

STATIC i32 read_stream_header(IoUring *iou, i32 in_fd, StreamHeader *header) {
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

PUBLIC i32 decompress_stream(i32 in_fd, i32 out_fd) {
	StreamHeader header;
	IoUring *iou = NULL;
INIT:
	if (iouring_init(&iou, 4) < 0) ERROR();
	if (read_stream_header(iou, in_fd, &header) < 0) ERROR();
	println("magic={X},v={},mt={},at={},perm={x}", header.magic,
		header.version, header.mtime, header.atime, header.permissions);

CLEANUP:
	iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 compress_stream(i32 in_fd, i32 out_fd) {
	IoUring *iou = NULL;
	u8 in_chunks[CR_BUFS][CHUNK_SIZE],
	    out_chunks[CW_BUFS][COMPRESSED_CHUNK_SIZE];
	u64 id, in_offset = 0, next_read = 0;
	i32 res, bytes_read[CR_BUFS];
	struct stat st;
	bool fin = false;
INIT:
	if (fstat(in_fd, &st) < 0) ERROR();
	if (iouring_init(&iou, CR_BUFS + CW_BUFS) < 0) ERROR();
	if (write_stream_header(iou, out_fd, &st) < 0) ERROR();

	if (iouring_init_read(iou, in_fd, in_chunks[next_read % CR_BUFS],
			      CHUNK_SIZE, in_offset, next_read) < 0)
		ERROR();
	if (iouring_submit(iou, 1) < 0) ERROR();
	u64 proc_sum = 0, wsum = 0, tsum = 0;

	while (!fin) {
		bytes_read[next_read % CR_BUFS] = 0;
		if (iouring_pending(iou, next_read)) {
			while (true) {
				res = iouring_spin(iou, &id);
				/*
				println("next_read={},res={}",
					next_read, res);
					*/
				if (res == 0) {
					fin = true;
					break;
				}
				bytes_read[next_read % CR_BUFS] += res;
				if (bytes_read[next_read % CR_BUFS] >=
				    CHUNK_SIZE)
					break;
				if (bytes_read[id % CR_BUFS] < CHUNK_SIZE) {
					/*
					println(
					    "(cont)sched read len={},offset={}",
					    CHUNK_SIZE - bytes_read[id %
					CR_BUFS], in_offset + bytes_read[id %
					CR_BUFS]);
					    */
					if (iouring_init_read(
						iou, in_fd,
						in_chunks[id % CR_BUFS],
						CHUNK_SIZE -
						    bytes_read[id % CR_BUFS],
						in_offset +
						    bytes_read[id % CR_BUFS],
						id) < 0)
						ERROR();
					if (iouring_submit(iou, 1) < 0) ERROR();
				}
			}
		}

		if (!fin) {
			/*
			println("(reg)sched read len={},offset={}", CHUNK_SIZE,
				in_offset + CHUNK_SIZE);
				*/

			res = iouring_init_read(
			    iou, in_fd, in_chunks[(next_read + 1) % CR_BUFS],
			    CHUNK_SIZE, in_offset + CHUNK_SIZE, next_read + 1);
			if (res < 0) ERROR();
			if (iouring_submit(iou, 1) < 0) ERROR();
		}

		proc_sum += bytes_read[next_read % CR_BUFS];
		/*println("proc {} bytes ({})", bytes_read[next_read % CR_BUFS],
			proc_sum);*/
		res = compress_block(
		    in_chunks[next_read % CR_BUFS],
		    bytes_read[next_read % CR_BUFS],
		    out_chunks[next_read % CR_BUFS] + sizeof(ChunkHeader),
		    COMPRESSED_CHUNK_SIZE);
		if (res < 0) ERROR();
		ChunkHeader *cheader = (void *)out_chunks[next_read % CR_BUFS];
		cheader->fin = fin;
		cheader->size = res;

		wsum += res + sizeof(ChunkHeader);
		i64 timer = micros();
		if (write(out_fd, out_chunks[next_read % CR_BUFS],
			  res + sizeof(ChunkHeader)) < 0)
			ERROR();
		timer = micros() - timer;
		tsum += timer;
		/*println("timer={},tsum={}", timer, tsum);*/
		next_read++;
		in_offset += CHUNK_SIZE;
	}
	/*println("wsum={}", wsum);*/

	(void)out_chunks;
	(void)proc_sum;
	(void)wsum;
	(void)tsum;
CLEANUP:
	iouring_destroy(iou);
	RETURN;
}
