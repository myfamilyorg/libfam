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
#include <libfam/compress_impl.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/linux_time.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

PUBLIC i32 decompress_stream(i32 in_fd, i32 out_fd) {
	CompressHeader header = {0};
	u64 in_offset = sizeof(CompressHeader);
	u64 out_offset = 0;
	u8 in_chunk[MAX_COMPRESS_BOUND_LEN] = {0},
	   out_chunk[4][MAX_COMPRESS_LEN + MAX_AVX_OVERWRITE] = {0};
	u64 in_chunk_size = 0, out_chunk_size = 0, id;
	IoUring *iou = NULL;
	u64 in_file_size = fsize(in_fd);
	u64 next_write = U32_MAX, next_read = 0;
	struct timevalfam ts[2] = {0};
INIT:
	if (iouring_init(&iou, 4) < 0) ERROR();

	in_chunk_size = compress_bound(MAX_COMPRESS_LEN);
	out_chunk_size = MAX_COMPRESS_LEN;

	if (iouring_init_read(iou, in_fd, &header, sizeof(CompressHeader), 0,
			      next_read) < 0)
		ERROR();
	next_read++;

	if (iouring_submit(iou, 1) < 0) ERROR();
	iouring_spin(iou, &id);

	while (out_offset < header.file_size) {
		in_chunk_size = min(compress_bound(MAX_COMPRESS_LEN),
				    in_file_size - in_offset);
		if (iouring_init_read(iou, in_fd, in_chunk, in_chunk_size,
				      in_offset, next_read) < 0)
			ERROR();

		if (iouring_submit(iou, 1) < 0) ERROR();
		while (true) {
			iouring_spin(iou, &id);
			if (id == next_read) break;
		}
		next_read++;

		u64 bytes_consumed;
		i32 result = decompress_block(in_chunk, in_chunk_size,
					      out_chunk[next_write % 4],
					      out_chunk_size, &bytes_consumed);
		if (result < 0) ERROR(EINVAL);

		if (iouring_init_write(iou, out_fd, out_chunk[next_write % 4],
				       result, out_offset, next_write) < 0)
			ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();

		if (out_fd == STDOUT_FD) {
			u64 written = 0;
			while (written < result) {
				i32 res = iouring_spin(iou, &id);
				if (res < 0) ERROR();
				written += res;
				if (written < result) {
					if (iouring_init_write(
						iou, out_fd,
						out_chunk[next_write % 4] +
						    written,
						result - written, out_offset,
						next_write) < 0)
						ERROR();
					if (iouring_submit(iou, 1) < 0) ERROR();
				}
			}
		} else if (next_write != U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					iouring_spin(iou, &id);
					if (id == next_write + 1) break;
				}
			}
		}

		in_offset += bytes_consumed;
		out_offset += result;
		next_write--;
	}

	while (iouring_pending_all(iou)) iouring_spin(iou, &id);
	if (out_fd != STDOUT_FD) {
		if (fresize(out_fd, out_offset) < 0) ERROR();
		if (fchmod(out_fd, header.permissions & 07777) < 0) ERROR();
		ts[0].tv_sec = header.atime;
		ts[1].tv_sec = header.mtime;
		if (utimesat(out_fd, NULL, ts, 0) < 0) ERROR();
	}
CLEANUP:
	if (iou) iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 compress_stream(i32 in_fd, i32 out_fd) {
	CompressHeader header;
	u64 in_offset = 0;
	u64 out_offset = sizeof(CompressHeader);
	u8 in_chunk[2][MAX_COMPRESS_LEN], out_chunk[2][MAX_COMPRESS_BOUND_LEN];
	u64 in_chunk_size = MAX_COMPRESS_LEN,
	    out_chunk_size = compress_bound(MAX_COMPRESS_LEN);
	IoUring *iou = NULL;
	u64 next_read = 0, next_write = U64_MAX, id;
	struct stat st;
INIT:
	if (fstat(in_fd, &st) < 0) ERROR();
	if (!S_ISREG(st.st_mode)) ERROR(EINVAL);

	header.file_size = fsize(in_fd);
	header.version = 0;
	header.permissions = st.st_mode & 07777;
	header.mtime = st.st_mtime;
	header.atime = st.st_atime;

	if (iouring_init(&iou, 4) < 0) ERROR();

	if (header.file_size == 0) ERROR(EINVAL);

	if (iouring_init_write(iou, out_fd, (u8 *)&header,
			       sizeof(CompressHeader), 0, 0) < 0)
		ERROR();
	if (iouring_submit(iou, 1) < 0) ERROR();
	i32 res = iouring_spin(iou, &id);
	if (res < 0) ERROR();
	if (res != sizeof(CompressHeader)) ERROR(EIO);

	in_chunk_size = min(header.file_size, MAX_COMPRESS_LEN);
	if (iouring_init_read(iou, in_fd, in_chunk[0], in_chunk_size, in_offset,
			      next_read) < 0)
		ERROR();
	iouring_submit(iou, 1);

	while (in_offset < header.file_size) {
		if (iouring_pending(iou, next_read)) {
			while (true) {
				iouring_spin(iou, &id);
				if (id == next_read) break;
			}
		}
		next_read++;

		if (in_offset + MAX_COMPRESS_LEN <= header.file_size) {
			in_chunk_size = min(
			    header.file_size - (in_offset + MAX_COMPRESS_LEN),
			    MAX_COMPRESS_LEN);
			if (iouring_init_read(
				iou, in_fd, in_chunk[next_read % 2],
				in_chunk_size, in_offset + MAX_COMPRESS_LEN,
				next_read) < 0)
				ERROR();
			iouring_submit(iou, 1);
		}

		in_chunk_size =
		    min(header.file_size - in_offset, MAX_COMPRESS_LEN);

		i32 result =
		    compress_block(in_chunk[(next_read - 1) % 2], in_chunk_size,
				   out_chunk[next_write % 2], out_chunk_size);
		if (result < 0) ERROR(EINVAL);

		if (iouring_init_write(iou, out_fd, out_chunk[next_write % 2],
				       result, out_offset, next_write) < 0)
			ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();

		if (out_fd == STDOUT_FD) {
			u64 written = 0;
			while (written < result) {
				i32 res = iouring_spin(iou, &id);
				if (res < 0) ERROR();
				if (id == next_write) {
					written += res;
					if (written < result) {
						if (iouring_init_write(
							iou, out_fd,
							out_chunk[next_write %
								  2] +
							    written,
							result - written,
							out_offset,
							next_write) < 0)
							ERROR();
						if (iouring_submit(iou, 1) < 0)
							ERROR();
					}
				}
			}
		} else if (next_write != U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					iouring_spin(iou, &id);
					if (id == next_write + 1) break;
				}
			}
		}

		next_write--;
		in_offset += in_chunk_size;
		out_offset += result;
	}
	while (iouring_pending_all(iou)) iouring_spin(iou, &id);
	if (out_fd != STDOUT_FD) {
		if (fresize(out_fd, out_offset) < 0) ERROR();
		if (fchmod(out_fd, header.permissions & 07777) < 0) ERROR();
	}
CLEANUP:
	if (iou) iouring_destroy(iou);
	RETURN;
}

