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
#include <libfam/compress_file.h>
#include <libfam/compress_impl.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/linux_time.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

STATIC i32 __attribute__((unused)) stream_write_header(i32 out_fd,
						       i16 permissions,
						       i64 mtime, i64 atime,
						       const u8 *filename) {
	u8 flags = 0;
	u8 buffer[1024];
	u16 offset = 0;
	u64 file_name_len = filename ? strlen(filename) : 0;
	u8 version = VERSION;
	u32 magic = MAGIC;
INIT:
	if (file_name_len > MAX_FILE_NAME) ERROR(EINVAL);
	if (permissions >= 0) flags |= STREAM_FLAG_HAS_PERMISSIONS;
	if (mtime >= 0) flags |= STREAM_FLAG_HAS_MTIME;
	if (atime >= 0) flags |= STREAM_FLAG_HAS_ATIME;
	if (filename) flags |= STREAM_FLAG_HAS_FILE_NAME;

	memcpy(buffer + offset, &magic, sizeof(u32));
	offset += sizeof(u32);
	memcpy(buffer + offset, &version, sizeof(u8));
	offset += sizeof(u8);
	memcpy(buffer + offset, &flags, sizeof(u8));
	offset += sizeof(u8);
	if (permissions >= 0) {
		memcpy(buffer + offset, &permissions, sizeof(u16));
		offset += sizeof(u16);
	}
	if (mtime >= 0) {
		memcpy(buffer + offset, &mtime, sizeof(u64));
		offset += sizeof(u64);
	}
	if (atime >= 0) {
		memcpy(buffer + offset, &atime, sizeof(u64));
		offset += sizeof(u64);
	}
	if (filename) {
		memcpy(buffer + offset, filename, file_name_len);
		buffer[offset + file_name_len] = 0;
		offset += file_name_len + 1;
	}
	u16 written = 0;
	while (written < offset) {
		i64 value = write(out_fd, buffer + written, offset - written);
		if (value < 0) ERROR();
		written += value;
	}

	OK(offset);
CLEANUP:
	RETURN;
}

STATIC i32 __attribute__((unused)) stream_read_header(
    i32 in_fd, ComressFileHeader *header) {
	u8 buffer[1024] = {0}, flags;
	u16 total = 0, offset = 0;
	u64 needed = sizeof(u32) + sizeof(u8) * 2;
INIT:
	while (total < needed) {
		i64 value = read(in_fd, buffer + total, needed - total);
		if (value < 0) ERROR();
		total += value;
	}
	if (((u32 *)buffer)[0] != MAGIC) ERROR(EPROTO);
	if (buffer[4] != VERSION) ERROR(EPROTO);
	flags = buffer[5];
	needed = 0;
	total = 0;
	if (flags & STREAM_FLAG_HAS_PERMISSIONS) needed += 2;
	if (flags & STREAM_FLAG_HAS_MTIME) needed += 8;
	if (flags & STREAM_FLAG_HAS_ATIME) needed += 8;
	if (flags & STREAM_FLAG_HAS_FILE_NAME) needed += MAX_FILE_NAME + 1;

	total = 0;
	while (total < needed) {
		i64 value = read(in_fd, buffer + total, needed - total);
		if (value < 0) ERROR();
		if (value == 0) ERROR(EPROTO);
		total += value;
		offset = 0;

		if (flags & STREAM_FLAG_HAS_PERMISSIONS &&
		    total - offset >= sizeof(u16)) {
			memcpy(&header->permissions, buffer + offset,
			       sizeof(u16));
			offset += sizeof(u16);
		} else if (flags & STREAM_FLAG_HAS_PERMISSIONS)
			continue;

		if (flags & STREAM_FLAG_HAS_MTIME &&
		    total - offset >= sizeof(u64)) {
			memcpy(&header->mtime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		} else if (flags & STREAM_FLAG_HAS_MTIME)
			continue;

		if (flags & STREAM_FLAG_HAS_ATIME &&
		    total - offset >= sizeof(u64)) {
			memcpy(&header->atime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		} else if (flags & STREAM_FLAG_HAS_ATIME)
			continue;

		if (flags & STREAM_FLAG_HAS_FILE_NAME && total - offset > 0) {
			u64 len = strlen((char *)(buffer + offset));
			if (len > MAX_FILE_NAME) ERROR(EPROTO);
			if (len < total - offset) {
				header->filename = alloc(len + 1);
				if (!header->filename) ERROR();
				strcpy((char *)header->filename,
				       (char *)(buffer + offset));
				offset += len + 1;
			} else
				continue;
		}

		break;
	}
	OK(offset + 6);
CLEANUP:
	RETURN;
}

PUBLIC i32 decompress_file(i32 in_fd, i32 out_fd) {
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

PUBLIC i32 compress_file(i32 in_fd, i32 out_fd) {
	CompressHeader header;
	u64 in_offset = 0;
	u64 out_offset = sizeof(CompressHeader);
	u8 in_chunk[2][MAX_COMPRESS_LEN] = {0},
	   out_chunk[2][MAX_COMPRESS_BOUND_LEN] = {0};
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

