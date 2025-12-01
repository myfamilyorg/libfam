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
#include <libfam/compress_file.h>
#include <libfam/compress_impl.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

#define MAX_PROCS 32

STATIC i32 compress_write_header(i32 out_fd, i16 permissions, i64 mtime,
				 i64 atime, const u8 *filename) {
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

STATIC i32 compress_read_header(i32 in_fd, CompressFileHeader *header) {
	u8 buffer[1024] = {0}, flags;
	u16 total = 0, offset = 0;
	u64 needed = sizeof(u32) + sizeof(u8) * 2;
INIT:
	while (total < needed) {
		i64 value = read(in_fd, buffer + total, needed - total);
		if (value < 0) ERROR();
		total += value;
		if (value == 0) ERROR(EPROTO);
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
		u8 flag;
		i64 value = read(in_fd, buffer + total, needed - total);
		if (value < 0) ERROR();
		if (value == 0) ERROR(EPROTO);
		total += value;
		offset = 0;

		flag = flags & STREAM_FLAG_HAS_PERMISSIONS;
		if (flag && !(total - offset >= sizeof(u16))) continue;
		if (flag && total - offset >= sizeof(u16)) {
			memcpy(&header->permissions, buffer + offset,
			       sizeof(u16));
			offset += sizeof(u16);
		}

		flag = flags & STREAM_FLAG_HAS_MTIME;
		if (flag && !(total - offset >= sizeof(u64))) continue;
		if (flag && total - offset >= sizeof(u64)) {
			memcpy(&header->mtime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		}

		flag = flags & STREAM_FLAG_HAS_ATIME;
		if (flag && !(total - offset >= sizeof(u64))) continue;
		if (flag && total - offset >= sizeof(u64)) {
			memcpy(&header->atime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		}

		if (flags & STREAM_FLAG_HAS_FILE_NAME && total - offset > 0) {
			u64 len = strlen((char *)(buffer + offset));
			if (len > MAX_FILE_NAME) ERROR(EPROTO);
			if (!(len < total - offset)) continue;
			if (len < total - offset) {
				header->filename = alloc(len + 1);
				if (!header->filename) ERROR();
				strcpy((char *)header->filename,
				       (char *)(buffer + offset));
				offset += len + 1;
			}
		}

		break;
	}
	OK(offset + 6);
CLEANUP:
	RETURN;
}

STATIC i32 compress_file_sched_read(IoUring *iou, i32 fd, u64 offset, u32 len,
				    void *buf, u64 id) {
INIT:
	if (iouring_init_pread(iou, fd, buf, len, offset, id) < 0) ERROR();
	if (iouring_submit(iou, 1) < 1) ERROR(EIO);
CLEANUP:
	RETURN;
}

STATIC i32 compress_file_complete(IoUring *iou, u64 id) {
	i32 res = 0;
	u64 actual_id;
	if (iouring_pending(iou, id)) {
		while (true) {
			res = iouring_spin(iou, &actual_id);
			if (id == actual_id) break;
		}
	}
	return res;
}

STATIC i32 compress_file_sched_write(IoUring *iou, i32 fd, u64 offset, u32 len,
				     void *buf, u64 id) {
INIT:
	if (iouring_init_pwrite(iou, fd, buf, len, offset, id) < 0) ERROR();
	if (iouring_submit(iou, 1) < 1) ERROR(EIO);
CLEANUP:
	RETURN;
}

STATIC i32 decompress_file_sync(i32 in_fd, i32 out_fd,
				u8 rbuf[2][MAX_COMPRESSED_SIZE],
				u8 wbuf[2][CHUNK_SIZE + 1024]) {
	ChunkHeader cheader;
	u64 bytes_consumed;
INIT:
	while (true) {
		i32 res = read(in_fd, &cheader, sizeof(ChunkHeader));
		if (res < 0) ERROR();
		if (res == 0) break;
		if (res < sizeof(ChunkHeader)) ERROR(EPROTO);
		if (cheader.size > MAX_COMPRESSED_SIZE) ERROR(EPROTO);
		i32 total_read = 0;
		while (total_read < cheader.size) {
			res = read(in_fd, rbuf[0] + total_read,
				   cheader.size - total_read);
			if (res < 0) ERROR();
			if (res == 0) ERROR(EPROTO);
			total_read += res;
		}

		res = decompress_block(rbuf[0], cheader.size, wbuf[0],
				       CHUNK_SIZE + 1024, &bytes_consumed);
		if (res < 0) ERROR();

		i32 total_written = 0;

		while (total_written < res) {
			i32 wlen = write(out_fd, wbuf[0] + total_written,
					 res - total_written);
			if (wlen < 0) ERROR();
			total_written += wlen;
		}
	}
CLEANUP:
	RETURN;
}

STATIC i32 compress_file_sync(i32 in_fd, i32 out_fd, u8 rbuf[2][CHUNK_SIZE],
			      u8 wbuf[2][MAX_COMPRESSED_SIZE]) {
INIT:
	while (true) {
		i64 to_read = CHUNK_SIZE, total_read = 0;
		while (total_read < to_read) {
			i32 res = read(in_fd, rbuf[0] + total_read,
				       to_read - total_read);
			if (res < 0) ERROR();
			if (res == 0) break;
			total_read += res;
		}

		if (!total_read) break;
		i32 res = compress_block(rbuf[0], total_read,
					 wbuf[0] + sizeof(ChunkHeader),
					 MAX_COMPRESSED_SIZE);
		if (res < 0) ERROR();
		ChunkHeader *ch = (void *)wbuf[0];
		ch->size = res;
		i64 to_write = res + sizeof(ChunkHeader), total_written = 0;
		while (total_written < to_write) {
			i32 res = write(out_fd, wbuf[0] + total_written,
					to_write - total_written);
			if (res < 0) ERROR();
			total_written += res;
		}
	}
CLEANUP:
	RETURN;
}

PUBLIC i32 decompress_file(i32 in_fd, i32 out_fd) {
	IoUring *iou = NULL;
	CompressFileHeader header = {0};
	ChunkHeader cheader = {0};
	i64 roffset, woffset = 0;
	u8 rbuf[2][MAX_COMPRESSED_SIZE] = {0};
	u8 wbuf[2][CHUNK_SIZE + 1024] = {0};
	i32 res = 0;
	u64 next_read = 0, next_write = U64_MAX;
	u64 expected_bytes, bytes_consumed;
	bool read_pending = true, fin = false;
	ChunkHeader *ch = NULL;
	bool out_is_regular_file, in_is_regular_file;
	struct stat st;
	i32 sched_val;
INIT:
	if (fstat(out_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);
	out_is_regular_file = S_ISREG(st.st_mode);

	if (fstat(in_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);
	in_is_regular_file = S_ISREG(st.st_mode);

	if (in_is_regular_file)
		if (lseek(in_fd, 0, SEEK_SET) < 0) ERROR();
	if ((roffset = compress_read_header(in_fd, &header)) < 0) ERROR();
	if (lseek(in_fd, roffset, SEEK_SET) < 0) ERROR();

	if (!in_is_regular_file || !out_is_regular_file) {
		if (header.filename) release(header.filename);
		return decompress_file_sync(in_fd, out_fd, rbuf, wbuf);
	}

	if (iouring_init(&iou, 4) < 0) ERROR();

	sched_val = compress_file_sched_read(iou, in_fd, roffset,
					     sizeof(ChunkHeader), &cheader, 0);
	if (sched_val < 0) ERROR();
	u64 len0 = compress_file_complete(iou, 0);
	if (len0 < sizeof(ChunkHeader)) ERROR(EPROTO);
	expected_bytes = cheader.size + sizeof(ChunkHeader);
	roffset += sizeof(ChunkHeader);

	sched_val = compress_file_sched_read(iou, in_fd, roffset,
					     cheader.size + sizeof(ChunkHeader),
					     rbuf[0], 0);
	if (sched_val < 0) ERROR();

	while (!fin) {
		if (expected_bytes > MAX_COMPRESSED_SIZE) ERROR(EOVERFLOW);
		u8 index = next_read & 1;
		if (read_pending) res = compress_file_complete(iou, next_read);
		read_pending = true;
		if (res < 0) ERROR();
		if (expected_bytes == res) {
			ch = (void *)(rbuf[index] + expected_bytes -
				      sizeof(ChunkHeader));
			if (ch->size > MAX_COMPRESSED_SIZE) ERROR(EOVERFLOW);
			sched_val = compress_file_sched_read(
			    iou, in_fd, roffset + expected_bytes,
			    ch->size + sizeof(ChunkHeader),
			    rbuf[(next_read + 1) % 2], next_read + 1);
			if (sched_val < 0) ERROR();
		} else if (expected_bytes == res + 4)
			fin = true;

		i32 res2 = decompress_block(rbuf[index], res, wbuf[index],
					    CHUNK_SIZE + 1024, &bytes_consumed);
		if (res2 < 0) ERROR();
		expected_bytes = ch ? ch->size + sizeof(ChunkHeader) : 0;
		if (expected_bytes > MAX_COMPRESSED_SIZE) ERROR(EOVERFLOW);

		sched_val = compress_file_sched_write(
		    iou, out_fd, woffset, res2, wbuf[index], next_write);
		if (sched_val < 0) ERROR();

		roffset += res;

		read_pending = true;
		woffset += res2;
		next_read++;

		if (next_write < U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					u64 id;
					i32 spin_res = iouring_spin(iou, &id);
					if (id == next_read) {
						res = spin_res;
						read_pending = false;
					} else if (id == next_write + 1)
						break;
				}
			}
		}

		next_write--;
	}

	struct timeval ts[2] = {0};
	if (fchmod(out_fd, header.permissions & 0777) < 0) ERROR();
	ts[0].tv_sec = header.atime;
	ts[1].tv_sec = header.mtime;
	if (utimesat(out_fd, NULL, ts, 0) < 0) ERROR();

	while (iouring_pending_all(iou)) iouring_spin(iou, &next_write);

CLEANUP:
	if (header.filename) release(header.filename);
	if (iou) iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 compress_file(i32 in_fd, i32 out_fd, const u8 *filename) {
	struct stat st;
	i64 roffset = 0, woffset;
	IoUring *iou = NULL;
	u8 rbuf[2][CHUNK_SIZE] = {0};
	u8 wbuf[2][MAX_COMPRESSED_SIZE] = {0};
	u64 next_read = 0, next_write = U64_MAX;
	i32 res = 0, res2;
	bool read_pending = true;
	bool out_is_regular_file, in_is_regular_file;
	i32 sched_val;
INIT:
	if (fstat(out_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);
	out_is_regular_file = S_ISREG(st.st_mode);

	if (fstat(in_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);

	in_is_regular_file = S_ISREG(st.st_mode);

	woffset = compress_write_header(out_fd, st.st_mode & 0777, st.st_mtime,
					st.st_atime, filename);
	if (woffset < 0) ERROR();

	if (!in_is_regular_file || !out_is_regular_file)
		return compress_file_sync(in_fd, out_fd, rbuf, wbuf);

	if (iouring_init(&iou, 4) < 0) ERROR();

	sched_val = compress_file_sched_read(iou, in_fd, roffset, CHUNK_SIZE,
					     rbuf[0], 0);
	if (sched_val < 0) ERROR();

	i32 last_res = CHUNK_SIZE;
	while (true) {
		u8 index = next_read & 1;
		if (read_pending) res = compress_file_complete(iou, next_read);
		read_pending = true;

		if (res < 0) ERROR();
		if (res == 0 && last_res != CHUNK_SIZE) break;
		if (res == CHUNK_SIZE) {
			sched_val = compress_file_sched_read(
			    iou, in_fd, roffset + CHUNK_SIZE, CHUNK_SIZE,
			    rbuf[(next_read + 1) % 2], next_read + 1);
			if (sched_val < 0) ERROR();
		}
		last_res = res;
		res2 = compress_block(
		    rbuf[index], res, wbuf[index] + sizeof(ChunkHeader),
		    MAX_COMPRESSED_SIZE - sizeof(ChunkHeader));
		if (res2 < 0) ERROR();
		ChunkHeader *ch = (void *)wbuf[index];
		ch->size = res2;
		res2 += sizeof(ChunkHeader);

		sched_val = compress_file_sched_write(
		    iou, out_fd, woffset, res2, wbuf[index], next_write);
		if (sched_val < 0) ERROR();

		read_pending = true;
		roffset += res;
		woffset += res2;
		next_read++;

		if (next_write < U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					u64 id;
					i32 spin_res = iouring_spin(iou, &id);
					if (id == next_read) {
						res = spin_res;
						read_pending = false;
					} else if (id == next_write + 1)
						break;
				}
			}
		}
		next_write--;
	}

	while (iouring_pending_all(iou)) iouring_spin(iou, &next_write);

CLEANUP:
	if (iou) iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 decompress_get_filename(i32 fd, u8 filename[MAX_FILE_NAME + 1]) {
	CompressFileHeader header = {0};
INIT:
	if (lseek(fd, 0, SEEK_SET) < 0) ERROR();
	if (compress_read_header(fd, &header) < 0) ERROR();
	if (header.filename) {
		u64 len = strlen(header.filename);
		memcpy(filename, header.filename, len);
		OK(len);
	} else {
		filename[0] = 0;
		OK(0);
	}
CLEANUP:
	if (header.filename) release(header.filename);
	RETURN;
}

STATIC i32 compress_read_header2(i32 in_fd, CompressFileHeader *header) {
	u8 buffer[1024] = {0}, flags;
	u16 total = 0, offset = 0;
	u64 needed = sizeof(u32) + sizeof(u8) * 2, cur;
INIT:
	while (total < needed) {
		i64 value = pread(in_fd, buffer + total, needed - total, total);
		if (value < 0) ERROR();
		total += value;
		if (value == 0) ERROR(EPROTO);
	}
	cur = total;
	if (((u32 *)buffer)[0] != MAGIC) ERROR(EPROTO);
	if (buffer[4] != VERSION) ERROR(EPROTO);
	flags = buffer[5];
	needed = 0;
	total = 0;
	if (flags & STREAM_FLAG_HAS_PERMISSIONS) needed += 2;
	if (flags & STREAM_FLAG_HAS_MTIME) needed += 8;
	if (flags & STREAM_FLAG_HAS_ATIME) needed += 8;
	if (flags & STREAM_FLAG_HAS_FILE_NAME) needed += MAX_FILE_NAME + 1;

	while (total < needed) {
		u8 flag;
		i64 value =
		    pread(in_fd, buffer + total, needed - total, cur + total);
		if (value < 0) ERROR();
		if (value == 0) ERROR(EPROTO);
		total += value;
		offset = 0;

		flag = flags & STREAM_FLAG_HAS_PERMISSIONS;
		if (flag && !(total - offset >= sizeof(u16))) continue;
		if (flag && total - offset >= sizeof(u16)) {
			memcpy(&header->permissions, buffer + offset,
			       sizeof(u16));
			offset += sizeof(u16);
		}

		flag = flags & STREAM_FLAG_HAS_MTIME;
		if (flag && !(total - offset >= sizeof(u64))) continue;
		if (flag && total - offset >= sizeof(u64)) {
			memcpy(&header->mtime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		}

		flag = flags & STREAM_FLAG_HAS_ATIME;
		if (flag && !(total - offset >= sizeof(u64))) continue;
		if (flag && total - offset >= sizeof(u64)) {
			memcpy(&header->atime, buffer + offset, sizeof(u64));
			offset += sizeof(u64);
		}

		if (flags & STREAM_FLAG_HAS_FILE_NAME && total - offset > 0) {
			u64 len = strlen((char *)(buffer + offset));
			if (len > MAX_FILE_NAME) ERROR(EPROTO);
			if (!(len < total - offset)) continue;
			if (len < total - offset) {
				header->filename = alloc(len + 1);
				if (!header->filename) ERROR();
				strcpy((char *)header->filename,
				       (char *)(buffer + offset));
				offset += len + 1;
			}
		}

		break;
	}
	OK(offset + 6);
CLEANUP:
	RETURN;
}

typedef struct {
	u64 chunks_discovered;
	u64 chunk_sizes[500];
} DecompressState;

i32 decompress_file2(i32 in_fd, i32 out_fd) {
	IoUring *iou = NULL;
	CompressFileHeader header = {0};
	ChunkHeader cheader = {0};
	i64 roffset, woffset = 0;
	u8 rbuf[2][MAX_COMPRESSED_SIZE] = {0};
	u8 wbuf[2][CHUNK_SIZE + 1024] = {0};
	i32 res = 0;
	u64 next_read = 0, next_write = U64_MAX;
	u64 expected_bytes, bytes_consumed;
	bool read_pending = true, fin = false;
	ChunkHeader *ch = NULL;
	bool out_is_regular_file, in_is_regular_file;
	struct stat st;
	i32 sched_val;
	DecompressState *state = NULL;
	i32 proc_count = 6;
INIT:
	if (fstat(out_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);
	out_is_regular_file = S_ISREG(st.st_mode);

	if (fstat(in_fd, &st) < 0) ERROR();
	if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
		ERROR(EINVAL);
	in_is_regular_file = S_ISREG(st.st_mode);

	if (in_is_regular_file)
		if (lseek(in_fd, 0, SEEK_SET) < 0) ERROR();
	if ((roffset = compress_read_header2(in_fd, &header)) < 0) ERROR();
	if (lseek(in_fd, roffset, SEEK_SET) < 0) ERROR();

	if (!in_is_regular_file || !out_is_regular_file) {
		if (header.filename) release(header.filename);
		return decompress_file_sync(in_fd, out_fd, rbuf, wbuf);
	}

	/*
	println("roffset={},name={},mtime={},atime={}", roffset,
		header.filename, header.mtime, header.atime);
		*/
	state = smap(sizeof(DecompressState));
	if (!state) ERROR();

	i32 pid = fork();
	if (pid < 0) ERROR();
	if (pid) {
		while (true) {
			ChunkHeader chunk;
			i32 res =
			    pread(in_fd, &chunk, sizeof(ChunkHeader), roffset);
			if (res != sizeof(ChunkHeader)) break;
			/*println("size={},res={}", chunk.size, res);*/
			__astore64(
			    &state->chunk_sizes[state->chunks_discovered],
			    roffset + sizeof(ChunkHeader));
			roffset += chunk.size + sizeof(ChunkHeader);

			__aadd64(&state->chunks_discovered, 1);
		}
		for (i32 i = 0; i < proc_count; i++) {
			__astore64(
			    &state->chunk_sizes[state->chunks_discovered],
			    U64_MAX);
			__aadd64(&state->chunks_discovered, 1);
		}
		// println("found all chunks");
		await(pid);
	} else {
		i32 pids[MAX_PROCS] = {0};
		for (i32 i = 0; i < proc_count; i++) {
			pids[i] = fork();
			if (pids[i] < 0) panic("Could not fork worker!");
			if (!pids[i]) {
				u32 offset = i;
				while (true) {
					while (__aload64(
						   &state->chunks_discovered) <=
					       offset);
					u64 boffset = __aload64(
					    &state->chunk_sizes[offset]);

					/*
					println("proc block {},offt={}", offset,
						boffset);
						*/
					if (boffset == U64_MAX) break;
					offset += proc_count;
				}
				// println("end {}", i);
				_exit(0);
			}
		}
		for (i32 i = 0; i < proc_count; i++) await(pids[i]);
		_exit(0);
	}

	(void)fin;
	(void)ch;
	(void)sched_val;
	(void)out_is_regular_file;
	(void)read_pending;
	(void)next_read;
	(void)res;
	(void)rbuf;
	(void)wbuf;
	(void)cheader;
	(void)woffset;
	(void)iou;
	(void)next_write;
	(void)expected_bytes;
	(void)bytes_consumed;
CLEANUP:
	if (header.filename) release(header.filename);
	if (iou) iouring_destroy(iou);
	if (state) munmap(state, sizeof(DecompressState));

	RETURN;
}
