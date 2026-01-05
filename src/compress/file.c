/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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
#include <libfam/env.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

#define MAX_PROCS 8

typedef struct {
	u64 next_chunk;
	u64 next_write;
	u64 chunks;
	u8 procs;
	i32 infd;
	u64 in_offset;
	i32 outfd;
	u64 out_offset;
} CompressState;

typedef struct {
	u64 next_chunk;
	u64 next_write;
	u64 chunks;
	u8 procs;
	i32 infd;
	u64 in_offset;
	u64 in_len;
	i32 outfd;
	u64 out_offset;
	u64 *chunk_offsets;
} DecompressState;

STATIC void compress_run_proc(u32 id, CompressState *state) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];
	u64 chunk;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));
	while ((chunk = __aadd64(&state->next_chunk, 1)) < state->chunks) {
		i64 res = pread(state->infd, buffers[0], MAX_COMPRESS_LEN,
				state->in_offset + chunk * MAX_COMPRESS_LEN);
		i32 len =
		    compress_block(buffers[0], res, buffers[1] + sizeof(u32),
				   MAX_COMPRESS_LEN + 3);
		fastmemcpy(buffers[1], &len, sizeof(u32));
		u64 expected;
		do {
			expected = chunk;
		} while (!__cas64(&state->next_write, &expected, U64_MAX));

		pwrite(state->outfd, buffers[1], len + sizeof(u32),
		       state->out_offset);
		__aadd64(&state->out_offset, len + sizeof(u32));
		__astore64(&state->next_write, chunk + 1);
	}
}

STATIC void decompress_run_proc(u32 id, DecompressState *state) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];
	u64 chunk;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));
	while ((chunk = __aadd64(&state->next_chunk, 1)) < state->chunks) {
		i64 res = pread(state->infd, buffers[0], MAX_COMPRESS_LEN,
				state->chunk_offsets[chunk]);
		res = decompress_block(buffers[0], res, buffers[1],
				       MAX_COMPRESS_LEN + 3);
		pwrite(state->outfd, buffers[1], res,
		       state->out_offset + MAX_COMPRESS_LEN * chunk);
	}
}

i32 compress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	i32 ret = 0;
	CompressState *state = NULL;
	struct stat st, outst;
	state = smap(sizeof(CompressState));
	if (!state) return -1;

	if (fstat(infd, &st) < 0) return -1;
	if (fstat(outfd, &outst) < 0) return -1;
	if (st.st_size <= in_offset || !S_ISREG(st.st_mode) ||
	    !S_ISREG(outst.st_mode)) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	state->chunks = ((st.st_size - in_offset) + MAX_COMPRESS_LEN - 1) /
			MAX_COMPRESS_LEN;
	state->procs = min(MAX_PROCS, state->chunks);
	state->infd = infd;
	state->in_offset = in_offset;
	state->outfd = outfd;
	state->out_offset = out_offset;

	i32 pids[MAX_PROCS] = {0};
	u32 i;
	for (i = 0; i < (state->procs - 1); i++) {
		pids[i] = fork();
		if (!pids[i]) {
			compress_run_proc(i, state);
			_exit(0);
		}
	}
	compress_run_proc(i, state);
	for (u32 i = 0; i < state->procs; i++) await(pids[i]);
cleanup:
	if (state) munmap(state, sizeof(CompressState));
	return ret;
}

i32 decompress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	u64 chunk_offset_allocation = 0;
	i32 ret = 0;
	DecompressState *state = NULL;
	struct stat st, outst;

	state = smap(sizeof(DecompressState));
	if (!state) {
		ret = -1;
		goto cleanup;
	}
	if (fstat(infd, &st) < 0) {
		ret = -1;
		goto cleanup;
	}
	if (fstat(outfd, &outst) < 0) {
		ret = -1;
		goto cleanup;
	}
	if (!st.st_size || st.st_size <= in_offset || !S_ISREG(st.st_mode) ||
	    !S_ISREG(outst.st_mode)) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	chunk_offset_allocation =
	    ((st.st_size / (48000 * (4096 / 8))) + 1) * 4096;

	state->chunk_offsets = smap(chunk_offset_allocation);
	if (!state->chunk_offsets) {
		ret = -1;
		goto cleanup;
	}

	state->procs = min(MAX_PROCS - 2, (st.st_size + (MAX_COMPRESS_LEN - 1) /
							    MAX_COMPRESS_LEN));
	state->infd = infd;
	state->in_offset = in_offset;
	state->in_len = st.st_size;
	state->outfd = outfd;
	state->out_offset = out_offset;

	u32 chunk_len = 0;
	u64 offset = 0, i = 0, file_size = 0;

	while (offset < state->in_len) {
		pread(state->infd, &chunk_len, sizeof(u32),
		      state->in_offset + offset);
		state->chunk_offsets[i++] =
		    offset + state->in_offset + sizeof(u32);
		offset += chunk_len + sizeof(u32);
		if (chunk_len == 0) break;
		if (offset < state->in_len) file_size += MAX_COMPRESS_LEN;
	}
	state->chunks = i;
	state->chunk_offsets[i] = state->in_len;
	fallocate(outfd, file_size);
	(void)file_size;

	i32 pids[MAX_PROCS] = {0};

	for (i = 0; i < (state->procs - 1); i++) {
		pids[i] = fork();
		if (!pids[i]) {
			decompress_run_proc(i, state);
			_exit(0);
		}
	}
	decompress_run_proc(i, state);
	for (u32 i = 0; i < state->procs; i++) await(pids[i]);

cleanup:
	if (state) {
		if (state->chunk_offsets)
			munmap(state->chunk_offsets, chunk_offset_allocation);
		munmap(state, sizeof(DecompressState));
	}
	return ret;
}

