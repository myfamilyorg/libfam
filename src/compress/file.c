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
#include <libfam/env.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

#define MAX_PROCS 6

typedef struct {
	u64 next_chunk;
	u64 next_write;
	u64 chunks;
	u32 in_progress;
	u8 procs;
	i32 infd;
	u64 in_offset;
	i32 outfd;
	u64 out_offset;
} CompressState;

STATIC void compress_run_proc(u32 id, CompressState *state) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3];
	u64 chunk;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));
	while ((chunk = __aadd64(&state->next_chunk, 1)) < state->chunks) {
		i64 res = pread(state->infd, buffers[0], MAX_COMPRESS_LEN,
				state->in_offset + chunk * MAX_COMPRESS_LEN);
		i32 len = compress_block(buffers[0], res, buffers[1],
					 MAX_COMPRESS_LEN + 3);

		u64 expected;
		do {
			expected = chunk;
		} while (!__cas64(&state->next_write, &expected, U64_MAX));
		pwrite(state->outfd, buffers[1], len, state->out_offset);
		__aadd64(&state->out_offset, len);
		__astore64(&state->next_write, chunk + 1);

		/*
		println("proc {} ({},{},{},{})", chunk, id, res, len,
			state->out_offset);
			*/
	}
}

i32 compress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	CompressState *state = NULL;
	struct stat st, outst;
	state = smap(sizeof(CompressState));
	fastmemset(state, 0, sizeof(*state));
	if (!state) return -1;

	if (fstat(infd, &st) < 0) return -1;
	if (fstat(outfd, &outst) < 0) return -1;
	if (st.st_size <= in_offset || !S_ISREG(st.st_mode) ||
	    !S_ISREG(outst.st_mode)) {
		errno = EINVAL;
		return -1;
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
	munmap(state, sizeof(CompressState));

	return 0;
}

i32 decompress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset);

