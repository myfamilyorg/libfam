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

#ifndef _COMPRESS_STREAM_H
#define _COMPRESS_STREAM_H

#include <libfam/compress_impl.h>
#include <libfam/types.h>

#define MAGIC 0xC3161337
#define VERSION 1
#define CHUNK_SIZE MAX_COMPRESS_LEN
#define COMPRESSED_CHUNK_SIZE \
	(CHUNK_SIZE + (CHUNK_SIZE >> 9) + 24 + sizeof(ChunkHeader))
#define CTHREADS 4
#define CR_BUFS 2
#define CW_BUFS 2
#define DR_BUFS 4
#define DW_BUFS 4

typedef struct {
	u32 magic;
	u8 version;
	u8 reserved;
	u16 permissions;
	u64 mtime;
	u64 atime;
} __attribute__((packed)) StreamHeader;

typedef struct {
	bool fin;
	u32 size;
} __attribute__((packed)) ChunkHeader;

typedef struct {
	u32 tid;
	u32 io_lock;
	u32 is_ready[CTHREADS];
} StreamState;

#endif /* _COMPRESS_STREAM_H */
