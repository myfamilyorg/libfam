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

#define MAGIC 0xC3161337
#define VERSION 1

#define CHUNK_SIZE (1 << 18)
#define MAX_COMPRESSED_SIZE (CHUNK_SIZE + 3 + sizeof(ChunkHeader))

#define STREAM_FLAG_HAS_PERMISSIONS (0x1 << 0)
#define STREAM_FLAG_HAS_MTIME (0x1 << 1)
#define STREAM_FLAG_HAS_ATIME (0x1 << 2)
#define STREAM_FLAG_HAS_FILE_NAME (0x1 << 3)
#define MAX_FILE_NAME 256

typedef struct {
	u16 permissions;
	u64 mtime;
	u64 atime;
	u8 *filename;
} CompressFileHeader;

typedef struct {
	u32 size;
} ChunkHeader;
