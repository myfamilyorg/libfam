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

#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <libfam/types.h>

/*
 * Constant: MAX_COMPRESS_LEN
 * Maximum input length for compress_block (262144 bytes).
 * Prevents excessive memory usage in compression functions.
 */
#define MAX_COMPRESS_LEN (1 << 18)

/*
 * Constant: MAX_FILE_NAME
 * Maximum length for filenames in decompress_get_filename (256 bytes).
 * Includes space for null terminator.
 */
#define MAX_FILE_NAME 256

/*
 * Function: compress_bound
 * Returns the maximum size of compressed data for a given input length.
 * inputs:
 *         u64 source_len - the length of the input data to compress.
 * return value: u64 - maximum compressed size, including overhead.
 * errors: None.
 * notes:
 *         Use to allocate out buffer for compress_block.
 */
u64 compress_bound(u64 source_len);

/*
 * Function: compress_block
 * Compresses a block of data.
 * inputs:
 *         const u8 *in   - the text or binary data to compress.
 *         u32 len        - the length of the input data.
 *         u8 *out        - the pointer to the memory location to store the
 *                          output.
 * 	   u32 capacity   - the capacity, in bytes, of the output location.
 * return value: i32 - 0 on success, -1 on error with errno value set.
 * errors:
 *         EINVAL         - if len > MAX_COMPRESS_LEN (1 << 18) or
 *         		    if capacity < compress_bound(len).
 *         EFAULT         - if in or out is a null pointer.
 * notes:
 *         in must not be empty (len > 0).
 *         out must be pre-allocated with at least compress_bound(len) bytes.
 *         On error, out is unmodified.
 */
i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity);

/*
 * Function: decompress_block
 * Decompresses a block of data compressed by compress_block.
 * inputs:
 *         const u8 *in   - the compressed data.
 *         u32 len        - the length of the compressed data.
 *         u8 *out        - the pointer to the memory location to store the
 *                          output.
 *         u32 capacity   - the capacity, in bytes, of the output location.
 *         u64 *bytes_consumed - pointer to store the number of input bytes
 * processed.
 * return value: i32 - 0 on success, -1 on error with errno value set.
 * errors:
 *         EINVAL         - if len is invalid or data is corrupted.
 *         EFAULT         - if in, out, or bytes_consumed is a null pointer.
 * notes: in must be valid compressed data from compress_block.
 * out must be pre-allocated with sufficient capacity.
 * bytes_consumed is set to the number of input bytes used,
 * even on error. On error, out is unmodified.
 */
i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity,
		     u64 *bytes_consumed);

/*
 * Function: compress_file
 * Compresses data from an input file descriptor to an output file descriptor.
 * inputs:
 *         i32 in_fd      - file descriptor for the input file.
 *         i32 out_fd     - file descriptor for the output file.
 *         const u8 *filename - the name of the input file (for metadata).
 * return value: i32 - 0 on success, -1 on error with errno value set.
 * errors:
 *         EINVAL         - if in_fd or out_fd is invalid or filename is too
 *                          long.
 *         ENOMEM         - if insufficient memory is available.
 *         EIO            - if an I/O error occurs during reading or
 *                          writing.
 *         EFAULT         - if filename is a null pointer.
 * notes: filename is
 * stored in the compressed output for use by decompress_get_filename. in_fd and
 * out_fd must be valid, open file descriptors. On error, out_fd may contain
 * partial data.
 */
i32 compress_file(i32 in_fd, i32 out_fd, const u8 *filename);

/*
 * Function: decompress_file
 * Decompresses data from an input file descriptor to an output file descriptor.
 * inputs:
 *         i32 in_fd      - file descriptor for the compressed input file.
 *         i32 out_fd     - file descriptor for the output file.
 * return value: i32 - 0 on success, -1 on error with errno value set.
 * errors:
 *         EINVAL         - if in_fd or out_fd is invalid or input data is
 *                          corrupted.
 *         ENOMEM         - if insufficient memory is available.
 *         EIO            - if an I/O error occurs during reading or writing.
 * notes:
 *         in_fd must contain valid compressed data from compress_file.
 *         in_fd and out_fd must be valid, open file descriptors.
 *         On error, out_fd may contain partial data.
 */
i32 decompress_file(i32 in_fd, i32 out_fd);

i32 decompress_file2(i32 in_fd, i32 out_fd);

/*
 * Function: decompress_get_filename
 * Retrieves the filename stored in a compressed file.
 * inputs:
 *         i32 fd         - file descriptor for the compressed file.
 *         u8 filename[MAX_FILE_NAME + 1] - buffer to store the filename.
 * return value: i32 - 0 on success, -1 on error with errno value set.
 * errors:
 *         EINVAL         - if fd is invalid or input data is corrupted.
 *         EIO            - if an I/O error occurs during reading.
 * notes:
 *         filename buffer must have space for MAX_FILE_NAME + 1 bytes.
 *         On success, filename is null-terminated.
 *         On error, filename is unmodified.
 */
i32 decompress_get_filename(i32 fd, u8 filename[MAX_FILE_NAME + 1]);

#endif /* _COMPRESS_H */
