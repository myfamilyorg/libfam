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

#ifndef _B64_H
#define _B64_H

#include <libfam/types.h>

/*
 * Function: b64_encode
 * Encodes binary data into Base64 text.
 * inputs:
 *         const u8 *in     - pointer to input binary data.
 *         u64 in_len       - length of input data in bytes.
 *         u8 *out          - pointer to output buffer for encoded text.
 *         u64 out_max      - maximum capacity of output buffer (including
 * null). return value: u64 - number of bytes written to out (excluding null),
 * or 0 on error. errors: None (returns 0 on failure). notes: Output is
 * null-terminated if space allows. Required output size: ((in_len + 2) / 3) * 4
 * + 1 (including null). If out_max is insufficient, returns 0 and out is
 * unmodified. in and out must not be null; in_len may be 0. Uses standard
 * Base64 alphabet (RFC 4648).
 */
u64 b64_encode(const u8 *in, u64 in_len, u8 *out, u64 out_max);

/*
 * Function: b64_decode
 * Decodes Base64 text into binary data.
 * inputs:
 *         const u8 *in     - pointer to input Base64 text (null-terminated or
 * not). u64 in_len       - length of input data in bytes (excluding null if
 * present). u8 *out          - pointer to output buffer for decoded binary. u64
 * out_max      - maximum capacity of output buffer. return value: u64 - number
 * of bytes written to out, or 0 on error. errors: None (returns 0 on failure).
 * notes:
 *         Input must contain only valid Base64 characters (A-Z, a-z, 0-9, +, /,
 * =). Padding '=' is optional but respected if present. Required output size:
 * (in_len * 3) / 4 (rounded down). If out_max is insufficient or input is
 * invalid, returns 0 and out is unmodified. in and out must not be null; in_len
 * may be 0. Stops at first invalid character or end of input.
 */
u64 b64_decode(const u8 *in, u64 in_len, u8 *out, u64 out_max);

#endif /* _B64_H */
