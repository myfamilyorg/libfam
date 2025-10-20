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

#include <libfam/b64.h>
#include <libfam/types.h>
#include <libfam/utils.h>

/* Base64 encode */
PUBLIC u64 b64_encode(const u8 *in, u64 in_len, u8 *out, u64 out_max) {
	u64 i;
	u64 j;
	static const u8 *b64_table =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (!in || !out || out_max < ((in_len + 2) / 3) * 4 + 1) {
		return 0;
	}

	j = 0;
	for (i = 0; i + 2 < in_len; i += 3) {
		out[j] = b64_table[(in[i] >> 2) & 0x3F];
		j++;
		out[j] = b64_table[((in[i] & 0x3) << 4) | (in[i + 1] >> 4)];
		j++;
		out[j] = b64_table[((in[i + 1] & 0xF) << 2) | (in[i + 2] >> 6)];
		j++;
		out[j] = b64_table[in[i + 2] & 0x3F];
		j++;
	}

	if (i < in_len) {
		out[j] = b64_table[(in[i] >> 2) & 0x3F];
		j++;
		if (i + 1 < in_len) {
			out[j] =
			    b64_table[((in[i] & 0x3) << 4) | (in[i + 1] >> 4)];
			j++;
			out[j] = b64_table[(in[i + 1] & 0xF) << 2];
			j++;
		} else {
			out[j] = b64_table[(in[i] & 0x3) << 4];
			j++;
			out[j] = '=';
			j++;
		}
		out[j] = '=';
		j++;
	}

	out[j] = '\0';
	return j;
}

/* Base64 decode */
PUBLIC u64 b64_decode(const u8 *in, u64 in_len, u8 *out, u64 out_max) {
	u64 i;
	u64 j;
	i32 b0;
	i32 b1;
	i32 b2;
	i32 b3;
	static const i32 decode_table[256] = {
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	    -1, 0,  1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14,
	    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

	if (!in || !out || in_len % 4 != 0) {
		return 0;
	}

	/* Account for padding in output size */
	{
		u64 expected_out = (in_len / 4) * 3;
		if (in_len >= 4 && in[in_len - 1] == '=') out_max++;
		if (in_len >= 4 && in[in_len - 2] == '=') out_max++;
		if (out_max < expected_out) {
			return 0;
		}
	}

	j = 0;
	for (i = 0; i < in_len; i += 4) {
		b0 = decode_table[(u8)in[i]];
		b1 = decode_table[(u8)in[i + 1]];
		b2 = (i + 2 < in_len && in[i + 2] != '=')
			 ? decode_table[(u8)in[i + 2]]
			 : -1;
		b3 = (i + 3 < in_len && in[i + 3] != '=')
			 ? decode_table[(u8)in[i + 3]]
			 : -1;

		if (b0 == -1 || b1 == -1 ||
		    (i + 2 < in_len && in[i + 2] != '=' && b2 == -1) ||
		    (i + 3 < in_len && in[i + 3] != '=' && b3 == -1)) {
			return 0;
		}

		if (j + 3 > out_max) return 0;
		out[j] = (u8)((b0 << 2) | (b1 >> 4));
		j++;
		if (i + 2 < in_len && in[i + 2] != '=') {
			out[j] = (u8)((b1 << 4) | (b2 >> 2));
			j++;
		}
		if (i + 3 < in_len && in[i + 3] != '=') {
			out[j] = (u8)((b2 << 6) | b3);
			j++;
		}
	}

	return j;
}
