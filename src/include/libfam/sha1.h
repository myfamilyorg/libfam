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

#ifndef _SHA1_H
#define _SHA1_H

#include <libfam/types.h>

/*
 * Type: SHA1_CTX
 * Context structure for SHA-1 hash computation.
 * members:
 *         u32 state[5]   - internal hash state (160 bits, 5 x 32-bit words).
 *         u64 count      - total number of bits processed.
 *         u8 buffer[64]  - input buffer for partial message blocks.
 * notes:
 *         Must be initialized with sha1_init before use.
 *         Opaque to user; do not modify directly.
 *         Size: 84 bytes (portable and compact).
 */
typedef struct {
	u32 state[5];
	u64 count;
	u8 buffer[64];
} SHA1_CTX;

/*
 * Function: sha1_init
 * Initializes a SHA-1 context.
 * inputs:
 *         SHA1_CTX *ctx - pointer to context to initialize.
 * return value: None.
 * errors: None.
 * notes:
 *         ctx must not be null.
 *         Sets initial hash state to standard SHA-1 constants.
 *         Must be called before sha1_update or sha1_final.
 *         Safe to call multiple times.
 */
void sha1_init(SHA1_CTX *ctx);

/*
 * Function: sha1_update
 * Processes input data into the SHA-1 hash.
 * inputs:
 *         SHA1_CTX *ctx    - pointer to initialized context.
 *         const void *data - pointer to input data.
 *         u64 len          - length of input data in bytes.
 * return value: None.
 * errors: None.
 * notes:
 *         ctx must be initialized.
 *         data must not be null if len > 0.
 *         len may be zero (no-op).
 *         Can be called multiple times with streaming data.
 *         Internally buffers partial 64-byte blocks.
 */
void sha1_update(SHA1_CTX *ctx, const void *data, u64 len);

/*
 * Function: sha1_final
 * Finalizes the SHA-1 hash and outputs the 20-byte digest.
 * inputs:
 *         SHA1_CTX *ctx    - pointer to initialized context.
 *         u8 *digest       - pointer to 20-byte output buffer.
 * return value: None.
 * errors: None.
 * notes:
 *         ctx must be initialized and may have been updated.
 *         digest must not be null and must have at least 20 bytes.
 *         Pads message and appends length per SHA-1 specification.
 *         After call, ctx is reset and may be reused via sha1_init.
 *         Output is in big-endian byte order (network order).
 */
void sha1_final(SHA1_CTX *ctx, u8 *digest);

#endif /* _SHA1_H */
