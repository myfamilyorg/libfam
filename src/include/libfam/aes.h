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

#ifndef _AES_H
#define _AES_H

#include <libfam/types.h>

/*
 * Constant: AES_BLOCKLEN
 * Size of an AES block in bytes (16 bytes).
 * All AES operations process data in blocks of this size.
 */
#define AES_BLOCKLEN 16

/*
 * Constant: AES_KEYLEN
 * Length of the AES key in bytes (32 bytes, i.e., AES-256).
 * This implementation uses 256-bit keys exclusively.
 */
#define AES_KEYLEN 32

/*
 * Constant: AES_KEYEXPSIZE
 * Size of the expanded key schedule in bytes (240 bytes).
 * Required for internal key expansion in AES-256.
 */
#define AES_KEYEXPSIZE 240

/*
 * Type: AesContext
 * Opaque context structure holding AES state.
 * members:
 *         u8 RoundKey[AES_KEYEXPSIZE] - expanded key schedule for encryption.
 *         u8 Iv[AES_BLOCKLEN]        - current initialization vector (IV).
 * notes:
 *         Must be initialized with aes_init before use.
 *         IV is updated internally during CTR mode operations.
 */
typedef struct {
	__attribute__((aligned(16))) u8 RoundKey[AES_KEYEXPSIZE];
	u8 Iv[AES_BLOCKLEN];
} AesContext;

/*
 * Function: aes_init
 * Initializes an AES context with a key and initial IV.
 * inputs:
 *         AesContext *ctx - pointer to the context to initialize.
 *         const u8 *key   - 32-byte encryption key (AES-256).
 *         const u8 *iv    - 16-byte initial initialization vector.
 * return value: None.
 * errors: None.
 * notes:
 *         Must be called before any encryption/decryption.
 *         key and iv must not be null and must be exactly AES_KEYLEN
 *         and AES_BLOCKLEN bytes respectively.
 *         ctx is fully initialized; previous contents are overwritten.
 */
void aes_init(AesContext *ctx, const u8 *key, const u8 *iv);

/*
 * Function: aes_set_iv
 * Updates the initialization vector in an already-initialized context.
 * inputs:
 *         AesContext *ctx - pointer to the initialized context.
 *         const u8 *iv    - new 16-byte initialization vector.
 * return value: None.
 * errors: None.
 * notes:
 *         ctx must have been previously initialized with aes_init.
 *         iv must not be null and must be exactly AES_BLOCKLEN bytes.
 *         Useful for restarting CTR stream with a new nonce/IV.
 */
void aes_set_iv(AesContext *ctx, const u8 *iv);

/*
 * Function: aes_ctr_xcrypt_buffer
 * Encrypts or decrypts a buffer in CTR mode (stream cipher).
 * inputs:
 *         AesContext *ctx - pointer to initialized AES context.
 *         void *buf       - pointer to data to encrypt/decrypt in-place.
 *         u64 length      - number of bytes to process.
 * return value: None.
 * errors: None.
 * notes:
 *         Operates in CTR mode: encryption and decryption are identical.
 *         buf is modified in-place; no output buffer needed.
 *         length can be any value >= 0; zero-length inputs are no-ops.
 *         ctx->Iv is updated to reflect the next block's counter state.
 *         Thread-safe as long as ctx is not shared without synchronization.
 */
void aes_ctr_xcrypt_buffer(AesContext *ctx, void *buf, u64 length);

/*
 * Fast aes (uses SIMD)
 */
void aes256_ctr_encrypt_8blocks(AesContext *ctx, const u8 in[128], u8 out[128]);

#endif /* _AES_H */
