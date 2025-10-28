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

#ifndef _SHA3_H
#define _SHA3_H

#include <libfam/types.h>

/*
 * Constant: SHA3_KECCAK_SPONGE_WORDS
 * Number of 64-bit words in the Keccak sponge state (25).
 * notes:
 *         Derived from 1600-bit state: (1600 / 8) / sizeof(u64) = 25.
 *         Fixed for all SHA-3 variants.
 */
#define SHA3_KECCAK_SPONGE_WORDS (((1600) / 8 /*bits to byte*/) / sizeof(u64))

/*
 * Type: Sha3Context
 * Internal context for SHA-3 (Keccak) hash computation.
 * members:
 *         u64 saved          - partial word from previous update (bits not yet
 * absorbed). union u { u64 s[25]      - 1600-bit Keccak state as 25 x 64-bit
 * words. u8 sb[200]     - same state as byte array (for byte-wise access).
 *         }
 *         u32 byteIndex      - index into current word (0–7) for next input
 * byte. u32 wordIndex      - index into state array (0–24) for next word to
 * fill. u32 capacityWords  - capacity in words = 2 * output_hash_bits / 64.
 * notes:
 *         Opaque to user; do not access directly.
 *         Must be initialized with sha3_init* before use.
 *         Supports streaming via sha3_update.
 */
typedef struct Sha3Context_ {
	u64 saved; /* the portion of the input message that we
		    * didn't consume yet */
	union {	   /* Keccak's state */
		u64 s[SHA3_KECCAK_SPONGE_WORDS];
		u8 sb[SHA3_KECCAK_SPONGE_WORDS * 8];
	} u;
	u32 byteIndex;	   /* 0..7--the next byte after the set one
			    * (starts from 0; 0--none are buffered) */
	u32 wordIndex;	   /* 0..24--the next word to integrate input
			    * (starts from 0) */
	u32 capacityWords; /* the double size of the hash output in
			    * words (e.g. 16 for Keccak 512) */
} Sha3Context;

/*
 * Function: sha3_init256
 * Initializes context for SHA3-256 (32-byte output).
 * inputs:
 *         void *priv - pointer to user-provided Sha3Context buffer.
 * return value: None.
 * errors: None.
 * notes:
 *         priv must point to at least sizeof(Sha3Context) bytes.
 *         Sets rate=1088, capacity=512, output=256 bits.
 *         Must be called before sha3_update or sha3_finalize.
 */
void sha3_init256(void *priv);

/*
 * Function: sha3_init384
 * Initializes context for SHA3-384 (48-byte output).
 * inputs:
 *         void *priv - pointer to user-provided Sha3Context buffer.
 * return value: None.
 * errors: None.
 * notes:
 *         priv must point to at least sizeof(Sha3Context) bytes.
 *         Sets rate=832, capacity=768, output=384 bits.
 */
void sha3_init384(void *priv);

/*
 * Function: sha3_init512
 * Initializes context for SHA3-512 (64-byte output).
 * inputs:
 *         void *priv - pointer to user-provided Sha3Context buffer.
 * return value: None.
 * errors: None.
 * notes:
 *         priv must point to at least sizeof(Sha3Context) bytes.
 *         Sets rate=576, capacity=1024, output=512 bits.
 */
void sha3_init512(void *priv);

/*
 * Function: sha3_init
 * Initializes context for arbitrary SHA-3 output size.
 * inputs:
 *         void *priv     - pointer to user-provided Sha3Context buffer.
 *         u32 bit_size   - desired output size in bits (must be 224, 256, 384,
 * or 512). return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if bit_size is not a valid SHA-3 output size.
 * notes:
 *         priv must point to at least sizeof(Sha3Context) bytes.
 *         Automatically selects correct rate/capacity.
 *         Use for non-standard but valid SHA-3 sizes (e.g. 224).
 */
i32 sha3_init(void *priv, u32 bit_size);

/*
 * Function: sha3_update
 * Absorbs input data into the SHA-3 sponge.
 * inputs:
 *         void *priv        - pointer to initialized Sha3Context.
 *         void const *bufIn - input data to hash.
 *         u64 len           - length of input in bytes.
 * return value: None.
 * errors: None.
 * notes:
 *         priv must be initialized.
 *         bufIn must not be null if len > 0.
 *         len may be zero (no-op).
 *         Can be called multiple times for streaming.
 *         Internally applies Keccak-f[1600] when rate is full.
 */
void sha3_update(void *priv, void const *bufIn, u64 len);

/*
 * Function: sha3_finalize
 * Finalizes hash and returns pointer to digest in context.
 * inputs:
 *         void *priv - pointer to initialized and updated Sha3Context.
 * return value: const void * - pointer to digest bytes in context.
 * errors: None.
 * notes:
 *         priv must be initialized and may have been updated.
 *         Returns pointer to internal digest buffer (32/48/64 bytes).
 *         Digest is in little-endian byte order within words.
 *         Context is reset after finalization; may be reused with sha3_init*.
 *         Do not free returned pointer.
 */
void const *sha3_finalize(void *priv);

#endif /* _SHA3_H */
