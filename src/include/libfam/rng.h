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

#ifndef _RNG_H
#define _RNG_H

#include <libfam/aes.h>
#include <libfam/types.h>

/*
 * Type: Rng
 * Cryptographically secure pseudorandom number generator (CSPRNG).
 * members:
 *         AesContext ctx - internal AES-CTR state.
 * notes:
 *         Initialized with rng_init.
 *         Thread-safe as long as each thread has its own Rng instance.
 *         Uses AES-256 in CTR mode with 128-bit counter.
 */
typedef struct {
	AesContext ctx;
} Rng;

/*
 * Function: rng_init
 * Initializes a new RNG instance with a cryptographically secure seed.
 * inputs:
 *         Rng *rng - pointer to uninitialized Rng structure.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if rng is null.
 *         EIO            - if hardware RNG fails.
 * notes:
 *         Seeds from OS entropy source (getrandom).
 *         Must be called before rng_gen.
 *         Safe to call multiple times (reseeds).
 *         Opaque seeding mechanism — no user-provided key.
 */
i32 rng_init(Rng *rng);

/*
 * Function: rng_reseed
 * Forces a reseed from the entropy source.
 * inputs:
 *         Rng *rng - pointer to initialized Rng.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if rng is null.
 * notes:
 *         Useful for long-running processes or after fork().
 *         Does not interrupt in-progress rng_gen calls.
 */
i32 rng_reseed(Rng *rng);

/*
 * Function: rng_gen
 * Generates cryptographically secure random bytes.
 * inputs:
 *         Rng *rng  - pointer to initialized Rng.
 *         void *v   - buffer to fill with random data.
 *         u64 size  - number of bytes to generate.
 * return value: None.
 * errors: None.
 * notes:
 *         rng must be initialized with rng_init.
 *         v must not be null and must have at least size bytes.
 *         Uses AES-CTR: each call advances the counter and encrypts.
 *         Suitable for keys, nonces, salts, etc.
 *         Constant-time and side-channel resistant.
 */
void rng_gen(Rng *rng, void *v, u64 size);

#if TEST == 1
/*
 * Function: rng_test_seed
 * [TEST ONLY] Seeds the RNG with a user-provided key and IV.
 * inputs:
 *         Rng *rng         - pointer to Rng structure.
 *         u8 key[32]       - 256-bit AES key.
 *         u8 iv[16]        - 128-bit initial counter (IV).
 * return value: None.
 * errors: None.
 * notes:
 *         Only available when TEST == 1.
 *         For deterministic testing and fuzzing.
 *         Bypasses entropy source.
 *         Do not use in production.
 */
void rng_test_seed(Rng *rng, u8 key[32], u8 iv[16]);
#endif /* TEST */

#endif /* _RNG_H */
