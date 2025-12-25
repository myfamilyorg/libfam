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

#ifndef _SIGN_H
#define _SIGN_H

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#include <libfam/format.h>
#include <libfam/types.h>

#define DILITHIUM_SECRETKEY_SIZE 2560
#define DILITHIUM_PUBLICKEY_SIZE 1312
#define DILITHIUM_SIGNATURE_SIZE 2420

i32 pqcrystals_dilithium2_ref_keypair(u8 *pk, u8 *sk);
i32 pqcrystals_dilithium2_ref_signature(u8 *sig, u64 *siglen, const u8 *m,
					u64 mlen, const u8 *ctx, u64 ctxlen,
					const u8 *sk);
i32 pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
				     const uint8_t *m, size_t mlen,
				     const uint8_t *ctx, size_t ctxlen,
				     const uint8_t *pk);

i32 pqcrystals_dilithium2_avx2_keypair(u8 *pk, u8 *sk);
i32 pqcrystals_dilithium2_avx2_signature(u8 *sig, u64 *siglen, const u8 *m,
					 u64 mlen, const u8 *ctx, u64 ctxlen,
					 const u8 *sk);
i32 pqcrystals_dilithium2_avx2_verify(const uint8_t *sig, size_t siglen,
				      const uint8_t *m, size_t mlen,
				      const uint8_t *ctx, size_t ctxlen,
				      const uint8_t *pk);

typedef struct {
	__attribute__((aligned(32))) u8 data[DILITHIUM_SECRETKEY_SIZE];
} SecretKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[DILITHIUM_PUBLICKEY_SIZE];
} PublicKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[DILITHIUM_SIGNATURE_SIZE];
} Signature;

static inline void keyfrom(const u8 seed[32], SecretKey *sk, PublicKey *pk) {
#ifdef USE_AVX2
	pqcrystals_dilithium2_avx2_keypair(pk->data, sk->data);
#else
	pqcrystals_dilithium2_ref_keypair(pk->data, sk->data);
#endif
}
static inline void sign(const u8 msg[32], const SecretKey *sk, Signature *out) {
	u64 siglen;
#ifdef USE_AVX2
	pqcrystals_dilithium2_ref_signature(out->data, &siglen, msg, 32, NULL,
					    0, sk->data);
#else
	pqcrystals_dilithium2_ref_signature(out->data, &siglen, msg, 32, NULL,
					    0, sk->data);
#endif
}
i32 verify(const u8 msg[32], const PublicKey *pk, const Signature *sig) {
#ifdef USE_AVX2
	return pqcrystals_dilithium2_avx2_verify(sig->data, 2420, msg, 32, NULL,
						 0, pk->data);
#else
	return pqcrystals_dilithium2_ref_verify(sig->data, 2420, msg, 32, NULL,
						0, pk->data);
#endif
}

#endif /* _SIGN_H */
