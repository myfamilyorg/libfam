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

#ifndef _KEM_H
#define _KEM_H

#include <libfam/rng.h>
#include <libfam/types.h>

#define KEM_SECKEY_SIZE 1632
#define KEM_PUBKEY_SIZE 800
#define KEM_SS_SIZE 32
#define KEM_CT_SIZE 768

typedef struct {
	__attribute__((aligned(32))) u8 data[KEM_SECKEY_SIZE];
} KemSecKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[KEM_PUBKEY_SIZE];
} KemPubKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[KEM_CT_SIZE];
} KemCipherText;

typedef struct {
	__attribute__((aligned(32))) u8 data[KEM_SS_SIZE];
} KemSharedSecret;

i32 pqcrystals_kyber512_ref_keypair(u8 *pk, u8 *sk, Rng *rng);
i32 pqcrystals_kyber512_ref_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);
i32 pqcrystals_kyber512_ref_dec(u8 *ss, const u8 *ct, const u8 *sk);
i32 pqcrystals_kyber512_avx2_keypair(u8 *pk, u8 *sk, Rng *rng);
i32 pqcrystals_kyber512_avx2_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng);
i32 pqcrystals_kyber512_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);

static inline void keypair(KemPubKey *pk, KemSecKey *sk, Rng *rng) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_keypair(pk->data, sk->data, rng);
#else
	pqcrystals_kyber512_ref_keypair(pk->data, sk->data, rng);
#endif
}

static inline void enc(KemCipherText *ct, KemSharedSecret *ss,
		       const KemPubKey *pk, Rng *rng) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_enc(ct->data, ss->data, pk->data, rng);
#else
	pqcrystals_kyber512_ref_enc(ct->data, ss->data, pk->data, rng);
#endif
}

static inline void dec(KemSharedSecret *ss, const KemCipherText *ct,
		       const KemSecKey *sk) {
#ifdef __AVX2__
	pqcrystals_kyber512_avx2_dec(ss->data, ct->data, sk->data);
#else
	pqcrystals_kyber512_ref_dec(ss->data, ct->data, sk->data);
#endif
}

#endif /* _KEM_H */
