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

#include <libfam/format.h>
#include <libfam/types.h>

typedef struct {
	__attribute__((aligned(32))) u8 data[3000];
} SecKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[3000];
} PubKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[3000];
} Sig;

i32 pqcrystals_dilithium2_ref_keypair(u8 *pk, u8 *sk);
i32 pqcrystals_dilithium2_ref_signature(u8 *sig, u64 *siglen, const u8 *m,
					u64 mlen, const u8 *ctx, u64 ctxlen,
					const u8 *sk);
i32 pqcrystals_dilithium2_ref_open(const u8 *m, u64 *mlen, const u8 *sm,
				   u64 smlen, const u8 *ctx, u64 ctxlen,
				   const u8 *pk);

static inline void keyfrom(PubKey *pk, SecKey *sk, const u8 seed[32]) {
	pqcrystals_dilithium2_ref_keypair(pk->data, sk->data);
}

static inline void sign(const SecKey *sk, const u8 message[32], Sig *sig) {
	u64 siglen;
	i32 res = pqcrystals_dilithium2_ref_signature(
	    sig->data, &siglen, message, 32, NULL, 0, sk->data);
	println("res={},siglen={}", res, siglen);
}

static inline i32 verify(const PubKey *pk, const u8 message[32],
			 const Sig *sig) {
	/*
	u64 mlen = 32;
	return pqcrystals_dilithium2_ref_open(message, &mlen, sig->data, 2420,
					      NULL, 0, pk->data);
					      */
	return 0;
}

#endif /* _SIGN_H */
