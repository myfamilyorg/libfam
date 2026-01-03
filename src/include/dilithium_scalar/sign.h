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

#ifndef SIGN_H
#define SIGN_H

#include <dilithium_scalar/params.h>
#include <dilithium_scalar/poly.h>
#include <dilithium_scalar/polyvec.h>
#include <libfam/rng.h>

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(u8 *pk, u8 *sk, const u8 seed[32]);

#define crypto_sign_signature_internal DILITHIUM_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
				   const u8 *pre, u64 prelen,
				   const u8 rnd[RNDBYTES], const u8 *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(u8 *sig, u64 *siglen, const u8 *m, u64 mlen,
			  const u8 *ctx, u64 ctxlen, const u8 *sk, Rng *rng);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(u8 *sm, u64 *smlen, const u8 *m, u64 mlen, const u8 *ctx,
		u64 ctxlen, const u8 *sk, Rng *rng);

#define crypto_sign_verify_internal DILITHIUM_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const u8 *sig, u64 siglen, const u8 *m,
				u64 mlen, const u8 *pre, u64 prelen,
				const u8 *pk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const u8 *sig, u64 siglen, const u8 *m, u64 mlen,
		       const u8 *ctx, u64 ctxlen, const u8 *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(u8 *m, u64 *mlen, const u8 *sm, u64 smlen, const u8 *ctx,
		     u64 ctxlen, const u8 *pk);

#endif
