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

#include <dilithium/params.h>
#include <dilithium/poly.h>
#include <dilithium/polyvec.h>
#include <libfam/types.h>

void dilithium_keyfrom(u8 *sk, u8 *pk, u8 seed[32]);
i32 dilithium_sign(u8 *sm, u64 *smlen, const u8 *m, u64 mlen, const u8 *ctx,
		   u64 ctxlen, const u8 *sk);
i32 dilithium_verify(u8 *m, u64 *mlen, const u8 *sm, u64 smlen, const u8 *ctx,
		     u64 ctxlen, const u8 *pk);

#endif /* _SIGN_H */
