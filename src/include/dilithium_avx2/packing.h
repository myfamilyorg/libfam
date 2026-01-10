/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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

#ifndef PACKING_H
#define PACKING_H

#include <dilithium_avx2/params.h>
#include <dilithium_avx2/polyvec.h>

#define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	     const polyveck *t1);

#define pack_sk DILITHIUM_NAMESPACE(pack_sk)
void pack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	     const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyveck *t0,
	     const polyvecl *s1, const polyveck *s2);

#define pack_sig DILITHIUM_NAMESPACE(pack_sig)
void pack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvecl *z,
	      const polyveck *h);

#define unpack_pk DILITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(u8 rho[SEEDBYTES], polyveck *t1,
	       const u8 pk[CRYPTO_PUBLICKEYBYTES]);

#define unpack_sk DILITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
	       polyveck *t0, polyvecl *s1, polyveck *s2,
	       const u8 sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sig DILITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(u8 c[CTILDEBYTES], polyvecl *z, polyveck *h,
	       const u8 sig[CRYPTO_BYTES]);

#endif
