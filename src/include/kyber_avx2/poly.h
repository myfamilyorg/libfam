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

#ifndef POLY_H
#define POLY_H

#include <kyber_avx2/align.h>
#include <kyber_common/params.h>

typedef ALIGNED_INT16(KYBER_N) poly;

#define poly_compress KYBER_NAMESPACE(poly_compress)
void poly_compress(u8 r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);
#define poly_decompress KYBER_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const u8 a[KYBER_POLYCOMPRESSEDBYTES]);

#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(u8 r[KYBER_POLYBYTES], const poly *a);
#define poly_frombytes KYBER_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const u8 a[KYBER_POLYBYTES]);

#define poly_frommsg KYBER_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const u8 msg[KYBER_INDCPA_MSGBYTES]);
#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
void poly_tomsg(u8 msg[KYBER_INDCPA_MSGBYTES], const poly *r);

#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);

#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce);

#ifndef KYBER_90S
#define poly_getnoise_eta1_4x KYBER_NAMESPACE(poly_getnoise_eta2_4x)
void poly_getnoise_eta1_4x(poly *r0, poly *r1, poly *r2, poly *r3,
			   const u8 seed[32], u8 nonce0, u8 nonce1, u8 nonce2,
			   u8 nonce3);

#if KYBER_K == 2
#define poly_getnoise_eta1122_4x KYBER_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly *r0, poly *r1, poly *r2, poly *r3,
			      const u8 seed[32], u8 nonce0, u8 nonce1,
			      u8 nonce2, u8 nonce3);
#endif
#endif

#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_nttunpack KYBER_NAMESPACE(poly_nttunpack)
void poly_nttunpack(poly *r);
#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
#define poly_tomont KYBER_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
