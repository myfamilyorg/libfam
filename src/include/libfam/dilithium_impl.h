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

#ifndef _DILITHIUM_IMPL
#define _DILITHIUM_IMPL

#include <libfam/dilithium_const.h>
#include <libfam/storm.h>
#include <libfam/types.h>

typedef struct {
	__attribute__((aligned(32))) i32 coeffs[N];
} poly __attribute__((aligned(32)));

typedef struct {
	poly vec[K];
} polyvec;

i32 montgomery_reduce(i64 a);
i32 reduce32(i32 a);
i32 caddq(i32 a);
i32 freeze(i32 a);
void ntt(i32 a[N]);
void invntt_tomont(i32 a[N]);
i32 power2round(i32 *a0, i32 a);
i32 decompose(i32 *a0, i32 a);
u32 make_hint(i32 a0, i32 a1);
i32 use_hint(i32 a, u32 hint);

void poly_reduce(poly *a);
void poly_caddq(poly *a);

void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);
void poly_shiftl(poly *a);

void poly_ntt(poly *a);
void poly_invntt_tomont(poly *a);

void poly_decompose(poly *a1, poly *a0, const poly *a);

void poly_uniform_eta(poly *a, StormContext *ctx);
void poly_challenge(poly *c, const u8 seed[CTILDEBYTES]);

void polyvec_uniform_gamma1(polyvec *v, const u8 seed[CRHBYTES], u64 nonce);

void polyvec_reduce(polyvec *v);

void polyvec_pointwise_poly_montgomery(polyvec *r, const poly *a,
				       const polyvec *v);
void polyvec_pointwise_acc_montgomery(poly *w, const polyvec *u,
				      const polyvec *v);

int polyvec_chknorm(const polyvec *v, i32 B);

void polyvec_uniform_eta(polyvec *v, const u8 seed[CRHBYTES], u16 nonce);

void polyvec_caddq(polyvec *v);

void polyvec_add(polyvec *w, const polyvec *u, const polyvec *v);
void polyvec_sub(polyvec *w, const polyvec *u, const polyvec *v);
void polyvec_shiftl(polyvec *v);

void polyvec_ntt(polyvec *v);
void polyvec_invntt_tomont(polyvec *v);
void polyvec_pointwise_poly_montgomery(polyvec *r, const poly *a,
				       const polyvec *v);

int polyvec_chknorm(const polyvec *v, i32 B);

void polyvec_power2round(polyvec *v1, polyvec *v0, const polyvec *v);
void polyvec_decompose(polyvec *v1, polyvec *v0, const polyvec *v);
u32 polyvec_make_hint(polyvec *h, const polyvec *v0, const polyvec *v1);
void polyvec_use_hint(polyvec *w, const polyvec *v, const polyvec *h);

void polyvec_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyvec *w1);

void polyvec_matrix_expand(polyvec mat[K], const u8 rho[SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(polyvec *t, const polyvec mat[K],
					 const polyvec *v);

void polyeta_pack(u8 *r, const poly *a);
void polyeta_unpack(poly *r, const u8 *a);

void polyt1_pack(u8 *r, const poly *a);
void polyt1_unpack(poly *r, const u8 *a);

void polyt0_pack(u8 *r, const poly *a);
void polyt0_unpack(poly *r, const u8 *a);

void polyz_pack(u8 *r, const poly *a);
void polyz_unpack(poly *r, const u8 *a);

void dpack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	      const polyvec *t1);

void dpack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	      const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyvec *t0,
	      const polyvec *s1, const polyvec *s2);

void dpack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvec *z,
	       const polyvec *h);

void dunpack_pk(u8 rho[SEEDBYTES], polyvec *t1,
		const u8 pk[CRYPTO_PUBLICKEYBYTES]);

void dunpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
		polyvec *t0, polyvec *s1, polyvec *s2,
		const u8 sk[CRYPTO_SECRETKEYBYTES]);

int dunpack_sig(u8 c[CTILDEBYTES], polyvec *z, polyvec *h,
		const u8 sig[CRYPTO_BYTES]);

#endif /* _DILITHIUM_IMPL */
