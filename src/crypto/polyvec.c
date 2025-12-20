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

#include <libfam/dilithium_const.h>
#include <libfam/dilithium_impl.h>
#include <libfam/limits.h>
#include <libfam/storm.h>
#include <libfam/string.h>

__attribute__((aligned(32))) static const u8 POLY_CHALLENGE_DOMAIN[32] = {2, 3,
									  4};

STATIC u32 rej_uniform(i32 *a, u32 len, const u8 *buf, u32 buflen) {
	u32 ctr, pos;
	u32 t;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		t = buf[pos++];
		t |= (u32)buf[pos++] << 8;
		t |= (u32)buf[pos++] << 16;
		t &= 0x7FFFFF;

		a[ctr] = t;
		ctr += t < Q;
	}

	return ctr;
}

STATIC u32 poly_make_hint(poly *h, const poly *a0, const poly *a1) {
	u32 i, s = 0;
	for (i = 0; i < N; ++i) {
		h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
		s += h->coeffs[i];
	}
	return s;
}

STATIC void polyw1_pack(u8 *r, const poly *a) {
	u32 i;
	for (i = 0; i < N / 4; ++i) {
		r[3 * i + 0] = a->coeffs[4 * i + 0];
		r[3 * i + 0] |= a->coeffs[4 * i + 1] << 6;
		r[3 * i + 1] = a->coeffs[4 * i + 1] >> 2;
		r[3 * i + 1] |= a->coeffs[4 * i + 2] << 4;
		r[3 * i + 2] = a->coeffs[4 * i + 2] >> 4;
		r[3 * i + 2] |= a->coeffs[4 * i + 3] << 2;
	}
}

#define POLY_UNIFORM_NBLOCKS \
	((768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES)
STATIC void poly_uniform(poly *a, StormContext *ctx) {
	static u64 value = U64_MAX / 2;
	u32 ctr = 0;
	__attribute__((aligned(32))) u8 buf[32];
	for (u32 i = 0; i < 32 / 8; i++)
		((u64 *)buf)[i] = (i + value) * 0x9E3779B97F4A7C15ULL;

	while (ctr < N) {
		storm_next_block(ctx, buf);
		ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, 32);
	}
}

STATIC void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
#ifdef USE_AVX2
	pointwise_avx((void *)c, (void *)a, (void *)b, qdata.vec);
#else
	u32 i;
	for (i = 0; i < N; ++i)
		c->coeffs[i] =
		    montgomery_reduce((i64)a->coeffs[i] * b->coeffs[i]);
#endif /* USE_AVX2 */
}

STATIC void poly_power2round(poly *a1, poly *a0, const poly *a) {
	u32 i;
	for (i = 0; i < N; ++i)
		a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

STATIC int poly_chknorm(const poly *a, i32 B) {
	u32 i;
	i32 t;

	if (B > (Q - 1) / 8) return 1;

	for (i = 0; i < N; ++i) {
		t = a->coeffs[i] >> 31;
		t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

		if (t >= B) {
			return 1;
		}
	}

	return 0;
}

STATIC void poly_use_hint(poly *b, const poly *a, const poly *h) {
	u32 i;
	for (i = 0; i < N; ++i)
		b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
}

STATIC void poly_uniform_gamma1(poly *a, StormContext *ctx, u64 nonce) {
	__attribute__((aligned(32))) u8 buf[704] = {0};

	((u64 *)buf)[0] ^= nonce;
	for (u32 i = 0; i < 704; i += 32) storm_next_block(ctx, buf + i);

	polyz_unpack(a, buf);
}

static u32 rej_eta(i32 *a, u32 len, const u8 *buf, u32 buflen) {
	u32 ctr, pos;
	u32 t0, t1;
	ctr = pos = 0;
	while (ctr < len && pos < buflen) {
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;

		if (t0 < 15) {
			t0 = t0 - (205 * t0 >> 10) * 5;
			a[ctr++] = 2 - t0;
		}
		if (t1 < 15 && ctr < len) {
			t1 = t1 - (205 * t1 >> 10) * 5;
			a[ctr++] = 2 - t1;
		}
	}

	return ctr;
}

#define POLY_UNIFORM_ETA_NBLOCKS \
	((136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
void poly_uniform_eta(poly *a, StormContext *ctx) {
	static u64 value = U64_MAX / 2;
	u32 ctr = 0;
	__attribute__((aligned(32))) u8 buf[32];
	for (u32 i = 0; i < 32 >> 3; i++)
		((u64 *)buf)[i] = (i + value) * 0x9E3779B97F4A7C15ULL;

	while (ctr < N) {
		storm_next_block(ctx, buf);
		ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, 32);
	}
}

void poly_decompose(poly *a1, poly *a0, const poly *a) {
	u32 i;
	for (i = 0; i < N; ++i)
		a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
}

void poly_challenge(poly *c, const u8 seed[CTILDEBYTES]) {
	u32 i, b, pos;
	u64 signs;
	__attribute__((aligned(32))) u8 buf[32] = {0};
	StormContext state;

	storm_init(&state, POLY_CHALLENGE_DOMAIN);
	fastmemcpy(buf, seed, 32);
	storm_next_block(&state, buf);

	signs = 0;
	for (i = 0; i < 8; ++i) signs |= (u64)buf[i] << 8 * i;
	pos = 8;

	fastmemset(c->coeffs, 0, sizeof(c->coeffs));
	for (i = N - TAU; i < N; ++i) {
		do {
			if (pos >= 32) {
				storm_next_block(&state, buf);
				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);
		signs >>= 1;
	}
}

void polyvec_matrix_expand(polyvec mat[K], const u8 rho[SEEDBYTES]) {
	u32 i, j;
	StormContext ctx;
	storm_init(&ctx, rho);

	for (i = 0; i < K; ++i)
		for (j = 0; j < K; ++j) poly_uniform(&mat[i].vec[j], &ctx);
}

void polyvec_matrix_pointwise_montgomery(polyvec *t, const polyvec mat[K],
					 const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		polyvec_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

void polyvec_uniform_gamma1(polyvec *v, const u8 seed[CRHBYTES], u64 nonce) {
	u32 i;
	StormContext ctx;
	storm_init(&ctx, seed);

	for (i = 0; i < K; ++i)
		poly_uniform_gamma1(&v->vec[i], &ctx, K * nonce + i);
}

void polyvec_ntt(polyvec *v) {
	for (u32 i = 0; i < K; ++i) ntt(v->vec[i].coeffs);
}

void polyvec_invntt_tomont(polyvec *v) {
	for (u32 i = 0; i < K; ++i) invntt_tomont(v->vec[i].coeffs);
}

void polyvec_pointwise_acc_montgomery(poly *w, const polyvec *u,
				      const polyvec *v) {
	poly t;

	poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (u32 i = 1; i < K; ++i) {
		poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
		for (u32 j = 0; j < N; ++j)
			w->coeffs[j] = w->coeffs[j] + t.coeffs[j];
	}
}

int polyvec_chknorm(const polyvec *v, i32 bound) {
	u32 i;

	for (i = 0; i < K; ++i)
		if (poly_chknorm(&v->vec[i], bound)) return 1;

	return 0;
}

void polyvec_uniform_eta(polyvec *v, const u8 seed[CRHBYTES], u16 nonce) {
	__attribute__((aligned(32))) u8 nonce_buf[32] = {0};
	u32 i;
	StormContext ctx;
	storm_init(&ctx, seed);
	fastmemcpy(nonce_buf, &nonce, sizeof(u16));
	storm_next_block(&ctx, nonce_buf);
	for (i = 0; i < K; ++i) poly_uniform_eta(&v->vec[i], &ctx);
}

void polyvec_reduce(polyvec *v) {
	for (u32 i = 0; i < K; ++i)
		for (u32 j = 0; j < N; ++j)
			v->vec[i].coeffs[j] = reduce32(v->vec[i].coeffs[j]);
}

void polyvec_caddq(polyvec *v) {
	for (u32 i = 0; i < K; ++i)
		for (u32 j = 0; j < N; ++j)
			v->vec[i].coeffs[j] = caddq(v->vec[i].coeffs[j]);
}

void polyvec_add(polyvec *w, const polyvec *u, const polyvec *v) {
	for (u32 i = 0; i < K; ++i)
		for (u32 j = 0; j < N; ++j)
			w->vec[i].coeffs[j] =
			    u->vec[i].coeffs[j] + v->vec[i].coeffs[j];
}

void polyvec_sub(polyvec *w, const polyvec *u, const polyvec *v) {
	for (u32 i = 0; i < K; ++i)
		for (u32 j = 0; j < N; ++j)
			w->vec[i].coeffs[j] =
			    u->vec[i].coeffs[j] - v->vec[i].coeffs[j];
}

void polyvec_shiftl(polyvec *v) {
	for (u32 i = 0; i < K; i++)
		for (u32 j = 0; j < N; j++) v->vec[i].coeffs[j] <<= D;
}

void polyvec_pointwise_poly_montgomery(polyvec *r, const poly *a,
				       const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

void polyvec_power2round(polyvec *v1, polyvec *v0, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyvec_decompose(polyvec *v1, polyvec *v0, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

u32 polyvec_make_hint(polyvec *h, const polyvec *v0, const polyvec *v1) {
	u32 i, s = 0;

	for (i = 0; i < K; ++i)
		s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

	return s;
}

void polyvec_use_hint(polyvec *w, const polyvec *u, const polyvec *h) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyvec_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyvec *w1) {
	u32 i;

	for (i = 0; i < K; ++i)
		polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
}
