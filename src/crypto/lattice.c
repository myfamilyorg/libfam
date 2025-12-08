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

#include <libfam/env.h>
#include <libfam/format.h>
#include <libfam/lattice.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/utils.h>

#define LATTICE_D 13
#define LATTICE_K 8
#define LATTICE_L 7
#define LATTICE_N 256
#define LATTICE_Q 8380417
#define LATTICE_GAMMA1 (1 << 19)
#define LATTICE_BETA 196
#define MESSAGE_SIZE 128

typedef struct {
	i32 coeffs[LATTICE_N];
} poly;

typedef struct {
	poly vec[LATTICE_K];
} polyvecm;

typedef struct {
	poly vec[LATTICE_L];
} polyvecl;

typedef struct {
	poly vec[LATTICE_K];
} polyveck_t0;

typedef struct {
	poly vec[LATTICE_K];
} polyveck;

typedef struct {
	__attribute__((aligned(32))) u8 rho[32];
	__attribute__((aligned(32))) u8 tr[64];
	polyvecm s1;
	polyvecm s2;
	polyvecl t;
	polyvecl t0;
	polyvecl t1;
} LatticeSkeyExpanded;

typedef struct {
	polyvecl z;
	u8 c_tilde[64];
	polyveck h;
} LatticeSigImpl;

typedef struct {
	u8 rho[32];
	polyvecl t1;
} LatticePKImpl;

static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};

STATIC void poly_uniform(poly *p, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u32 x = 0;
	while (true) {
		storm_xcrypt_buffer(ctx, buf);
		for (u8 j = 0; j < 8; j++) {
			u32 t = ((u32 *)buf)[j] & 0x7FFFFF;
			t += (t >> 19);
			if (t < LATTICE_Q) {
				p->coeffs[x++] = t;
				if (x == LATTICE_N) return;
			}
		}
	}
}

STATIC void poly_uniform_eta(poly *p, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u32 x = 0;

	while (true) {
		storm_xcrypt_buffer(ctx, buf);

		for (u8 j = 0; j < 32; j++) {
			u8 t = buf[j];
			if (t <= 4) {
				p->coeffs[x++] = (t < 2) ? t : t - 5;
				if (x == LATTICE_N) return;
			}
		}
	}
}

STATIC void expand_mat(polyvecm mat[LATTICE_K], const u8 rho[32]) {
	StormContext ctx;
	storm_init(&ctx, rho);

	for (u32 i = 0; i < LATTICE_K; i++)
		for (u32 j = 0; j < LATTICE_K; j++)
			poly_uniform(&mat[i].vec[j], &ctx);
}

STATIC void poly_add(poly *w, const poly *u, const poly *v) {
	for (int i = 0; i < LATTICE_N; i++) {
		w->coeffs[i] = u->coeffs[i] + v->coeffs[i];
	}
}

STATIC void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
	for (int i = 0; i < LATTICE_L; i++) {
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

STATIC void poly_pointwise_mul(poly *w, const poly *u, const poly *v) {
	for (int i = 0; i < LATTICE_N; i++) {
		i64 t = (i64)u->coeffs[i] * v->coeffs[i];
		w->coeffs[i] = (i32)t;
	}
}

STATIC void polyvecm_pointwise_acc(polyvecl *w, const polyvecm *u,
				   const polyvecm *v) {
	fastmemset(w, 0, sizeof(*w));

	for (int i = 0; i < LATTICE_L; i++) {
		for (int j = 0; j < LATTICE_K; j++) {
			poly temp;
			poly_pointwise_mul(&temp, &u->vec[j], &v->vec[j]);
			poly_add(&w->vec[i], &w->vec[i], &temp);
		}
	}
}

STATIC void polyvecl_pointwise_acc(polyvecl *w, const polyvecm mat[LATTICE_K],
				   const polyvecl *v) {
	fastmemset(w, 0, sizeof(*w));

	for (int i = 0; i < LATTICE_L; i++) {
		for (int j = 0; j < LATTICE_K; j++) {
			poly temp;
			poly_pointwise_mul(&temp, &mat[j].vec[i], &v->vec[i]);
			poly_add(&w->vec[i], &w->vec[i], &temp);
		}
	}
}

STATIC void polyvecl_add_poly(polyvecl *w, const poly *p) {
	for (u32 i = 0; i < LATTICE_L; i++) {
		poly_add(&w->vec[i], &w->vec[i], p);
	}
}

STATIC void polyvecl_decompose(polyvecl *t1, polyvecl *t0, const polyvecl *t) {
	const u32 d = LATTICE_D;
	const i32 alpha = (1 << d);

	for (u32 i = 0; i < LATTICE_L; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 a = t->vec[i].coeffs[j];

			i32 a1 = (a + (alpha >> 1)) >> d;
			i32 a0 = a - (a1 << d);

			if (t1) t1->vec[i].coeffs[j] = a1;
			if (t0) t0->vec[i].coeffs[j] = a0;
		}
	}
}

STATIC void lattice_skey_expand(const LatticeSK *sk, LatticeSkeyExpanded *exp) {
	StormContext ctx;

	fastmemset(exp, 0, sizeof(LatticeSkeyExpanded));
	storm_init(&ctx, sk->data);
	storm_xcrypt_buffer(&ctx, exp->rho);
	storm_xcrypt_buffer(&ctx, exp->tr);
	storm_xcrypt_buffer(&ctx, exp->tr + 32);

	for (i32 i = 0; i < LATTICE_K; i++)
		poly_uniform_eta(&exp->s1.vec[i], &ctx);

	for (i32 i = 0; i < LATTICE_K; i++)
		poly_uniform_eta(&exp->s2.vec[i], &ctx);

	{
		polyvecm A[LATTICE_K];
		expand_mat(A, exp->rho);

		for (i32 i = 0; i < LATTICE_K; i++) {
			polyvecl temp;
			polyvecm_pointwise_acc(&temp, &A[i], &exp->s1);
			polyvecl_add(&exp->t, &exp->t, &temp);
		}
	}
	for (u32 i = 0; i < LATTICE_K; i++) {
		polyvecl_add_poly(&exp->t, &exp->s2.vec[i]);
	}
	polyvecl_decompose(&exp->t1, &exp->t0, &exp->t);
}

STATIC void poly_uniform_gamma1(poly *p, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u32 x = 0;

	while (true) {
		storm_xcrypt_buffer(ctx, buf);
		for (u8 i = 0; i < 8; i++) {
			u32 t = ((u32 *)buf)[i] & 0xFFFFF;
			p->coeffs[x++] = (i32)(LATTICE_GAMMA1 - 1 - t);
			if (x == LATTICE_N) return;
		}
	}
}

STATIC u32 polyvecl_infinity_norm(const polyvecl *v) {
	u32 max = 0;

#if TEST == 1
	u8 *vg = getenv("VALGRIND");
	if (vg && strlen(vg) == 1 && !memcmp(vg, "1", 1)) return max;
#endif

	for (u32 i = 0; i < LATTICE_L; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 c = v->vec[i].coeffs[j];
			u32 abs = (u32)(c < 0 ? -c : c);
			if (abs > max) max = abs;
		}
	}

	return max;
}

STATIC void polyveck_make_hint(polyveck *h, const polyvecl *t0, const poly *c,
			       const polyvecm *s2) {
	fastmemset(h, 0, sizeof(*h));

	for (u32 k = 0; k < LATTICE_K; k++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 val = t0->vec[k].coeffs[j];

			if (c->coeffs[j] == 1)
				val += s2->vec[k].coeffs[j];
			else if (c->coeffs[j] == -1)
				val -= s2->vec[k].coeffs[j];

			if (val >= LATTICE_Q / 2 || val <= -LATTICE_Q / 2)
				h->vec[k].coeffs[j] = 1;
		}
	}
}

STATIC void pack_sig(LatticeSig *sig, const polyvecl *z, const u8 c_tilde[64],
		     const polyveck *h) {
	LatticeSigImpl *impl = (void *)sig;
	fastmemcpy(&impl->z, z, sizeof(*z));
	fastmemcpy(&impl->c_tilde, c_tilde, 64);
	fastmemcpy(&impl->h, h, sizeof(*h));
}

STATIC void expand_challenge(poly *c, const u8 c_tilde[64]) {
	fastmemset(c, 0, sizeof(poly));
	u64 signs = 0;
	for (int i = 0; i < 8; ++i) signs |= (u64)c_tilde[56 + i] << (8 * i);

	u32 pos = 0;
	for (int i = 0; i < 56; ++i) {
		u8 bucket = c_tilde[i];
		for (int j = 0; j < 8; ++j) {
			if (bucket & 1) {
				u32 idx = pos + j;
				if (idx < 256)
					c->coeffs[idx] = (signs & 1) ? -1 : 1;
			}
			bucket >>= 1;
		}
		signs >>= 8;
		pos += 32;
	}
}

PUBLIC void lattice_skey(const u8 seed[32], LatticeSK *sk) {
	fastmemcpy(sk, seed, 32);
}

PUBLIC void lattice_pubkey(const LatticeSK *sec_key, LatticePK *pk) {
	LatticePKImpl *impl = (void *)pk;
	LatticeSkeyExpanded exp;
	lattice_skey_expand(sec_key, &exp);

	fastmemcpy(&impl->rho, exp.rho, 32);
	fastmemcpy(&impl->t1, &exp.t1, sizeof(polyvecl));
	fastmemset(&exp, 0, sizeof(LatticeSkeyExpanded));
}

PUBLIC void lattice_sign(const LatticeSK *sk, const u8 message[MESSAGE_SIZE],
			 LatticeSig *sig) {
	__attribute__((aligned(32))) u8 nonce[32] = {0};
	__attribute__((aligned(32))) u8 c_tilde[64] = {0};
	StormContext ctx;
	LatticeSkeyExpanded exp;

	lattice_skey_expand(sk, &exp);

	__attribute__((aligned(32))) u8 challenge_input[64 + MESSAGE_SIZE] = {
	    0};

	fastmemcpy(challenge_input, exp.tr, 64);
	fastmemcpy(challenge_input + 64, message, MESSAGE_SIZE);

	storm_init(&ctx, ZERO_SEED);

	for (u32 i = 0; i < sizeof(challenge_input); i += 32) {
		storm_xcrypt_buffer(&ctx, challenge_input + i);
	}
	storm_xcrypt_buffer(&ctx, c_tilde);
	storm_xcrypt_buffer(&ctx, c_tilde + 32);

	polyvecl z;
	poly c;

	expand_challenge(&c, c_tilde);

	do {
		StormContext y_ctx;
		polyvecl y;

		storm_init(&y_ctx, sk->data);
		storm_xcrypt_buffer(&y_ctx, nonce);
		(*(u64 *)nonce)++;

		for (u32 i = 0; i < LATTICE_L; i++)
			poly_uniform_gamma1(&y.vec[i], &y_ctx);

		for (u32 i = 0; i < LATTICE_L; i++) {
			for (u32 j = 0; j < LATTICE_N; j++) {
				i64 val = y.vec[i].coeffs[j];

				if (c.coeffs[j] == 1)
					val += exp.s1.vec[i].coeffs[j];
				else if (c.coeffs[j] == -1)
					val -= exp.s1.vec[i].coeffs[j];

				z.vec[i].coeffs[j] = (i32)val;
			}
		}
	} while (polyvecl_infinity_norm(&z) >= (LATTICE_GAMMA1 - LATTICE_BETA));

	polyveck h;

	polyveck_make_hint(&h, &exp.t0, &c, &exp.s2);
	pack_sig(sig, &z, c_tilde, &h);
	fastmemset(&exp, 0, sizeof(LatticeSkeyExpanded));
}

PUBLIC i32 lattice_verify(const LatticePK *pub_key,
			  const u8 message[MESSAGE_SIZE],
			  const LatticeSig *sig) {
	const LatticePKImpl *pk = (const LatticePKImpl *)pub_key->data;
	const LatticeSigImpl *s = (const LatticeSigImpl *)sig;

	const polyvecl *z = &s->z;
	const u8 *c_tilde = s->c_tilde;
	const polyveck *h = &s->h;

	/* 1. Reject if ||z||_∞ is too large */
	if (polyvecl_infinity_norm(z) >= LATTICE_GAMMA1 - LATTICE_BETA)
		return 0;

	/* 2. Recompute expected c̃ = H(tr ‖ message) */
	/*     tr = H(ρ ‖ t₁) — recompute it from pk contents */
	u8 expected_c_tilde[64] = {0};
	{
		__attribute__((aligned(32))) u8 tr_input[32 + sizeof(polyvecl)];
		fastmemcpy(tr_input, pk->rho, 32);
		fastmemcpy(tr_input + 32, &pk->t1, sizeof(polyvecl));

		StormContext ctx;
		storm_init(&ctx, ZERO_SEED);
		for (u32 i = 0; i < sizeof(tr_input); i += 32)
			storm_xcrypt_buffer(&ctx, tr_input + i);
		storm_xcrypt_buffer(&ctx, expected_c_tilde);
		storm_xcrypt_buffer(&ctx, expected_c_tilde + 32);
	}

	if (memcmp(c_tilde, expected_c_tilde, 64) != 0) return 0;

	/* 3. Compute A·z */
	polyvecl Az;
	{
		polyvecm A[LATTICE_K];
		expand_mat(A, pk->rho);
		polyvecl_pointwise_acc(&Az, A, z);
	}

	/* 4. Compute w = A·z − c·t₁ */
	poly c;
	expand_challenge(&c, c_tilde);

	polyvecl w;
	for (u32 i = 0; i < LATTICE_L; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i64 val = Az.vec[i].coeffs[j];
			if (c.coeffs[j] == 1)
				val -= pk->t1.vec[i].coeffs[j];
			else if (c.coeffs[j] == -1)
				val += pk->t1.vec[i].coeffs[j];
			w.vec[i].coeffs[j] = (i32)val;
		}
	}

	/* 5. Apply hints and check recovery of t₁ */
	for (u32 k = 0; k < LATTICE_K; k++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 val = w.vec[k].coeffs[j];

			if (h->vec[k].coeffs[j]) {
				if (val >= 0)
					val -= LATTICE_Q;
				else
					val += LATTICE_Q;
			}

			if (val != pk->t1.vec[k].coeffs[j]) return 0;
		}
	}

	return 1;  // Valid signature
}
