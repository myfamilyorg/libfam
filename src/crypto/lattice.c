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

STATIC i32 mod_q(i64 x) {
	i32 r = (i32)x;
	if (r >= LATTICE_Q) r -= LATTICE_Q;
	if (r < -LATTICE_Q / 2) r += LATTICE_Q;
	return r;
}

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
		i64 sum = (i64)u->coeffs[i] + v->coeffs[i];
		w->coeffs[i] = mod_q(sum);
	}
}

STATIC void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
	for (int i = 0; i < LATTICE_L; i++) {
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

STATIC void poly_pointwise_mul(poly *w, const poly *u, const poly *v) {
	for (int i = 0; i < LATTICE_N; i++) {
		i64 prod = (i64)u->coeffs[i] * v->coeffs[i];
		w->coeffs[i] = mod_q(prod);
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

STATIC void polyvecl_add_poly(polyvecl *w, const poly *p) {
	for (u32 i = 0; i < LATTICE_L; i++) {
		poly_add(&w->vec[i], &w->vec[i], p);
	}
}

STATIC void polyvecl_decompose(polyvecl *t1, polyvecl *t0, const polyvecl *t) {
	for (u32 i = 0; i < LATTICE_L; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 a = t->vec[i].coeffs[j];
			if (a < 0) a += LATTICE_Q;

			i32 a0 = a & 0x1FFF;
			i32 a1 = (a - a0) >> 13;

			if (a0 > 4096) {
				a0 -= 8192;
				a1 += 1;
			}

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

		/*
		println(
		    "=== MATRIX A DEBUG (first row, first 8 coeffs) (sign) "
		    "===");*/
		/*
		for (int j = 0; j < 8; j++) {
			println("A[0][{}] = {}", j, A[0].vec[0].coeffs[j]);
		}
		*/

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

			/*
			println("val={},upper={},lower={}", val, LATTICE_Q / 2,
				-LATTICE_Q / 2);
				*/

			if (val >= LATTICE_Q / 2 || val <= -LATTICE_Q / 2) {
				/*
				println(
				    "+===================================SETH=="
				    "=======");
				    */
				h->vec[k].coeffs[j] = 1;
			}
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
	LatticePKImpl *impl = (void *)pk->data;
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
	LatticeSkeyExpanded exp;

	lattice_skey_expand(sk, &exp);

	/*
	println("=== EXPANDED KEY DEBUG ===");
	println("rho[0..7]:  {} {} {} {} {} {} {} {}", exp.rho[0], exp.rho[1],
		exp.rho[2], exp.rho[3], exp.rho[4], exp.rho[5], exp.rho[6],
		exp.rho[7]);
	println("tr[0..7]:   {} {} {} {} {} {} {} {}", exp.tr[0], exp.tr[1],
		exp.tr[2], exp.tr[3], exp.tr[4], exp.tr[5], exp.tr[6],
		exp.tr[7]);
	println("t1[0][0..3]: {} {} {} {}", exp.t1.vec[0].coeffs[0],
		exp.t1.vec[0].coeffs[1], exp.t1.vec[0].coeffs[2],
		exp.t1.vec[0].coeffs[3]);
	println("s1[0][0..3]: {} {} {} {}", exp.s1.vec[0].coeffs[0],
		exp.s1.vec[0].coeffs[1], exp.s1.vec[0].coeffs[2],
		exp.s1.vec[0].coeffs[3]);
	println("s2[0][0..3]: {} {} {} {}", exp.s2.vec[0].coeffs[0],
		exp.s2.vec[0].coeffs[1], exp.s2.vec[0].coeffs[2],
		exp.s2.vec[0].coeffs[3]);
	println("=== END EXPANDED KEY ===");
	*/

	{
		__attribute__((aligned(
		    32))) u8 input[32 + sizeof(polyvecl) + MESSAGE_SIZE];
		fastmemcpy(input, exp.rho, 32);
		fastmemcpy(input + 32, &exp.t1, sizeof(polyvecl));
		fastmemcpy(input + 32 + sizeof(polyvecl), message,
			   MESSAGE_SIZE);

		StormContext ctx;
		storm_init(&ctx, ZERO_SEED);
		for (u32 i = 0; i < sizeof(input); i += 32)
			storm_xcrypt_buffer(&ctx, input + i);
		storm_xcrypt_buffer(&ctx, c_tilde);
		storm_xcrypt_buffer(&ctx, c_tilde + 32);
	}

	poly c;
	expand_challenge(&c, c_tilde);

	/*
	println("c_tilde[0..7]: {} {} {} {} {} {} {} {}", c_tilde[0],
		c_tilde[1], c_tilde[2], c_tilde[3], c_tilde[4], c_tilde[5],
		c_tilde[6], c_tilde[7]);

	println("=== SIGN: sparse c (first 8 coeffs) ===");
	for (int i = 0; i < 8; i++) {
		println("c[{}] = {}", i, c.coeffs[i]);
	}
	*/

	polyvecl z;

	do {
		StormContext y_ctx;
		polyvecl y;

		storm_init(&y_ctx, sk->data);
		storm_xcrypt_buffer(&y_ctx, nonce);
		(*(u64 *)nonce)++;

		for (u32 i = 0; i < LATTICE_L; i++)
			poly_uniform_gamma1(&y.vec[i], &y_ctx);

		/*
		println("=== DEBUG: y.vec[0] first 8 coeffs ===");
		for (int j = 0; j < 8; j++)
			println("y[0][{}] = {}", j, y.vec[0].coeffs[j]);

		println("=== DEBUG: c·s1.vec[0] first 8 coeffs ===");
		i32 cs1[8] = {0};
		for (int j = 0; j < 8; j++) {
			if (c.coeffs[j] == 1) cs1[j] = exp.s1.vec[0].coeffs[j];
			if (c.coeffs[j] == -1)
				cs1[j] = -exp.s1.vec[0].coeffs[j];
			println("c·s1[{}] = {}  (c={} s1={})", j, cs1[j],
				c.coeffs[j], exp.s1.vec[0].coeffs[j]);
		}
		*/

		for (u32 i = 0; i < LATTICE_L; i++) {
			for (u32 j = 0; j < LATTICE_N; j++) {
				i64 val = y.vec[i].coeffs[j];
				if (c.coeffs[j] == 1)
					val += exp.s1.vec[i].coeffs[j];
				if (c.coeffs[j] == -1)
					val -= exp.s1.vec[i].coeffs[j];
				z.vec[i].coeffs[j] = (i32)val;
			}
		}
	} while (polyvecl_infinity_norm(&z) >= (LATTICE_GAMMA1 - LATTICE_BETA));

	/*
	println("=== SIGN: First 8 coeffs of z.vec[0] ===");
	for (int j = 0; j < 8; j++) {
		println("z[0][{}] = {}", j, z.vec[0].coeffs[j]);
	}
	println("||z||_inf = {}", polyvecl_infinity_norm(&z));
	*/

	polyveck h;

	/*
	println("=== t0 (first vector, first 8 coeffs) ===");
	for (int j = 0; j < 8; j++) {
		println("t0.vec[0].coeffs[{}] = {}", j,
			exp.t0.vec[0].coeffs[j]);
	}

	println("=== s2 (first vector, first 8 coeffs) ===");
	for (int j = 0; j < 8; j++) {
		println("s2.vec[0].coeffs[{}] = {}", j,
			exp.s2.vec[0].coeffs[j]);
	}*/

	polyveck_make_hint(&h, &exp.t0, &c, &exp.s2);

	/*
	println("=== SIGN: First 8 hint bits (vector 0) ===");
	for (int j = 0; j < 8; j++) {
		println("h[0][{}] = {}", j, h.vec[0].coeffs[j]);
	}
	*/

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

	/* 2. Recompute expected c̃ = H(ρ ‖ t₁ ‖ message) */
	u8 expected_c_tilde[64] = {0};
	{
		u8 input[32 + sizeof(polyvecl) + MESSAGE_SIZE];
		fastmemcpy(input, pk->rho, 32);
		fastmemcpy(input + 32, &pk->t1, sizeof(polyvecl));
		fastmemcpy(input + 32 + sizeof(polyvecl), message,
			   MESSAGE_SIZE);

		StormContext ctx;
		storm_init(&ctx, ZERO_SEED);
		for (u32 i = 0; i < sizeof(input); i += 32)
			storm_xcrypt_buffer(&ctx, input + i);
		storm_xcrypt_buffer(&ctx, expected_c_tilde);
		storm_xcrypt_buffer(&ctx, expected_c_tilde + 32);
	}

	if (memcmp(c_tilde, expected_c_tilde, 64) != 0) return 0;

	polyveck Az;
	{
		polyvecm A[LATTICE_K];
		expand_mat(A, pk->rho);

		/*
		println("=== MATRIX A DEBUG (first row, first 8 coeffs) ===");
		for (int j = 0; j < 8; j++) {
			println("A[0][{}] = {}", j, A[0].vec[0].coeffs[j]);
		}
		*/

		fastmemset(&Az, 0, sizeof(Az));
		for (u32 i = 0; i < LATTICE_K; i++) {
			for (u32 j = 0; j < LATTICE_L; j++) {
				poly temp;
				poly_pointwise_mul(&temp, &A[i].vec[j],
						   &z->vec[j]);
				poly_add(&Az.vec[i], &Az.vec[i], &temp);
			}
		}
	}

	poly c;
	expand_challenge(&c, c_tilde);

	/*
	println("=== VERIFY: sparse c (first 8 coeffs) ===");
	for (int i = 0; i < 8; i++) {
		println("c[{}] = {}", i, c.coeffs[i]);
	}
	*/

	polyveck w;
	for (u32 i = 0; i < LATTICE_K; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i64 val = Az.vec[i].coeffs[j];
			if (c.coeffs[j] == 1)
				val -= pk->t1.vec[i].coeffs[j];
			else if (c.coeffs[j] == -1)
				val += pk->t1.vec[i].coeffs[j];
			w.vec[i].coeffs[j] = mod_q((i32)val);
		}
	}

	/*
	println("=== FINAL CHECK (first 4 coeffs of first vector) ===");
	for (int j = 0; j < 4; j++) {
		i32 val = w.vec[0].coeffs[j];
		i32 hinted = val;

		if (h->vec[0].coeffs[j]) {
			if (val >= 0)
				hinted -= LATTICE_Q;
			else
				hinted += LATTICE_Q;
		}

		println("w[0][{}]={} → hinted={}  expected t1={}  match={}", j,
			val, hinted, pk->t1.vec[0].coeffs[j],
			(hinted == pk->t1.vec[0].coeffs[j]) ? "YES" : "NO");
	}
	*/

	for (u32 k = 0; k < LATTICE_K; k++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 val = w.vec[k].coeffs[j];

			if (h->vec[k].coeffs[j]) {
				if (val >= 0)
					val -= LATTICE_Q;
				else
					val += LATTICE_Q;
			}

			/*
			println("=== VERIFY: First 8 hint bits (vector 0) ===");
			for (int j = 0; j < 8; j++) {
				println("h[0][{}] = {}", j,
					h->vec[0].coeffs[j]);
			}

			println("val={},pk={}", val, pk->t1.vec[k].coeffs[j]);

			println("=== FINAL VERIFICATION PROOF ===");
			*/

			// Pick one coefficient — index 0 of vector 0
			/*
			u32 k = 0, j = 0;
			i32 az = Az.vec[k].coeffs[j];
			i32 ct1 = (c.coeffs[j] == 1) ? pk->t1.vec[k].coeffs[j]
				  : (c.coeffs[j] == -1)
				      ? -pk->t1.vec[k].coeffs[j]
				      : 0;
			i32 hint_adjust =
			    h->vec[k].coeffs[j]
				? (az >= 0 ? -LATTICE_Q : LATTICE_Q)
				: 0;

			i32 left = az;
			i32 right = pk->t1.vec[k].coeffs[j] + ct1 + hint_adjust;

			println("A·z[0][0]       = {}", left);
			println("t1 + c·t1 + h*Q = {} + {} + {} = {}",
				pk->t1.vec[k].coeffs[j], ct1, hint_adjust,
				right);
			println("MATCH? {}", left == right ? "YES" : "NO");

			if (left == right) {
				println(
				    "VERIFICATION WOULD PASS IF THIS WAS THE "
				    "ONLY COEFF");
			} else {
				println("VERIFICATION FAILS HERE");
			}
			*/

			if (val != pk->t1.vec[k].coeffs[j]) return 0;
		}
	}

	return 1;  // Valid signature
}
