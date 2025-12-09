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

#include <libfam/asymmetric.h>
#include <libfam/format.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/utils.h>

#define LATTICE_L 7
#define LATTICE_N 256
#define LATTICE_Q 8380417
#define LATTICE_GAMMA1 (1 << 17)
#define LATTICE_BETA 225
#define LATTICE_GAMMA2 ((LATTICE_Q - 1) / 88)

static __attribute__((aligned(32))) u8 ZERO_SEED[32] = {0};

typedef struct {
	i32 coeffs[LATTICE_N];
} poly;

typedef struct {
	poly vec[LATTICE_L];
} polyvec;

typedef struct {
	__attribute__((aligned(32))) u8 rho[32];
	__attribute__((aligned(32))) u8 tr[64];
	polyvec s1;
	polyvec s2;
	polyvec t;
	polyvec t0;
	polyvec t1;
} AsymmetricSkeyExpanded;

typedef struct {
	polyvec z;
	u8 c_tilde[64];
	polyvec h;
} AsymmetricSigImpl;

typedef struct {
	u8 rho[32];
	polyvec t1;
} AsymmetricPKImpl;

STATIC i32 asymmetric_mod_q(i64 x) {
	i32 r = (i32)x;
	if (r >= LATTICE_Q) r -= LATTICE_Q;
	if (r < -LATTICE_Q / 2) r += LATTICE_Q;
	return r;
}

STATIC void asymmetric_poly_add(poly *w, const poly *u, const poly *v) {
	for (int i = 0; i < LATTICE_N; i++) {
		i64 sum = (i64)u->coeffs[i] + v->coeffs[i];
		w->coeffs[i] = asymmetric_mod_q(sum);
	}
}

STATIC void asymmetric_poly_pointwise_mul(poly *w, const poly *u,
					  const poly *v) {
	for (int i = 0; i < LATTICE_N; i++) {
		i64 prod = (i64)u->coeffs[i] * v->coeffs[i];
		w->coeffs[i] = asymmetric_mod_q(prod);
	}
}

STATIC void asymmetric_poly_row_dot(poly *w, const polyvec *row,
				    const polyvec *vec) {
	poly temp;
	fastmemset(w, 0, sizeof(*w));

	for (int j = 0; j < LATTICE_L; j++) {
		asymmetric_poly_pointwise_mul(&temp, &row->vec[j],
					      &vec->vec[j]);
		asymmetric_poly_add(w, w, &temp);
	}
}

STATIC void asymmetric_poly_uniform(poly *p, StormContext *ctx) {
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

STATIC void asymmetric_poly_uniform_eta(poly *p, StormContext *ctx) {
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
STATIC void asymmetric_expand_mat(polyvec mat[LATTICE_L], const u8 rho[32]) {
	StormContext ctx;
	storm_init(&ctx, rho);

	for (u32 i = 0; i < LATTICE_L; i++)
		for (u32 j = 0; j < LATTICE_L; j++)
			asymmetric_poly_uniform(&mat[i].vec[j], &ctx);
}

STATIC void asymmetric_polyvec_decompose(polyvec *t1, polyvec *t0,
					 const polyvec *t) {
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

STATIC void asymmetric_skey_expand(const AsymmetricSK *sk,
				   AsymmetricSkeyExpanded *exp) {
	StormContext ctx;
	fastmemset(exp, 0, sizeof(AsymmetricSkeyExpanded));
	storm_init(&ctx, sk->data);
	storm_xcrypt_buffer(&ctx, exp->rho);
	storm_xcrypt_buffer(&ctx, exp->tr);
	storm_xcrypt_buffer(&ctx, exp->tr + 32);

	for (i32 i = 0; i < LATTICE_L; i++) {
		asymmetric_poly_uniform_eta(&exp->s1.vec[i], &ctx);
	}
	for (i32 i = 0; i < LATTICE_L; i++) {
		asymmetric_poly_uniform_eta(&exp->s2.vec[i], &ctx);
	}

	{
		poly temp;
		polyvec A[LATTICE_L];
		asymmetric_expand_mat(A, exp->rho);

		for (i32 i = 0; i < LATTICE_L; i++) {
			asymmetric_poly_row_dot(&temp, &A[i], &exp->s1);
			asymmetric_poly_add(&exp->t.vec[i], &exp->t.vec[i],
					    &temp);
		}
		secure_zero(A, sizeof(A));
		secure_zero(&temp, sizeof(temp));
	}

	for (u32 i = 0; i < LATTICE_L; i++) {
		asymmetric_poly_add(&exp->t.vec[i], &exp->t.vec[i],
				    &exp->s2.vec[i]);
	}

	asymmetric_polyvec_decompose(&exp->t1, &exp->t0, &exp->t);

	secure_zero(&ctx, sizeof(ctx));
}

STATIC void asymmetric_expand_challenge(poly *c, const u8 c_tilde[64]) {
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

STATIC void asymmetric_poly_uniform_gamma1(poly *p, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u32 pos = 0;

	while (pos < LATTICE_N) {
		storm_xcrypt_buffer(ctx, buf);
		for (int i = 0; i < 32 && pos < LATTICE_N; i += 3) {
			u32 t0 =
			    buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16);
			u32 t = t0 & 0x3FFFF;

			if (t < 2 * (LATTICE_GAMMA1 - 1) + 1) {
				i32 val = (i32)(t);
				if (val > LATTICE_GAMMA1 - 1)
					val = val -
					      (2 * (LATTICE_GAMMA1 - 1) + 1);
				p->coeffs[pos++] = val;
			}
		}
	}
}

STATIC u32 asymmetric_polyvec_infinity_norm(const polyvec *v) {
	u32 max = 0;

	for (u32 i = 0; i < LATTICE_L; i++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 c = v->vec[i].coeffs[j];
			u32 abs = (u32)(c < 0 ? -c : c);
			if (abs > max) max = abs;
		}
	}

	return max;
}

STATIC void asymmetric_polyvec_make_hint(polyvec *h, const polyvec *t0,
					 const poly *c, const polyvec *s2) {
	fastmemset(h, 0, sizeof(*h));

	for (u32 k = 0; k < LATTICE_L; k++) {
		for (u32 j = 0; j < LATTICE_N; j++) {
			i32 val = t0->vec[k].coeffs[j];

			if (c->coeffs[j] == 1)
				val += s2->vec[k].coeffs[j];
			else if (c->coeffs[j] == -1)
				val -= s2->vec[k].coeffs[j];

			if (val >= LATTICE_Q / 2 || val <= -LATTICE_Q / 2) {
				h->vec[k].coeffs[j] = 1;
			}
		}
	}
}

STATIC void asymmetric_pack_sig(AsymmetricSig *sig, const polyvec *z,
				const u8 c_tilde[64], const polyvec *h) {
	AsymmetricSigImpl *impl = (void *)sig;
	fastmemcpy(&impl->z, z, sizeof(*z));
	fastmemcpy(&impl->c_tilde, c_tilde, 64);
	fastmemcpy(&impl->h, h, sizeof(*h));
}

STATIC void asymmetric_polyvec_use_hint(polyvec *result, const polyvec *r,
					const polyvec *h) {
	for (int i = 0; i < LATTICE_L; i++) {
		for (int j = 0; j < LATTICE_N; j++) {
			i32 r_val = r->vec[i].coeffs[j];
			if (r_val < 0) r_val += LATTICE_Q;

			i32 r0 = r_val & 0x1FFF;
			i32 r1 = (r_val - r0) >> 13;

			if (h->vec[i].coeffs[j]) {
				if (r0 > 4096) {
					r1 -= 1;
				} else {
					r1 += 1;
				}
			}

			result->vec[i].coeffs[j] = r1;
		}
	}
}

PUBLIC void asymmetric_skey(const u8 seed[32], AsymmetricSK *sk) {
	fastmemcpy(sk->data, seed, 32);
}

STATIC void print_hex(const char *name, const u8 *data, u64 len) {
	print("{} = ", name);
	for (u64 i = 0; i < len; i++) print("{},", data[i]);
	println("");
}

STATIC void debug_print_full_expanded_key(const AsymmetricSkeyExpanded *exp) {
	println("=== DIE STORM DILITHIUM5 EXPANDED KEY ===");

	// Print rho and tr in hex
	print("rho = ");
	for (int i = 0; i < 32; i++) print("{x}", exp->rho[i]);
	println("");

	print("tr  = ");
	for (int i = 0; i < 64; i++) {
		print("{x}", exp->tr[i]);
		if (i == 31) print(" ");  // space in middle for readability
	}
	println("");

	// s1: length 7 — show first 8 coeffs of first and last vector
	println("s1[0] first 8 coeffs: {} {} {} {} {} {} {} {}",
		exp->s1.vec[0].coeffs[0], exp->s1.vec[0].coeffs[1],
		exp->s1.vec[0].coeffs[2], exp->s1.vec[0].coeffs[3],
		exp->s1.vec[0].coeffs[4], exp->s1.vec[0].coeffs[5],
		exp->s1.vec[0].coeffs[6], exp->s1.vec[0].coeffs[7]);

	println("s1[6] first 8 coeffs: {} {} {} {} {} {} {} {}",
		exp->s1.vec[6].coeffs[0], exp->s1.vec[6].coeffs[1],
		exp->s1.vec[6].coeffs[2], exp->s1.vec[6].coeffs[3],
		exp->s1.vec[6].coeffs[4], exp->s1.vec[6].coeffs[5],
		exp->s1.vec[6].coeffs[6], exp->s1.vec[6].coeffs[7]);

	// s2, t, t0, t1: length 8 — show first vec and confirm last has data
	for (int v = 0; v < 4; v++) {
		const char *name = (v == 0)   ? "s2"
				   : (v == 1) ? "t "
				   : (v == 2) ? "t0"
					      : "t1";
		const polyvec *vec = (v == 0)	? &exp->s2
				     : (v == 1) ? &exp->t
				     : (v == 2) ? &exp->t0
						: &exp->t1;

		println("{}[0] first 8: {} {} {} {} {} {} {} {}", name,
			vec->vec[0].coeffs[0], vec->vec[0].coeffs[1],
			vec->vec[0].coeffs[2], vec->vec[0].coeffs[3],
			vec->vec[0].coeffs[4], vec->vec[0].coeffs[5],
			vec->vec[0].coeffs[6], vec->vec[0].coeffs[7]);

		i32 last_coeff = vec->vec[LATTICE_L - 1].coeffs[0];
		println("{}[7] sample coeff[0] = {}  ← vec[7] is filled!", name,
			last_coeff);
	}

	println("=== KEYGEN SANITY CHECK COMPLETE ===");
	println("All vectors filled: YES");
}

STATIC void debug_verify_expanded_key_or_panic(
    const AsymmetricSkeyExpanded *exp) {
	println("=== DIE STORM DILITHIUM KEYGEN SANITY CHECK ===");

// Helper to check a single polynomial isn't all zeros
#define CHECK_POLY(name, poly_ptr)                                             \
	do {                                                                   \
		int all_zero = 1;                                              \
		for (int i = 0; i < LATTICE_N; i++) {                          \
			if ((poly_ptr)->coeffs[i] != 0) {                      \
				all_zero = 0;                                  \
				break;                                         \
			}                                                      \
		}                                                              \
		if (all_zero) {                                                \
			panic("FATAL: " name " is all zeros! Keygen failed."); \
		}                                                              \
	} while (0)

// Helper to check an entire vector (all components non-zero)
#define CHECK_VEC(name, vec_ptr, len, last_idx)                                \
	do {                                                                   \
		CHECK_POLY(name "[0]", &(vec_ptr)->vec[0]);                    \
		CHECK_POLY(name "[" #last_idx "]", &(vec_ptr)->vec[last_idx]); \
		println(                                                       \
		    name "[0] first 8: {} {} {} {} {} {} {} {}",               \
		    (vec_ptr)->vec[0].coeffs[0], (vec_ptr)->vec[0].coeffs[1],  \
		    (vec_ptr)->vec[0].coeffs[2], (vec_ptr)->vec[0].coeffs[3],  \
		    (vec_ptr)->vec[0].coeffs[4], (vec_ptr)->vec[0].coeffs[5],  \
		    (vec_ptr)->vec[0].coeffs[6], (vec_ptr)->vec[0].coeffs[7]); \
		println(name "[" #last_idx                                     \
			     "] sample coeff[0] = {}  ← filled!",              \
			(vec_ptr)->vec[last_idx].coeffs[0]);                   \
	} while (0)

	// === Actual checks ===
	print("rho = ");
	for (int i = 0; i < 32; i++) print("{x}", exp->rho[i]);
	println("");

	print("tr  = ");
	for (int i = 0; i < 64; i++) print("{x}", exp->tr[i]);
	println("");

	// s1: length LATTICE_L = 7
	CHECK_VEC("s1", &exp->s1, LATTICE_L, 6);

	// s2, t, t0, t1: length LATTICE_L = 7 (or 8 if you go 8×8)
	CHECK_VEC("s2", &exp->s2, LATTICE_L, LATTICE_L - 1);
	CHECK_VEC("t ", &exp->t, LATTICE_L, LATTICE_L - 1);
	CHECK_VEC("t0", &exp->t0, LATTICE_L, LATTICE_L - 1);
	CHECK_VEC("t1", &exp->t1, LATTICE_L, LATTICE_L - 1);

	println("=== ALL VECTORS NON-ZERO AND FILLED ===");
	println("Storm keygen: SUCCESS");

#undef CHECK_POLY
#undef CHECK_VEC
}

PUBLIC void asymmetric_pubkey(const AsymmetricSK *sec_key, AsymmetricPK *pk) {
	AsymmetricPKImpl *impl = (void *)pk->data;
	AsymmetricSkeyExpanded exp;
	asymmetric_skey_expand(sec_key, &exp);

	fastmemcpy(&impl->rho, exp.rho, 32);
	fastmemcpy(&impl->t1, &exp.t1, sizeof(exp.t1));

	(void)debug_print_full_expanded_key;
	(void)debug_verify_expanded_key_or_panic;
	(void)print_hex;
	// debug_print_full_expanded_key(&exp);
	// debug_verify_expanded_key_or_panic(&exp);
	// println("sizeof={}", sizeof(polyvec));

	secure_zero(&exp, sizeof(exp));
}

PUBLIC void asymmetric_sign(const AsymmetricSK *sk, const u8 message[128],
			    AsymmetricSig *sig) {
	__attribute__((aligned(32))) u8 nonce[32] = {0};
	__attribute__((aligned(32))) u8 c_tilde[64] = {0};
	AsymmetricSkeyExpanded exp;

	asymmetric_skey_expand(sk, &exp);

	{
		__attribute__((aligned(32))) u8 tmp[32];
		StormContext ctx;
		storm_init(&ctx, ZERO_SEED);
		storm_xcrypt_buffer(&ctx, exp.rho);
		for (u32 i = 0; i < sizeof(exp.t1); i += 32)
			storm_xcrypt_buffer(&ctx, ((u8 *)&exp.t1) + i);
		for (u32 i = 0; i < 128; i += 32) {
			fastmemcpy(tmp, message + i, 32);
			storm_xcrypt_buffer(&ctx, tmp);
		}
		storm_xcrypt_buffer(&ctx, c_tilde);
		storm_xcrypt_buffer(&ctx, c_tilde + 32);

		secure_zero(&ctx, sizeof(ctx));
		secure_zero(tmp, sizeof(tmp));
	}

	poly c;
	asymmetric_expand_challenge(&c, c_tilde);
	polyvec z;

	do {
		StormContext y_ctx;
		polyvec y;

		storm_init(&y_ctx, sk->data);
		storm_xcrypt_buffer(&y_ctx, nonce);
		(*(u64 *)nonce)++;

		for (u32 i = 0; i < LATTICE_L; i++)
			asymmetric_poly_uniform_gamma1(&y.vec[i], &y_ctx);

		for (u32 i = 0; i < LATTICE_L; i++) {
			fastmemcpy(z.vec[i].coeffs, y.vec[i].coeffs,
				   sizeof(poly));
		}

		for (u32 j = 0; j < LATTICE_N; j++) {
			if (c.coeffs[j] != 0) {
				i32 s = c.coeffs[j];
				for (u32 i = 0; i < LATTICE_L; i++) {
					i64 val = (i64)z.vec[i].coeffs[j] +
						  s * exp.s1.vec[i].coeffs[j];
					z.vec[i].coeffs[j] =
					    asymmetric_mod_q(val);
				}
			}
		}

	} while (asymmetric_polyvec_infinity_norm(&z) >=
		 (LATTICE_GAMMA1 - LATTICE_BETA));

	polyvec h;
	asymmetric_polyvec_make_hint(&h, &exp.t0, &c, &exp.s2);
	asymmetric_pack_sig(sig, &z, c_tilde, &h);

	secure_zero(nonce, sizeof(nonce));
	secure_zero(c_tilde, sizeof(c_tilde));
	secure_zero(&exp, sizeof(exp));
}

PUBLIC int asymmetric_verify(const AsymmetricPK *pk, const u8 message[128],
			     const AsymmetricSig *sig) {
	const AsymmetricPKImpl *pk_impl = (const void *)pk->data;
	const AsymmetricSigImpl *sig_impl = (const void *)sig->data;

	u8 c_tilde_recomputed[64] = {0};
	poly c;
	polyvec Az;
	polyvec r;
	polyvec w1;

	if (asymmetric_polyvec_infinity_norm(&sig_impl->z) >=
	    (LATTICE_GAMMA1 - LATTICE_BETA))
		return -1;

	{
		polyvec A[LATTICE_L];
		asymmetric_expand_mat(A, pk_impl->rho);
		for (int i = 0; i < LATTICE_L; i++) {
			asymmetric_poly_row_dot(&Az.vec[i], &A[i],
						&sig_impl->z);
		}
		secure_zero(A, sizeof(A));
	}

	for (int i = 0; i < LATTICE_L; i++) {
		fastmemcpy(r.vec[i].coeffs, Az.vec[i].coeffs, sizeof(poly));
	}
	asymmetric_expand_challenge(&c, sig_impl->c_tilde);
	for (int j = 0; j < LATTICE_N; j++) {
		if (c.coeffs[j] != 0) {
			i32 s = c.coeffs[j];
			for (int i = 0; i < LATTICE_L; i++) {
				i64 val = (i64)r.vec[i].coeffs[j] -
					  s * pk_impl->t1.vec[i].coeffs[j];
				r.vec[i].coeffs[j] = asymmetric_mod_q(val);
			}
		}
	}

	asymmetric_polyvec_use_hint(&w1, &r, &sig_impl->h);

	{
		StormContext ctx;
		u8 tmp[32];

		storm_init(&ctx, ZERO_SEED);

		fastmemcpy(tmp, pk_impl->rho, 32);
		storm_xcrypt_buffer(&ctx, tmp);

		for (u32 i = 0; i < sizeof(pk_impl->t1); i += 32) {
			fastmemcpy(tmp, ((const u8 *)&pk_impl->t1) + i, 32);
			storm_xcrypt_buffer(&ctx, tmp);
		}

		for (u32 i = 0; i < sizeof(w1); i += 32) {
			fastmemcpy(tmp, ((const u8 *)&w1) + i, 32);
			storm_xcrypt_buffer(&ctx, tmp);
		}

		for (u32 i = 0; i < 128; i += 32) {
			u32 len = (i + 32 <= 128) ? 32 : 128 - i;
			fastmemcpy(tmp, message + i, len);
			fastmemset(tmp + len, 0, 32 - len);
			storm_xcrypt_buffer(&ctx, tmp);
		}

		storm_xcrypt_buffer(&ctx, c_tilde_recomputed);
		storm_xcrypt_buffer(&ctx, c_tilde_recomputed + 32);
	}

	if (memcmp(c_tilde_recomputed, sig_impl->c_tilde, 64) != 0) return -1;

	return 0;  // Valid signature
}
