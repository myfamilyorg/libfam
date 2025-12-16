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
#include <libfam/storm.h>
#include <libfam/string.h>

/*************************************************
 * Name:        expand_mat
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *
 * Arguments:   - polyvec mat[K]: output matrix
 *              - const u8 rho[]: byte array containing seed rho
 **************************************************/
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
		polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

void polyvecl_uniform_gamma1(polyvec *v, const u8 seed[CRHBYTES], u64 nonce) {
	u32 i;
	StormContext ctx;
	storm_init(&ctx, seed);

	for (i = 0; i < K; ++i)
		poly_uniform_gamma1(&v->vec[i], &ctx, K * nonce + i);
}

void polyvecl_reduce(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_reduce(&v->vec[i]);
}

/*************************************************
 * Name:        polyvec_add
 *
 * Description: Add vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyvec *w: pointer to output vector
 *              - const polyvec *u: pointer to first summand
 *              - const polyvec *v: pointer to second summand
 **************************************************/
void polyvecl_add(polyvec *w, const polyvec *u, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyvecl_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length K. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyvecl_ntt(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvec *r, const poly *a,
					const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
 * Name:        polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length K, multiply
 *              resulting vector by 2^{-32} and add (accumulate) polynomials
 *              in it. Input/output vectors are in NTT domain representation.
 *
 * Arguments:   - poly *w: output polynomial
 *              - const polyvec *u: pointer to first input vector
 *              - const polyvec *v: pointer to second input vector
 **************************************************/
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvec *u,
				       const polyvec *v) {
	u32 i;
	poly t;

	poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (i = 1; i < K; ++i) {
		poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
		poly_add(w, w, &t);
	}
}

/*************************************************
 * Name:        polyvecl_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length K.
 *              Assumes input polyvec to be reduced by polyvecl_reduce().
 *
 * Arguments:   - const polyvec *v: pointer to vector
 *              - i32 B: norm bound
 *
 * Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 **************************************************/
int polyvecl_chknorm(const polyvec *v, i32 bound) {
	u32 i;

	for (i = 0; i < K; ++i)
		if (poly_chknorm(&v->vec[i], bound)) return 1;

	return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

void polyvec_uniform_eta(polyvec *v, const u8 seed[CRHBYTES], u16 nonce) {
	__attribute__((aligned(32))) u8 nonce_buf[32] = {0};
	u32 i;
	StormContext ctx;
	storm_init(&ctx, seed);
	fastmemcpy(nonce_buf, &nonce, sizeof(u16));
	storm_next_block(&ctx, nonce_buf);
	for (i = 0; i < K; ++i) poly_uniform_eta(&v->vec[i], &ctx);
}

/*************************************************
 * Name:        polyveck_reduce
 *
 * Description: Reduce coefficients of polynomials in vector of length K
 *              to representatives in [-6283008,6283008].
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyveck_reduce(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_reduce(&v->vec[i]);
}

/*************************************************
 * Name:        polyveck_caddq
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              add Q if coefficient is negative.
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyveck_caddq(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_caddq(&v->vec[i]);
}

/*************************************************
 * Name:        polyveck_add
 *
 * Description: Add vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyvec *w: pointer to output vector
 *              - const polyvec *u: pointer to first summand
 *              - const polyvec *v: pointer to second summand
 **************************************************/
void polyveck_add(polyvec *w, const polyvec *u, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_sub
 *
 * Description: Subtract vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - polyvec *w: pointer to output vector
 *              - const polyvec *u: pointer to first input vector
 *              - const polyvec *v: pointer to second input vector to be
 *                                   subtracted from first input vector
 **************************************************/
void polyveck_sub(polyvec *w, const polyvec *u, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_shiftl
 *
 * Description: Multiply vector of polynomials of Length K by 2^D without
 *modular reduction. Assumes input coefficients to be less than 2^{31-D}.
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyveck_shiftl(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_shiftl(&v->vec[i]);
}

/*************************************************
 * Name:        polyveck_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length K. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyveck_ntt(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_ntt(&v->vec[i]);
}

/*************************************************
 * Name:        polyveck_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by 2^{32} of polynomials
 *              in vector of length K. Input coefficients need to be less
 *              than 2*Q.
 *
 * Arguments:   - polyvec *v: pointer to input/output vector
 **************************************************/
void polyveck_invntt_tomont(polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i) poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyvec *r, const poly *a,
					const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length K.
 *              Assumes input polyvec to be reduced by polyveck_reduce().
 *
 * Arguments:   - const polyvec *v: pointer to vector
 *              - i32 B: norm bound
 *
 * Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 **************************************************/
int polyveck_chknorm(const polyvec *v, i32 bound) {
	u32 i;

	for (i = 0; i < K; ++i)
		if (poly_chknorm(&v->vec[i], bound)) return 1;

	return 0;
}

/*************************************************
 * Name:        polyveck_power2round
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
 *              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - polyvec *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - polyvec *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const polyvec *v: pointer to input vector
 **************************************************/
void polyveck_power2round(polyvec *v1, polyvec *v0, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_decompose
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
 *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
 *              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - polyvec *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - polyvec *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const polyvec *v: pointer to input vector
 **************************************************/
void polyveck_decompose(polyvec *v1, polyvec *v0, const polyvec *v) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_make_hint
 *
 * Description: Compute hint vector.
 *
 * Arguments:   - polyvec *h: pointer to output vector
 *              - const polyvec *v0: pointer to low part of input vector
 *              - const polyvec *v1: pointer to high part of input vector
 *
 * Returns number of 1 bits.
 **************************************************/
u32 polyveck_make_hint(polyvec *h, const polyvec *v0, const polyvec *v1) {
	u32 i, s = 0;

	for (i = 0; i < K; ++i)
		s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

	return s;
}

/*************************************************
 * Name:        polyveck_use_hint
 *
 * Description: Use hint vector to correct the high bits of input vector.
 *
 * Arguments:   - polyvec *w: pointer to output vector of polynomials with
 *                             corrected high bits
 *              - const polyvec *u: pointer to input vector
 *              - const polyvec *h: pointer to input hint vector
 **************************************************/
void polyveck_use_hint(polyvec *w, const polyvec *u, const polyvec *h) {
	u32 i;

	for (i = 0; i < K; ++i)
		poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyvec *w1) {
	u32 i;

	for (i = 0; i < K; ++i)
		polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
}
