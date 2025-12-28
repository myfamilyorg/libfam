#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2

#include <dilithium_avx2/consts.h>
#include <dilithium_avx2/ntt.h>
#include <dilithium_avx2/params.h>
#include <dilithium_avx2/poly.h>
#include <dilithium_avx2/polyvec.h>

void polyvec_matrix_expand(polyvecl mat[K], const u8 rho[SEEDBYTES]) {
	polyvec_matrix_expand_row0(&mat[0], NULL, rho);
	polyvec_matrix_expand_row1(&mat[1], NULL, rho);
	polyvec_matrix_expand_row2(&mat[2], NULL, rho);
	polyvec_matrix_expand_row3(&mat[3], NULL, rho);
}

void polyvec_matrix_expand_row0(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const u8 rho[SEEDBYTES]) {
	poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			&rowa->vec[3], rho, 0, 1, 2, 3);
	poly_nttunpack(&rowa->vec[0]);
	poly_nttunpack(&rowa->vec[1]);
	poly_nttunpack(&rowa->vec[2]);
	poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row1(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const u8 rho[SEEDBYTES]) {
	poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			&rowa->vec[3], rho, 256, 257, 258, 259);
	poly_nttunpack(&rowa->vec[0]);
	poly_nttunpack(&rowa->vec[1]);
	poly_nttunpack(&rowa->vec[2]);
	poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row2(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const u8 rho[SEEDBYTES]) {
	poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			&rowa->vec[3], rho, 512, 513, 514, 515);
	poly_nttunpack(&rowa->vec[0]);
	poly_nttunpack(&rowa->vec[1]);
	poly_nttunpack(&rowa->vec[2]);
	poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row3(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const u8 rho[SEEDBYTES]) {
	poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			&rowa->vec[3], rho, 768, 769, 770, 771);
	poly_nttunpack(&rowa->vec[0]);
	poly_nttunpack(&rowa->vec[1]);
	poly_nttunpack(&rowa->vec[2]);
	poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K],
					 const polyvecl *v) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

void polyvecl_uniform_eta(polyvecl *v, const u8 seed[CRHBYTES], u16 nonce) {
	unsigned int i;

	for (i = 0; i < L; ++i) poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyvecl_reduce(polyvecl *v) {
	unsigned int i;

	for (i = 0; i < L; ++i) poly_reduce(&v->vec[i]);
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
	unsigned int i;

	for (i = 0; i < L; ++i) poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyvecl_ntt(polyvecl *v) {
	unsigned int i;

	for (i = 0; i < L; ++i) poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvecl *v) {
	unsigned int i;

	for (i = 0; i < L; ++i) poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a,
					const polyvecl *v) {
	unsigned int i;

	for (i = 0; i < L; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
				       const polyvecl *v) {
	pointwise_acc_avx(w->vec, u->vec->vec, v->vec->vec, qdata.vec);
}

int polyvecl_chknorm(const polyvecl *v, i32 bound) {
	unsigned int i;

	for (i = 0; i < L; ++i)
		if (poly_chknorm(&v->vec[i], bound)) return 1;

	return 0;
}

void polyveck_uniform_eta(polyveck *v, const u8 seed[CRHBYTES], u16 nonce) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyveck_reduce(polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_reduce(&v->vec[i]);
}

void polyveck_caddq(polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_caddq(&v->vec[i]);
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_shiftl(polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_shiftl(&v->vec[i]);
}

void polyveck_ntt(polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_ntt(&v->vec[i]);
}

void polyveck_invntt_tomont(polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i) poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a,
					const polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

int polyveck_chknorm(const polyveck *v, i32 bound) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		if (poly_chknorm(&v->vec[i], bound)) return 1;

	return 0;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

unsigned int polyveck_make_hint(u8 *hint, const polyveck *v0,
				const polyveck *v1) {
	unsigned int i, n = 0;

	for (i = 0; i < K; ++i)
		n += poly_make_hint(&hint[n], &v0->vec[i], &v1->vec[i]);

	return n;
}

void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyveck *w1) {
	unsigned int i;

	for (i = 0; i < K; ++i)
		polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
}

#endif /* USE_AVX2 */
