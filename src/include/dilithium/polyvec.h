#ifndef POLYVEC_H
#define POLYVEC_H

#include <dilithium/params.h>
#include <dilithium/poly.h>
#include <libfam/types.h>

/* Vectors of polynomials of length K */
typedef struct {
	poly vec[K];
} polyvecl;

void polyvecl_uniform_eta(polyvecl *v, const u8 seed[CRHBYTES], u16 nonce);

void polyvecl_uniform_gamma1(polyvecl *v, const u8 seed[CRHBYTES], u16 nonce);

void polyvecl_reduce(polyvecl *v);

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a,
					const polyvecl *v);
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
				       const polyvecl *v);

int polyvecl_chknorm(const polyvecl *v, i32 B);

/* Vectors of polynomials of length K */
typedef struct {
	poly vec[K];
} polyveck;

void polyveck_uniform_eta(polyveck *v, const u8 seed[CRHBYTES], u16 nonce);

void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_shiftl(polyveck *v);

void polyveck_ntt(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a,
					const polyveck *v);

int polyveck_chknorm(const polyveck *v, i32 B);

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
u32 polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

void polyveck_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyveck *w1);

void polyvec_matrix_expand(polyvecl mat[K], const u8 rho[SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K],
					 const polyvecl *v);

#endif
