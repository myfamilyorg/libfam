#ifndef POLYVEC_H
#define POLYVEC_H

#include <libfam/dilithium.h>
#include <libfam/poly.h>
#include <libfam/types.h>

/* Vectors of polynomials of length K */
typedef struct {
	poly vec[K];
} polyvec;

void polyvecl_uniform_gamma1(polyvec *v, const u8 seed[CRHBYTES], u64 nonce);

void polyvecl_reduce(polyvec *v);

void polyvecl_add(polyvec *w, const polyvec *u, const polyvec *v);

void polyvecl_ntt(polyvec *v);
void polyvecl_invntt_tomont(polyvec *v);
void polyvecl_pointwise_poly_montgomery(polyvec *r, const poly *a,
					const polyvec *v);
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvec *u,
				       const polyvec *v);

int polyvecl_chknorm(const polyvec *v, i32 B);

void polyvec_uniform_eta(polyvec *v, const u8 seed[CRHBYTES], u16 nonce);

void polyveck_reduce(polyvec *v);
void polyveck_caddq(polyvec *v);

void polyveck_add(polyvec *w, const polyvec *u, const polyvec *v);
void polyveck_sub(polyvec *w, const polyvec *u, const polyvec *v);
void polyveck_shiftl(polyvec *v);

void polyveck_ntt(polyvec *v);
void polyveck_invntt_tomont(polyvec *v);
void polyveck_pointwise_poly_montgomery(polyvec *r, const poly *a,
					const polyvec *v);

int polyveck_chknorm(const polyvec *v, i32 B);

void polyveck_power2round(polyvec *v1, polyvec *v0, const polyvec *v);
void polyveck_decompose(polyvec *v1, polyvec *v0, const polyvec *v);
u32 polyveck_make_hint(polyvec *h, const polyvec *v0, const polyvec *v1);
void polyveck_use_hint(polyvec *w, const polyvec *v, const polyvec *h);

void polyveck_pack_w1(u8 r[K * POLYW1_PACKEDBYTES], const polyvec *w1);

void polyvec_matrix_expand(polyvec mat[K], const u8 rho[SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(polyvec *t, const polyvec mat[K],
					 const polyvec *v);

#endif
