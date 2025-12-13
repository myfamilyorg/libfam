#ifndef POLY_H
#define POLY_H

#include <dilithium/params.h>
#include <libfam/storm.h>

typedef struct {
	i32 coeffs[N];
} poly;

void poly_reduce(poly *a);
void poly_caddq(poly *a);

void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);
void poly_shiftl(poly *a);

void poly_ntt(poly *a);
void poly_invntt_tomont(poly *a);
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

void poly_power2round(poly *a1, poly *a0, const poly *a);
void poly_decompose(poly *a1, poly *a0, const poly *a);
u32 poly_make_hint(poly *h, const poly *a0, const poly *a1);
void poly_use_hint(poly *b, const poly *a, const poly *h);

int poly_chknorm(const poly *a, i32 B);
void poly_uniform(poly *a, StormContext *ctx);
void poly_uniform_eta(poly *a, StormContext *ctx);
void poly_uniform_gamma1(poly *a, StormContext *ctx, u16 nonce);
void poly_challenge(poly *c, const u8 seed[CTILDEBYTES]);

void polyeta_pack(u8 *r, const poly *a);
void polyeta_unpack(poly *r, const u8 *a);

void polyt1_pack(u8 *r, const poly *a);
void polyt1_unpack(poly *r, const u8 *a);

void polyt0_pack(u8 *r, const poly *a);
void polyt0_unpack(poly *r, const u8 *a);

void polyz_pack(u8 *r, const poly *a);
void polyz_unpack(poly *r, const u8 *a);

void polyw1_pack(u8 *r, const poly *a);

#endif
