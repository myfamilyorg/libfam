#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2

#include <dilithium_avx2/align.h>
#include <dilithium_avx2/consts.h>
#include <dilithium_avx2/ntt.h>
#include <dilithium_avx2/params.h>
#include <dilithium_avx2/poly.h>
#include <dilithium_avx2/rejsample.h>
#include <dilithium_avx2/rounding.h>
#include <immintrin.h>
#include <libfam/sign_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>

#define _mm256_blendv_epi32(a, b, mask)                              \
	_mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
					     _mm256_castsi256_ps(b), \
					     _mm256_castsi256_ps(mask)))

static void storm_init_nonce(StormContext *ctx, u16 nonce) {
	__attribute__((aligned(32))) u8 key[32];
	fastmemcpy(key, HASH_DOMAIN, 32);
	for (u32 i = 0; i < 16; i++) ((u16 *)key)[i] ^= nonce;
	storm_init(ctx, key);
}

void poly_reduce(poly *a) {
	unsigned int i;
	__m256i f, g;
	const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
	const __m256i off = _mm256_set1_epi32(1 << 22);

	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_add_epi32(f, off);
		g = _mm256_srai_epi32(g, 23);
		g = _mm256_mullo_epi32(g, q);
		f = _mm256_sub_epi32(f, g);
		_mm256_store_si256(&a->vec[i], f);
	}
}

void poly_caddq(poly *a) {
	unsigned int i;
	__m256i f, g;
	const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
	const __m256i zero = _mm256_setzero_si256();

	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_blendv_epi32(zero, q, f);
		f = _mm256_add_epi32(f, g);
		_mm256_store_si256(&a->vec[i], f);
	}
}

void poly_add(poly *c, const poly *a, const poly *b) {
	unsigned int i;
	__m256i f, g;

	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_load_si256(&b->vec[i]);
		f = _mm256_add_epi32(f, g);
		_mm256_store_si256(&c->vec[i], f);
	}
}

void poly_sub(poly *c, const poly *a, const poly *b) {
	unsigned int i;
	__m256i f, g;

	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_load_si256(&b->vec[i]);
		f = _mm256_sub_epi32(f, g);
		_mm256_store_si256(&c->vec[i], f);
	}
}

void poly_shiftl(poly *a) {
	unsigned int i;
	__m256i f;

	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		f = _mm256_slli_epi32(f, D);
		_mm256_store_si256(&a->vec[i], f);
	}
}

void poly_ntt(poly *a) { ntt_avx(a->vec, qdata.vec); }

void poly_invntt_tomont(poly *a) { invntt_avx(a->vec, qdata.vec); }

void poly_nttunpack(poly *a) { nttunpack_avx(a->vec); }

void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
	pointwise_avx(c->vec, a->vec, b->vec, qdata.vec);
}

void poly_power2round(poly *a1, poly *a0, const poly *a) {
	power2round_avx(a1->vec, a0->vec, a->vec);
}

void poly_decompose(poly *a1, poly *a0, const poly *a) {
	decompose_avx(a1->vec, a0->vec, a->vec);
}

unsigned int poly_make_hint(u8 hint[N], const poly *a0, const poly *a1) {
	unsigned int r;

	r = make_hint_avx(hint, a0->vec, a1->vec);

	return r;
}

void poly_use_hint(poly *b, const poly *a, const poly *h) {
	use_hint_avx(b->vec, a->vec, h->vec);
}

int poly_chknorm(const poly *a, i32 B) {
	unsigned int i;
	int r;
	__m256i f, t;
	const __m256i bound = _mm256_set1_epi32(B - 1);

	if (B > (Q - 1) / 8) return 1;

	t = _mm256_setzero_si256();
	for (i = 0; i < N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		f = _mm256_abs_epi32(f);
		f = _mm256_cmpgt_epi32(f, bound);
		t = _mm256_or_si256(t, f);
	}

	r = 1 - _mm256_testz_si256(t, t);
	return r;
}

static unsigned int rej_uniform(i32 *a, unsigned int len, const u8 *buf,
				unsigned int buflen) {
	unsigned int ctr, pos;
	u32 t;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		t = buf[pos++];
		t |= (u32)buf[pos++] << 8;
		t |= (u32)buf[pos++] << 16;
		t &= 0x7FFFFF;

		if (t < Q) a[ctr++] = t;
	}

	return ctr;
}

void poly_uniform_4x(poly *a0, poly *a1, poly *a2, poly *a3, const u8 seed[32],
		     u16 nonce0, u16 nonce1, u16 nonce2, u16 nonce3) {
	StormContext ctx0, ctx1, ctx2, ctx3;
	unsigned int ctr0, ctr1, ctr2, ctr3;
	ALIGNED_UINT8(864) buf[4] = {0};
	__m256i f;

	f = _mm256_loadu_si256((__m256i *)seed);
	_mm256_store_si256(buf[0].vec, f);
	_mm256_store_si256(buf[1].vec, f);
	_mm256_store_si256(buf[2].vec, f);
	_mm256_store_si256(buf[3].vec, f);

	buf[0].coeffs[SEEDBYTES + 0] = nonce0;
	buf[0].coeffs[SEEDBYTES + 1] = nonce0 >> 8;
	buf[1].coeffs[SEEDBYTES + 0] = nonce1;
	buf[1].coeffs[SEEDBYTES + 1] = nonce1 >> 8;
	buf[2].coeffs[SEEDBYTES + 0] = nonce2;
	buf[2].coeffs[SEEDBYTES + 1] = nonce2 >> 8;
	buf[3].coeffs[SEEDBYTES + 0] = nonce3;
	buf[3].coeffs[SEEDBYTES + 1] = nonce3 >> 8;

	storm_init_nonce(&ctx0, nonce0);
	storm_init_nonce(&ctx1, nonce1);
	storm_init_nonce(&ctx2, nonce2);
	storm_init_nonce(&ctx3, nonce3);

	for (u32 i = 0; i < 864; i += 32) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i);
	}

	ctr0 = rej_uniform_avx(a0->coeffs, buf[0].coeffs);
	ctr1 = rej_uniform_avx(a1->coeffs, buf[1].coeffs);
	ctr2 = rej_uniform_avx(a2->coeffs, buf[2].coeffs);
	ctr3 = rej_uniform_avx(a3->coeffs, buf[3].coeffs);

	while (ctr0 < N || ctr1 < N || ctr2 < N || ctr3 < N) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs);

		ctr0 +=
		    rej_uniform(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, 32);
		ctr1 +=
		    rej_uniform(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, 32);
		ctr2 +=
		    rej_uniform(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, 32);
		ctr3 +=
		    rej_uniform(a3->coeffs + ctr3, N - ctr3, buf[3].coeffs, 32);
	}
}

static unsigned int rej_eta(i32 *a, unsigned int len, const u8 *buf,
			    unsigned int buflen) {
	unsigned int ctr, pos;
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

void poly_uniform_eta(poly *a, const u8 seed[CRHBYTES], u16 nonce) {
	StormContext ctx;
	unsigned int ctr;
	__attribute__((aligned(32))) u8 buf[160] = {0};

	storm_init_nonce(&ctx, nonce);
	fastmemcpy(buf, seed, CRHBYTES);
	fastmemcpy(buf + CRHBYTES, &nonce, sizeof(nonce));
	for (u32 i = 0; i < sizeof(buf); i += 32)
		storm_next_block(&ctx, buf + i);

	ctr = rej_eta(a->coeffs, N, buf, 160);

	while (ctr < N) {
		storm_next_block(&ctx, buf);
		ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, 32);
	}
}

void poly_uniform_eta_4x(poly *a0, poly *a1, poly *a2, poly *a3,
			 const u8 seed[64], u16 nonce0, u16 nonce1, u16 nonce2,
			 u16 nonce3) {
	StormContext ctx0, ctx1, ctx2, ctx3;
	unsigned int ctr0, ctr1, ctr2, ctr3;
	ALIGNED_UINT8(160) buf[4] = {0};

	__m256i f;

	f = _mm256_loadu_si256((__m256i *)&seed[0]);
	_mm256_store_si256(&buf[0].vec[0], f);
	_mm256_store_si256(&buf[1].vec[0], f);
	_mm256_store_si256(&buf[2].vec[0], f);
	_mm256_store_si256(&buf[3].vec[0], f);
	f = _mm256_loadu_si256((__m256i *)&seed[32]);
	_mm256_store_si256(&buf[0].vec[1], f);
	_mm256_store_si256(&buf[1].vec[1], f);
	_mm256_store_si256(&buf[2].vec[1], f);
	_mm256_store_si256(&buf[3].vec[1], f);

	buf[0].coeffs[64] = nonce0;
	buf[0].coeffs[65] = nonce0 >> 8;
	buf[1].coeffs[64] = nonce1;
	buf[1].coeffs[65] = nonce1 >> 8;
	buf[2].coeffs[64] = nonce2;
	buf[2].coeffs[65] = nonce2 >> 8;
	buf[3].coeffs[64] = nonce3;
	buf[3].coeffs[65] = nonce3 >> 8;

	storm_init_nonce(&ctx0, nonce0);
	storm_init_nonce(&ctx1, nonce1);
	storm_init_nonce(&ctx2, nonce2);
	storm_init_nonce(&ctx3, nonce3);

	for (u32 i = 0; i < 160; i += 32) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i);
	}

	ctr0 = rej_eta_avx(a0->coeffs, buf[0].coeffs);
	ctr1 = rej_eta_avx(a1->coeffs, buf[1].coeffs);
	ctr2 = rej_eta_avx(a2->coeffs, buf[2].coeffs);
	ctr3 = rej_eta_avx(a3->coeffs, buf[3].coeffs);

	while (ctr0 < N || ctr1 < N || ctr2 < N || ctr3 < N) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs);

		ctr0 += rej_eta(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, 32);
		ctr1 += rej_eta(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, 32);
		ctr2 += rej_eta(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, 32);
		ctr3 += rej_eta(a3->coeffs + ctr3, N - ctr3, buf[3].coeffs, 32);
	}
}

void poly_uniform_gamma1_4x(poly *a0, poly *a1, poly *a2, poly *a3,
			    const u8 seed[64], u16 nonce0, u16 nonce1,
			    u16 nonce2, u16 nonce3) {
	StormContext ctx0, ctx1, ctx2, ctx3;
	ALIGNED_UINT8(704)
	buf[4] = {0};
	__m256i f;

	f = _mm256_loadu_si256((__m256i *)&seed[0]);
	_mm256_store_si256(&buf[0].vec[0], f);
	_mm256_store_si256(&buf[1].vec[0], f);
	_mm256_store_si256(&buf[2].vec[0], f);
	_mm256_store_si256(&buf[3].vec[0], f);
	f = _mm256_loadu_si256((__m256i *)&seed[32]);
	_mm256_store_si256(&buf[0].vec[1], f);
	_mm256_store_si256(&buf[1].vec[1], f);
	_mm256_store_si256(&buf[2].vec[1], f);
	_mm256_store_si256(&buf[3].vec[1], f);

	buf[0].coeffs[64] = nonce0;
	buf[0].coeffs[65] = nonce0 >> 8;
	buf[1].coeffs[64] = nonce1;
	buf[1].coeffs[65] = nonce1 >> 8;
	buf[2].coeffs[64] = nonce2;
	buf[2].coeffs[65] = nonce2 >> 8;
	buf[3].coeffs[64] = nonce3;
	buf[3].coeffs[65] = nonce3 >> 8;

	storm_init_nonce(&ctx0, nonce0);
	storm_init_nonce(&ctx1, nonce1);
	storm_init_nonce(&ctx2, nonce2);
	storm_init_nonce(&ctx3, nonce3);
	for (u32 i = 0; i < 704; i += 32) {
		storm_next_block(&ctx0, buf[0].coeffs + i);
		storm_next_block(&ctx1, buf[1].coeffs + i);
		storm_next_block(&ctx2, buf[2].coeffs + i);
		storm_next_block(&ctx3, buf[3].coeffs + i);
	}

	polyz_unpack(a0, buf[0].coeffs);
	polyz_unpack(a1, buf[1].coeffs);
	polyz_unpack(a2, buf[2].coeffs);
	polyz_unpack(a3, buf[3].coeffs);
}

#define STORM_RATE 160
void poly_challenge(poly *restrict c, const u8 seed[CTILDEBYTES]) {
	unsigned int i, b, pos;
	u64 signs;
	__attribute__((aligned(32))) u8 buf[STORM_RATE] = {0};
	StormContext ctx;

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(buf, seed, 32);
	for (u32 i = 0; i < STORM_RATE; i += 32)
		storm_next_block(&ctx, buf + i);

	signs = 0;
	for (i = 0; i < 8; ++i) signs |= (u64)buf[i] << 8 * i;
	pos = 8;

	for (i = 0; i < N; ++i) c->coeffs[i] = 0;
	for (i = N - TAU; i < N; ++i) {
		do {
			if (pos >= STORM_RATE) {
				for (u32 i = 0; i < STORM_RATE; i += 32)
					storm_next_block(&ctx, buf + i);

				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);
		signs >>= 1;
	}
}

void polyeta_pack(u8 r[POLYETA_PACKEDBYTES], const poly *restrict a) {
	unsigned int i;
	u8 t[8];

	for (i = 0; i < N / 8; ++i) {
		t[0] = ETA - a->coeffs[8 * i + 0];
		t[1] = ETA - a->coeffs[8 * i + 1];
		t[2] = ETA - a->coeffs[8 * i + 2];
		t[3] = ETA - a->coeffs[8 * i + 3];
		t[4] = ETA - a->coeffs[8 * i + 4];
		t[5] = ETA - a->coeffs[8 * i + 5];
		t[6] = ETA - a->coeffs[8 * i + 6];
		t[7] = ETA - a->coeffs[8 * i + 7];

		r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
		r[3 * i + 1] =
		    (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
	}
}

void polyeta_unpack(poly *restrict r, const u8 a[POLYETA_PACKEDBYTES]) {
	unsigned int i;

	for (i = 0; i < N / 8; ++i) {
		r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
		r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
		r->coeffs[8 * i + 2] =
		    ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
		r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
		r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
		r->coeffs[8 * i + 5] =
		    ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
		r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
		r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

		r->coeffs[8 * i + 0] = ETA - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] = ETA - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] = ETA - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] = ETA - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] = ETA - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] = ETA - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] = ETA - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] = ETA - r->coeffs[8 * i + 7];
	}
}

void polyt1_pack(u8 r[POLYT1_PACKEDBYTES], const poly *restrict a) {
	unsigned int i;

	for (i = 0; i < N / 4; ++i) {
		r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0);
		r[5 * i + 1] =
		    (a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2);
		r[5 * i + 2] =
		    (a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4);
		r[5 * i + 3] =
		    (a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6);
		r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2);
	}
}

void polyt1_unpack(poly *restrict r, const u8 a[POLYT1_PACKEDBYTES]) {
	unsigned int i;

	for (i = 0; i < N / 4; ++i) {
		r->coeffs[4 * i + 0] =
		    ((a[5 * i + 0] >> 0) | ((u32)a[5 * i + 1] << 8)) & 0x3FF;
		r->coeffs[4 * i + 1] =
		    ((a[5 * i + 1] >> 2) | ((u32)a[5 * i + 2] << 6)) & 0x3FF;
		r->coeffs[4 * i + 2] =
		    ((a[5 * i + 2] >> 4) | ((u32)a[5 * i + 3] << 4)) & 0x3FF;
		r->coeffs[4 * i + 3] =
		    ((a[5 * i + 3] >> 6) | ((u32)a[5 * i + 4] << 2)) & 0x3FF;
	}
}

void polyt0_pack(u8 r[POLYT0_PACKEDBYTES], const poly *restrict a) {
	unsigned int i;
	u32 t[8];

	for (i = 0; i < N / 8; ++i) {
		t[0] = (1 << (D - 1)) - a->coeffs[8 * i + 0];
		t[1] = (1 << (D - 1)) - a->coeffs[8 * i + 1];
		t[2] = (1 << (D - 1)) - a->coeffs[8 * i + 2];
		t[3] = (1 << (D - 1)) - a->coeffs[8 * i + 3];
		t[4] = (1 << (D - 1)) - a->coeffs[8 * i + 4];
		t[5] = (1 << (D - 1)) - a->coeffs[8 * i + 5];
		t[6] = (1 << (D - 1)) - a->coeffs[8 * i + 6];
		t[7] = (1 << (D - 1)) - a->coeffs[8 * i + 7];

		r[13 * i + 0] = t[0];
		r[13 * i + 1] = t[0] >> 8;
		r[13 * i + 1] |= t[1] << 5;
		r[13 * i + 2] = t[1] >> 3;
		r[13 * i + 3] = t[1] >> 11;
		r[13 * i + 3] |= t[2] << 2;
		r[13 * i + 4] = t[2] >> 6;
		r[13 * i + 4] |= t[3] << 7;
		r[13 * i + 5] = t[3] >> 1;
		r[13 * i + 6] = t[3] >> 9;
		r[13 * i + 6] |= t[4] << 4;
		r[13 * i + 7] = t[4] >> 4;
		r[13 * i + 8] = t[4] >> 12;
		r[13 * i + 8] |= t[5] << 1;
		r[13 * i + 9] = t[5] >> 7;
		r[13 * i + 9] |= t[6] << 6;
		r[13 * i + 10] = t[6] >> 2;
		r[13 * i + 11] = t[6] >> 10;
		r[13 * i + 11] |= t[7] << 3;
		r[13 * i + 12] = t[7] >> 5;
	}
}

void polyt0_unpack(poly *restrict r, const u8 a[POLYT0_PACKEDBYTES]) {
	unsigned int i;

	for (i = 0; i < N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[13 * i + 0];
		r->coeffs[8 * i + 0] |= (u32)a[13 * i + 1] << 8;
		r->coeffs[8 * i + 0] &= 0x1FFF;

		r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
		r->coeffs[8 * i + 1] |= (u32)a[13 * i + 2] << 3;
		r->coeffs[8 * i + 1] |= (u32)a[13 * i + 3] << 11;
		r->coeffs[8 * i + 1] &= 0x1FFF;

		r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
		r->coeffs[8 * i + 2] |= (u32)a[13 * i + 4] << 6;
		r->coeffs[8 * i + 2] &= 0x1FFF;

		r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
		r->coeffs[8 * i + 3] |= (u32)a[13 * i + 5] << 1;
		r->coeffs[8 * i + 3] |= (u32)a[13 * i + 6] << 9;
		r->coeffs[8 * i + 3] &= 0x1FFF;

		r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
		r->coeffs[8 * i + 4] |= (u32)a[13 * i + 7] << 4;
		r->coeffs[8 * i + 4] |= (u32)a[13 * i + 8] << 12;
		r->coeffs[8 * i + 4] &= 0x1FFF;

		r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
		r->coeffs[8 * i + 5] |= (u32)a[13 * i + 9] << 7;
		r->coeffs[8 * i + 5] &= 0x1FFF;

		r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
		r->coeffs[8 * i + 6] |= (u32)a[13 * i + 10] << 2;
		r->coeffs[8 * i + 6] |= (u32)a[13 * i + 11] << 10;
		r->coeffs[8 * i + 6] &= 0x1FFF;

		r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
		r->coeffs[8 * i + 7] |= (u32)a[13 * i + 12] << 5;
		r->coeffs[8 * i + 7] &= 0x1FFF;

		r->coeffs[8 * i + 0] = (1 << (D - 1)) - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] = (1 << (D - 1)) - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] = (1 << (D - 1)) - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] = (1 << (D - 1)) - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] = (1 << (D - 1)) - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] = (1 << (D - 1)) - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] = (1 << (D - 1)) - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] = (1 << (D - 1)) - r->coeffs[8 * i + 7];
	}
}

void polyz_pack(u8 r[POLYZ_PACKEDBYTES], const poly *restrict a) {
	unsigned int i;
	u32 t[4];

	for (i = 0; i < N / 4; ++i) {
		t[0] = GAMMA1 - a->coeffs[4 * i + 0];
		t[1] = GAMMA1 - a->coeffs[4 * i + 1];
		t[2] = GAMMA1 - a->coeffs[4 * i + 2];
		t[3] = GAMMA1 - a->coeffs[4 * i + 3];

		r[9 * i + 0] = t[0];
		r[9 * i + 1] = t[0] >> 8;
		r[9 * i + 2] = t[0] >> 16;
		r[9 * i + 2] |= t[1] << 2;
		r[9 * i + 3] = t[1] >> 6;
		r[9 * i + 4] = t[1] >> 14;
		r[9 * i + 4] |= t[2] << 4;
		r[9 * i + 5] = t[2] >> 4;
		r[9 * i + 6] = t[2] >> 12;
		r[9 * i + 6] |= t[3] << 6;
		r[9 * i + 7] = t[3] >> 2;
		r[9 * i + 8] = t[3] >> 10;
	}
}

void polyz_unpack(poly *restrict r, const u8 *a) {
	unsigned int i;
	__m256i f;
	const __m256i shufbidx =
	    _mm256_set_epi8(-1, 9, 8, 7, -1, 7, 6, 5, -1, 5, 4, 3, -1, 3, 2, 1,
			    -1, 8, 7, 6, -1, 6, 5, 4, -1, 4, 3, 2, -1, 2, 1, 0);
	const __m256i srlvdidx = _mm256_set_epi32(6, 4, 2, 0, 6, 4, 2, 0);
	const __m256i mask = _mm256_set1_epi32(0x3FFFF);
	const __m256i gamma1 = _mm256_set1_epi32(GAMMA1);

	for (i = 0; i < N / 8; i++) {
		f = _mm256_loadu_si256((__m256i *)&a[18 * i]);
		f = _mm256_permute4x64_epi64(f, 0x94);
		f = _mm256_shuffle_epi8(f, shufbidx);
		f = _mm256_srlv_epi32(f, srlvdidx);
		f = _mm256_and_si256(f, mask);
		f = _mm256_sub_epi32(gamma1, f);
		_mm256_store_si256(&r->vec[i], f);
	}
}

void polyw1_pack(u8 *r, const poly *restrict a) {
	unsigned int i;
	__m256i f0, f1, f2, f3;
	const __m256i shift1 = _mm256_set1_epi16((64 << 8) + 1);
	const __m256i shift2 = _mm256_set1_epi32((4096 << 16) + 1);
	const __m256i shufdidx1 = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
	const __m256i shufdidx2 = _mm256_set_epi32(-1, -1, 6, 5, 4, 2, 1, 0);
	const __m256i shufbidx = _mm256_set_epi8(
	    -1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0, -1, -1, -1,
	    -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0);

	for (i = 0; i < N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
		f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
		f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
		f0 = _mm256_packus_epi32(f0, f1);
		f1 = _mm256_packus_epi32(f2, f3);
		f0 = _mm256_packus_epi16(f0, f1);
		f0 = _mm256_maddubs_epi16(f0, shift1);
		f0 = _mm256_madd_epi16(f0, shift2);
		f0 = _mm256_permutevar8x32_epi32(f0, shufdidx1);
		f0 = _mm256_shuffle_epi8(f0, shufbidx);
		f0 = _mm256_permutevar8x32_epi32(f0, shufdidx2);
		_mm256_storeu_si256((__m256i *)&r[24 * i], f0);
	}
}

#endif /* USE_AVX2 */
