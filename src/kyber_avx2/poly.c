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

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#ifdef USE_AVX2

#include <kyber_avx2/align.h>
#include <kyber_avx2/cbd.h>
#include <kyber_avx2/consts.h>
#include <kyber_avx2/ntt.h>
#include <kyber_avx2/poly.h>
#include <kyber_avx2/reduce.h>
#include <kyber_common/params.h>
#include <libfam/format.h>
#include <libfam/kem_impl.h>
#include <libfam/storm.h>
#include <libfam/string.h>

#define SHAKE256_RATE 136

static void storm_init_nonce2(StormContext *ctx, u16 nonce) {
	__attribute__((aligned(32))) u8 key[32];
	fastmemcpy(key, NOISE_ETA2_DOMAIN, 32);
	for (u32 i = 0; i < 16; i++) ((u16 *)key)[i] ^= nonce;
	storm_init(ctx, key);
}

static void storm_init_nonce1(StormContext *ctx, u16 nonce) {
	__attribute__((aligned(32))) u8 key[32];
	fastmemcpy(key, NOISE_ETA1_DOMAIN, 32);
	for (u32 i = 0; i < 16; i++) ((u16 *)key)[i] ^= nonce;
	storm_init(ctx, key);
}

void poly_compress(u8 r[128], const poly *restrict a) {
	unsigned int i;
	__m256i f0, f1, f2, f3;
	const __m256i v = _mm256_load_si256(&qdata.vec[_16XV / 16]);
	const __m256i shift1 = _mm256_set1_epi16(1 << 9);
	const __m256i mask = _mm256_set1_epi16(15);
	const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
	const __m256i permdidx = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);

	for (i = 0; i < KYBER_N / 64; i++) {
		f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
		f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
		f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
		f0 = _mm256_mulhi_epi16(f0, v);
		f1 = _mm256_mulhi_epi16(f1, v);
		f2 = _mm256_mulhi_epi16(f2, v);
		f3 = _mm256_mulhi_epi16(f3, v);
		f0 = _mm256_mulhrs_epi16(f0, shift1);
		f1 = _mm256_mulhrs_epi16(f1, shift1);
		f2 = _mm256_mulhrs_epi16(f2, shift1);
		f3 = _mm256_mulhrs_epi16(f3, shift1);
		f0 = _mm256_and_si256(f0, mask);
		f1 = _mm256_and_si256(f1, mask);
		f2 = _mm256_and_si256(f2, mask);
		f3 = _mm256_and_si256(f3, mask);
		f0 = _mm256_packus_epi16(f0, f1);
		f2 = _mm256_packus_epi16(f2, f3);
		f0 = _mm256_maddubs_epi16(f0, shift2);
		f2 = _mm256_maddubs_epi16(f2, shift2);
		f0 = _mm256_packus_epi16(f0, f2);
		f0 = _mm256_permutevar8x32_epi32(f0, permdidx);
		_mm256_storeu_si256((__m256i *)&r[32 * i], f0);
	}
}

void poly_decompress(poly *restrict r, const u8 a[128]) {
	unsigned int i;
	__m128i t;
	__m256i f;
	const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ / 16]);
	const __m256i shufbidx =
	    _mm256_set_epi8(7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 3,
			    3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0);
	const __m256i mask = _mm256_set1_epi32(0x00F0000F);
	const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);

	for (i = 0; i < KYBER_N / 16; i++) {
		t = _mm_loadl_epi64((__m128i *)&a[8 * i]);
		f = _mm256_broadcastsi128_si256(t);
		f = _mm256_shuffle_epi8(f, shufbidx);
		f = _mm256_and_si256(f, mask);
		f = _mm256_mullo_epi16(f, shift);
		f = _mm256_mulhrs_epi16(f, q);
		_mm256_store_si256(&r->vec[i], f);
	}
}

void poly_tobytes(u8 r[KYBER_POLYBYTES], const poly *a) {
	ntttobytes_avx(r, a->vec, qdata.vec);
}

void poly_frombytes(poly *r, const u8 a[KYBER_POLYBYTES]) {
	nttfrombytes_avx(r->vec, a, qdata.vec);
}

void poly_frommsg(poly *restrict r, const u8 msg[KYBER_INDCPA_MSGBYTES]) {
	__m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
	const __m256i shift =
	    _mm256_broadcastsi128_si256(_mm_set_epi32(0, 1, 2, 3));
	const __m256i idx = _mm256_broadcastsi128_si256(
	    _mm_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0));
	const __m256i hqs = _mm256_set1_epi16((KYBER_Q + 1) / 2);

#define FROMMSG64(i)                                                  \
	g3 = _mm256_shuffle_epi32(f, 0x55 * i);                       \
	g3 = _mm256_sllv_epi32(g3, shift);                            \
	g3 = _mm256_shuffle_epi8(g3, idx);                            \
	g0 = _mm256_slli_epi16(g3, 12);                               \
	g1 = _mm256_slli_epi16(g3, 8);                                \
	g2 = _mm256_slli_epi16(g3, 4);                                \
	g0 = _mm256_srai_epi16(g0, 15);                               \
	g1 = _mm256_srai_epi16(g1, 15);                               \
	g2 = _mm256_srai_epi16(g2, 15);                               \
	g3 = _mm256_srai_epi16(g3, 15);                               \
	g0 = _mm256_and_si256(g0, hqs); /* 19 18 17 16  3  2  1  0 */ \
	g1 = _mm256_and_si256(g1, hqs); /* 23 22 21 20  7  6  5  4 */ \
	g2 = _mm256_and_si256(g2, hqs); /* 27 26 25 24 11 10  9  8 */ \
	g3 = _mm256_and_si256(g3, hqs); /* 31 30 29 28 15 14 13 12 */ \
	h0 = _mm256_unpacklo_epi64(g0, g1);                           \
	h2 = _mm256_unpackhi_epi64(g0, g1);                           \
	h1 = _mm256_unpacklo_epi64(g2, g3);                           \
	h3 = _mm256_unpackhi_epi64(g2, g3);                           \
	g0 = _mm256_permute2x128_si256(h0, h1, 0x20);                 \
	g2 = _mm256_permute2x128_si256(h0, h1, 0x31);                 \
	g1 = _mm256_permute2x128_si256(h2, h3, 0x20);                 \
	g3 = _mm256_permute2x128_si256(h2, h3, 0x31);                 \
	_mm256_store_si256(&r->vec[0 + 2 * i + 0], g0);               \
	_mm256_store_si256(&r->vec[0 + 2 * i + 1], g1);               \
	_mm256_store_si256(&r->vec[8 + 2 * i + 0], g2);               \
	_mm256_store_si256(&r->vec[8 + 2 * i + 1], g3)

	f = _mm256_loadu_si256((__m256i *)msg);
	FROMMSG64(0);
	FROMMSG64(1);
	FROMMSG64(2);
	FROMMSG64(3);
}

void poly_tomsg(u8 msg[KYBER_INDCPA_MSGBYTES], const poly *restrict a) {
	unsigned int i;
	u32 small;
	__m256i f0, f1, g0, g1;
	const __m256i hq = _mm256_set1_epi16((KYBER_Q - 1) / 2);
	const __m256i hhq = _mm256_set1_epi16((KYBER_Q - 1) / 4);

	for (i = 0; i < KYBER_N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[2 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[2 * i + 1]);
		f0 = _mm256_sub_epi16(hq, f0);
		f1 = _mm256_sub_epi16(hq, f1);
		g0 = _mm256_srai_epi16(f0, 15);
		g1 = _mm256_srai_epi16(f1, 15);
		f0 = _mm256_xor_si256(f0, g0);
		f1 = _mm256_xor_si256(f1, g1);
		f0 = _mm256_sub_epi16(f0, hhq);
		f1 = _mm256_sub_epi16(f1, hhq);
		f0 = _mm256_packs_epi16(f0, f1);
		f0 = _mm256_permute4x64_epi64(f0, 0xD8);
		small = _mm256_movemask_epi8(f0);
		fastmemcpy(&msg[4 * i], &small, 4);
	}
}

void poly_getnoise_eta2(poly *r, const u8 seed[KYBER_SYMBYTES], u8 nonce) {
	ALIGNED_UINT8(KYBER_ETA2 * KYBER_N / 4) buf = {0};
	StormContext ctx;

	storm_init_nonce2(&ctx, nonce);
	fastmemcpy(buf.vec, seed, KYBER_SYMBYTES);
	((u8 *)&buf)[KYBER_SYMBYTES] = nonce;
	storm_next_block(&ctx, (u8 *)&buf);
	storm_next_block(&ctx, (u8 *)&buf + 32);

	for (u32 i = 0; i < sizeof(buf); i += 32)
		storm_next_block(&ctx, (u8 *)buf.vec + i);

	poly_cbd_eta2(r, buf.vec);
}

#define NOISE_NBLOCKS \
	((KYBER_ETA1 * KYBER_N / 4 + SHAKE256_RATE - 1) / SHAKE256_RATE)
void poly_getnoise_eta1_4x(poly *r0, poly *r1, poly *r2, poly *r3,
			   const u8 seed[32], u8 nonce0, u8 nonce1, u8 nonce2,
			   u8 nonce3) {
	ALIGNED_UINT8(NOISE_NBLOCKS * SHAKE256_RATE + 16) buf[4] = {0};
	StormContext ctx0, ctx1, ctx2, ctx3;
	__m256i f;

	f = _mm256_loadu_si256((__m256i *)seed);
	_mm256_store_si256(buf[0].vec, f);
	_mm256_store_si256(buf[1].vec, f);
	_mm256_store_si256(buf[2].vec, f);
	_mm256_store_si256(buf[3].vec, f);

	buf[0].coeffs[32] = nonce0;
	buf[1].coeffs[32] = nonce1;
	buf[2].coeffs[32] = nonce2;
	buf[3].coeffs[32] = nonce3;

	storm_init_nonce1(&ctx0, nonce0);
	storm_init_nonce1(&ctx1, nonce1);
	storm_init_nonce1(&ctx2, nonce2);
	storm_init_nonce1(&ctx3, nonce3);

	/*
	storm_init(&ctx0, NOISE_ETA1_DOMAIN);
	storm_init(&ctx1, NOISE_ETA1_DOMAIN);
	storm_init(&ctx2, NOISE_ETA1_DOMAIN);
	storm_init(&ctx3, NOISE_ETA1_DOMAIN);
	*/

	storm_next_block(&ctx0, (u8 *)buf[0].coeffs);
	storm_next_block(&ctx1, (u8 *)buf[1].coeffs);
	storm_next_block(&ctx2, (u8 *)buf[2].coeffs);
	storm_next_block(&ctx3, (u8 *)buf[3].coeffs);
	storm_next_block(&ctx0, (u8 *)buf[0].coeffs + 32);
	storm_next_block(&ctx1, (u8 *)buf[1].coeffs + 32);
	storm_next_block(&ctx2, (u8 *)buf[2].coeffs + 32);
	storm_next_block(&ctx3, (u8 *)buf[3].coeffs + 32);

	for (u32 i = 0; i < sizeof(buf[0]); i += 32) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i);
	}

	poly_cbd_eta1(r0, buf[0].vec);
	poly_cbd_eta1(r1, buf[1].vec);
	poly_cbd_eta1(r2, buf[2].vec);
	poly_cbd_eta1(r3, buf[3].vec);
}

void poly_getnoise_eta1122_4x(poly *r0, poly *r1, poly *r2, poly *r3,
			      const u8 seed[32], u8 nonce0, u8 nonce1,
			      u8 nonce2, u8 nonce3) {
	ALIGNED_UINT8(NOISE_NBLOCKS * SHAKE256_RATE + 16) buf[4] = {0};
	__m256i f;
	StormContext ctx0, ctx1, ctx2, ctx3;

	f = _mm256_loadu_si256((__m256i *)seed);
	_mm256_store_si256(buf[0].vec, f);
	_mm256_store_si256(buf[1].vec, f);
	_mm256_store_si256(buf[2].vec, f);
	_mm256_store_si256(buf[3].vec, f);

	buf[0].coeffs[32] = nonce0;
	buf[1].coeffs[32] = nonce1;
	buf[2].coeffs[32] = nonce2;
	buf[3].coeffs[32] = nonce3;

	/*
	storm_init(&ctx0, NOISE_ETA1_DOMAIN);
	storm_init(&ctx1, NOISE_ETA1_DOMAIN);
	storm_init(&ctx2, NOISE_ETA2_DOMAIN);
	storm_init(&ctx3, NOISE_ETA2_DOMAIN);
	*/
	storm_init_nonce1(&ctx0, nonce0);
	storm_init_nonce1(&ctx1, nonce1);
	storm_init_nonce2(&ctx2, nonce2);
	storm_init_nonce2(&ctx3, nonce3);

	storm_next_block(&ctx0, (u8 *)buf[0].coeffs);
	storm_next_block(&ctx1, (u8 *)buf[1].coeffs);
	storm_next_block(&ctx2, (u8 *)buf[2].coeffs);
	storm_next_block(&ctx3, (u8 *)buf[3].coeffs);
	storm_next_block(&ctx0, (u8 *)buf[0].coeffs + 32);
	storm_next_block(&ctx1, (u8 *)buf[1].coeffs + 32);
	storm_next_block(&ctx2, (u8 *)buf[2].coeffs + 32);
	storm_next_block(&ctx3, (u8 *)buf[3].coeffs + 32);

	for (u32 i = 0; i < sizeof(buf[0]); i += 32) {
		storm_next_block(&ctx0, (u8 *)buf[0].coeffs + i);
		storm_next_block(&ctx1, (u8 *)buf[1].coeffs + i);
		storm_next_block(&ctx2, (u8 *)buf[2].coeffs + i);
		storm_next_block(&ctx3, (u8 *)buf[3].coeffs + i);
	}

	poly_cbd_eta1(r0, buf[0].vec);
	poly_cbd_eta1(r1, buf[1].vec);
	poly_cbd_eta2(r2, buf[2].vec);
	poly_cbd_eta2(r3, buf[3].vec);
}

void poly_ntt(poly *r) { ntt_avx(r->vec, qdata.vec); }

void poly_invntt_tomont(poly *r) { invntt_avx(r->vec, qdata.vec); }

void poly_nttunpack(poly *r) { nttunpack_avx(r->vec, qdata.vec); }

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
	basemul_avx(r->vec, a->vec, b->vec, qdata.vec);
}

void poly_tomont(poly *r) { tomont_avx(r->vec, qdata.vec); }
void poly_reduce(poly *r) { reduce_avx(r->vec, qdata.vec); }

void poly_add(poly *r, const poly *a, const poly *b) {
	unsigned int i;
	__m256i f0, f1;

	for (i = 0; i < KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_add_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
}

void poly_sub(poly *r, const poly *a, const poly *b) {
	unsigned int i;
	__m256i f0, f1;

	for (i = 0; i < KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_sub_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
}

#endif /* !USE_AVX2 */
