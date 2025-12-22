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

#include <immintrin.h>
#include <kyber_avx2/consts.h>
#include <kyber_avx2/ntt.h>
#include <kyber_avx2/poly.h>
#include <kyber_avx2/polyvec.h>
#include <kyber_common/params.h>
#include <libfam/string.h>

STATIC void poly_compress10(u8 r[320], const poly *restrict a) {
	unsigned int i;
	__m256i f0, f1, f2;
	__m128i t0, t1;
	const __m256i v = _mm256_load_si256(&qdata.vec[_16XV / 16]);
	const __m256i v8 = _mm256_slli_epi16(v, 3);
	const __m256i off = _mm256_set1_epi16(15);
	const __m256i shift1 = _mm256_set1_epi16(1 << 12);
	const __m256i mask = _mm256_set1_epi16(1023);
	const __m256i shift2 =
	    _mm256_set1_epi64x((1024LL << 48) + (1LL << 32) + (1024 << 16) + 1);
	const __m256i sllvdidx = _mm256_set1_epi64x(12);
	const __m256i shufbidx = _mm256_set_epi8(
	    8, 4, 3, 2, 1, 0, -1, -1, -1, -1, -1, -1, 12, 11, 10, 9, -1, -1, -1,
	    -1, -1, -1, 12, 11, 10, 9, 8, 4, 3, 2, 1, 0);

	for (i = 0; i < KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_mullo_epi16(f0, v8);
		f2 = _mm256_add_epi16(f0, off);
		f0 = _mm256_slli_epi16(f0, 3);
		f0 = _mm256_mulhi_epi16(f0, v);
		f2 = _mm256_sub_epi16(f1, f2);
		f1 = _mm256_andnot_si256(f1, f2);
		f1 = _mm256_srli_epi16(f1, 15);
		f0 = _mm256_sub_epi16(f0, f1);
		f0 = _mm256_mulhrs_epi16(f0, shift1);
		f0 = _mm256_and_si256(f0, mask);
		f0 = _mm256_madd_epi16(f0, shift2);
		f0 = _mm256_sllv_epi32(f0, sllvdidx);
		f0 = _mm256_srli_epi64(f0, 12);
		f0 = _mm256_shuffle_epi8(f0, shufbidx);
		t0 = _mm256_castsi256_si128(f0);
		t1 = _mm256_extracti128_si256(f0, 1);
		t0 = _mm_blend_epi16(t0, t1, 0xE0);
		_mm_storeu_si128((__m128i *)&r[20 * i + 0], t0);
		fastmemcpy(&r[20 * i + 16], &t1, 4);
	}
}

STATIC void poly_decompress10(poly *restrict r, const u8 a[320 + 12]) {
	unsigned int i;
	__m256i f;
	const __m256i q = _mm256_set1_epi32((KYBER_Q << 16) + 4 * KYBER_Q);
	const __m256i shufbidx =
	    _mm256_set_epi8(11, 10, 10, 9, 9, 8, 8, 7, 6, 5, 5, 4, 4, 3, 3, 2,
			    9, 8, 8, 7, 7, 6, 6, 5, 4, 3, 3, 2, 2, 1, 1, 0);
	const __m256i sllvdidx = _mm256_set1_epi64x(4);
	const __m256i mask = _mm256_set1_epi32((32736 << 16) + 8184);

	for (i = 0; i < KYBER_N / 16; i++) {
		f = _mm256_loadu_si256((__m256i *)&a[20 * i]);
		f = _mm256_permute4x64_epi64(f, 0x94);
		f = _mm256_shuffle_epi8(f, shufbidx);
		f = _mm256_sllv_epi32(f, sllvdidx);
		f = _mm256_srli_epi16(f, 1);
		f = _mm256_and_si256(f, mask);
		f = _mm256_mulhrs_epi16(f, q);
		_mm256_store_si256(&r->vec[i], f);
	}
}

void polyvec_compress(u8 r[KYBER_POLYVECCOMPRESSEDBYTES + 2],
		      const polyvec *a) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_compress10(&r[320 * i], &a->vec[i]);
}

void polyvec_decompress(polyvec *r,
			const u8 a[KYBER_POLYVECCOMPRESSEDBYTES + 12]) {
	unsigned int i;

	for (i = 0; i < KYBER_K; i++)
		poly_decompress10(&r->vec[i], &a[320 * i]);
}

void polyvec_tobytes(u8 r[KYBER_POLYVECBYTES], const polyvec *a) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

void polyvec_frombytes(polyvec *r, const u8 a[KYBER_POLYVECBYTES]) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

void polyvec_ntt(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_ntt(&r->vec[i]);
}

void polyvec_invntt_tomont(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_invntt_tomont(&r->vec[i]);
}

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
				    const polyvec *b) {
	unsigned int i;
	poly tmp;

	poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
	for (i = 1; i < KYBER_K; i++) {
		poly_basemul_montgomery(&tmp, &a->vec[i], &b->vec[i]);
		poly_add(r, r, &tmp);
	}
}

void polyvec_reduce(polyvec *r) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++) poly_reduce(&r->vec[i]);
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
	unsigned int i;
	for (i = 0; i < KYBER_K; i++)
		poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
