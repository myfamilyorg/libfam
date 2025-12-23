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

void dpack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	      const polyvec *t1) {
	u32 i;

	for (i = 0; i < SEEDBYTES; ++i) pk[i] = rho[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}

void polyt1_unpack(poly *r, const u8 *a) {
	u32 i;

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

void polyeta_unpack(poly *r, const u8 *a) {
	u32 i;
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

void dunpack_pk(u8 rho[SEEDBYTES], polyvec *t1,
		const u8 pk[CRYPTO_PUBLICKEYBYTES]) {
	u32 i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = pk[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}

void dpack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	      const u8 tr[TRBYTES], const u8 key[SEEDBYTES], const polyvec *t0,
	      const polyvec *s1, const polyvec *s2) {
	u32 i;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = rho[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = key[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) sk[i] = tr[i];
	sk += TRBYTES;

	for (i = 0; i < K; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}

void dunpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES], u8 key[SEEDBYTES],
		polyvec *t0, polyvec *s1, polyvec *s2,
		const u8 sk[CRYPTO_SECRETKEYBYTES]) {
	u32 i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) key[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) tr[i] = sk[i];
	sk += TRBYTES;

	for (i = 0; i < K; ++i)
		polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}

void dpack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES], const polyvec *z,
	       const polyvec *h) {
	u32 i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) sig[i] = c[i];
	sig += CTILDEBYTES;

	for (i = 0; i < K; ++i)
		polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
	sig += K * POLYZ_PACKEDBYTES;

	for (i = 0; i < OMEGA + K; ++i) sig[i] = 0;

	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j)
			if (h->vec[i].coeffs[j] != 0) sig[k++] = j;

		sig[OMEGA + i] = k;
	}
}

i32 dunpack_sig(u8 c[CTILDEBYTES], polyvec *z, polyvec *h,
		const u8 sig[CRYPTO_BYTES]) {
	u32 i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) c[i] = sig[i];
	sig += CTILDEBYTES;

	for (i = 0; i < K; ++i)
		polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
	sig += K * POLYZ_PACKEDBYTES;

	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j) h->vec[i].coeffs[j] = 0;

		if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) return 1;

		for (j = k; j < sig[OMEGA + i]; ++j) {
			if (j > k && sig[j] <= sig[j - 1]) return 1;
			h->vec[i].coeffs[sig[j]] = 1;
		}

		k = sig[OMEGA + i];
	}

	for (j = k; j < OMEGA; ++j)
		if (sig[j]) return 1;

	return 0;
}

void polyz_unpack(poly *r, const u8 *a) {
	u32 i;

	for (i = 0; i < N / 4; ++i) {
		r->coeffs[4 * i + 0] = a[9 * i + 0];
		r->coeffs[4 * i + 0] |= (u32)a[9 * i + 1] << 8;
		r->coeffs[4 * i + 0] |= (u32)a[9 * i + 2] << 16;
		r->coeffs[4 * i + 0] &= 0x3FFFF;

		r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
		r->coeffs[4 * i + 1] |= (u32)a[9 * i + 3] << 6;
		r->coeffs[4 * i + 1] |= (u32)a[9 * i + 4] << 14;
		r->coeffs[4 * i + 1] &= 0x3FFFF;

		r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
		r->coeffs[4 * i + 2] |= (u32)a[9 * i + 5] << 4;
		r->coeffs[4 * i + 2] |= (u32)a[9 * i + 6] << 12;
		r->coeffs[4 * i + 2] &= 0x3FFFF;

		r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
		r->coeffs[4 * i + 3] |= (u32)a[9 * i + 7] << 2;
		r->coeffs[4 * i + 3] |= (u32)a[9 * i + 8] << 10;
		r->coeffs[4 * i + 3] &= 0x3FFFF;

		r->coeffs[4 * i + 0] = GAMMA1 - r->coeffs[4 * i + 0];
		r->coeffs[4 * i + 1] = GAMMA1 - r->coeffs[4 * i + 1];
		r->coeffs[4 * i + 2] = GAMMA1 - r->coeffs[4 * i + 2];
		r->coeffs[4 * i + 3] = GAMMA1 - r->coeffs[4 * i + 3];
	}
}

void polyt0_unpack(poly *r, const u8 *a) {
	u32 i;

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

void polyz_pack(u8 *r, const poly *a) {
	u32 i;
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

void polyt1_pack(u8 *r, const poly *a) {
	u32 i;
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

void polyt0_pack(u8 *r, const poly *a) {
	u32 i;
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

void polyeta_pack(u8 *r, const poly *a) {
	u32 i;
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
