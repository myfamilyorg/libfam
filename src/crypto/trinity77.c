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

#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/trinity77.h>
#include <libfam/utils.h>

#define N 256
#define L 7
#define Q 8380417
#define QINV 58728449

typedef struct {
	i32 coeffs[N];
} poly;

typedef struct {
	poly vec[L];
} polyvec;

typedef struct {
	__attribute__((aligned(32))) u8 rho[32];
	__attribute__((aligned(32))) u8 tr[64];
	polyvec s1;
	polyvec s2;
	polyvec t;
	polyvec t0;
	polyvec t1;
} Trinity77SKExpanded;

typedef struct {
	polyvec z;
	u8 c_tilde[64];
	polyvec h;
} Trinity77SigImpl;

typedef struct {
	u8 rho[32];
	polyvec t1;
} Trinity77PKImpl;

static const i32 zetas[N] = {
    0,	      25847,	-2608894, -518909,  237124,   -777960,	-876248,
    466468,   1826347,	2353451,  -359251,  -2091905, 3119733,	-2884855,
    3111497,  2680103,	2725464,  1024112,  -1079900, 3585928,	-549488,
    -1119584, 2619752,	-2108549, -2118186, -3859737, -1399561, -3277672,
    1757237,  -19422,	4010497,  280005,   2706023,  95776,	3077325,
    3530437,  -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716,
    3574422,  -2867647, 3539968,  -300467,  2348700,  -539299,	-1699267,
    -1643818, 3505694,	-3821735, 3507263,  -2140649, -1600420, 3699596,
    811944,   531354,	954230,	  3881043,  3900724,  -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455,  -1585221, -1257611, 1939314,  -4083598, -1000202, -3190144,
    -3157330, -3632928, 126922,	  3412210,  -983419,  2147896,	2715295,
    -2967645, -3693493, -411027,  -2477047, -671102,  -1228525, -22981,
    -1308169, -381987,	1349076,  1852771,  -1430430, -3343383, 264944,
    508951,   3097992,	44288,	  -1100098, 904516,   3958618,	-3724342,
    -8578,    1653064,	-3249728, 2389356,  -210977,  759969,	-1316856,
    189548,   -3553272, 3159746,  -1851402, -2409325, -177440,	1315589,
    1341330,  1285669,	-1584928, -812732,  -1439742, -3019102, -3881060,
    -3628969, 3839961,	2091667,  3407706,  2316500,  3817976,	-3342478,
    2244091,  -2446433, -3562462, 266997,   2434439,  -1235728, 3513181,
    -3520352, -3759364, -1197226, -3193378, 900702,   1859098,	909542,
    819034,   495491,	-1613174, -43260,   -522500,  -655327,	-3122442,
    2031748,  3207046,	-3556995, -525098,  -768622,  -3595838, 342297,
    286988,   -2437823, 4108315,  3437287,  -3342277, 1735879,	203044,
    2842341,  2691481,	-2590150, 1265009,  4055324,  1247620,	2486353,
    1595974,  -3767016, 1250494,  2635921,  -3548272, -2994039, 1869119,
    1903435,  -1050970, -1333058, 1237275,  -3318210, -1430225, -451100,
    1312455,  3306115,	-1962642, -1279661, 1917081,  -2546312, -1374803,
    1500165,  777191,	2235880,  3406031,  -542412,  -2831860, -1671176,
    -1846953, -2584293, -3724270, 594136,   -3776993, -2013608, 2432395,
    2454455,  -164721,	1957272,  3369112,  185531,   -1207385, -3183426,
    162844,   1616392,	3014001,  810149,   1652634,  -3694233, -1799107,
    -3038916, 3523897,	3866901,  269760,   2213111,  -975884,	1717735,
    472078,   -426683,	1723600,  -1803090, 1910376,  -1667432, -1104333,
    -260646,  -3833893, -2939036, -2235985, -420899,  -2286327, 183443,
    -976891,  1612842,	-3545687, -554416,  3919660,  -48306,	-1362209,
    3937738,  1400424,	-846154,  1976782};

STATIC i32 trinity77_montgomery_reduce(i64 a) {
	i32 t;

	t = (i64)(i32)a * QINV;
	t = (a - (i64)t * Q) >> 32;
	return t;
}

STATIC void trinity77_ntt(i32 a[N]) {
	u32 len, start, j, k;
	i32 zeta, t;

	k = 0;
	for (len = 128; len > 0; len >>= 1) {
		for (start = 0; start < N; start = j + len) {
			zeta = zetas[++k];
			for (j = start; j < start + len; ++j) {
				t = trinity77_montgomery_reduce((i64)zeta *
								a[j + len]);
				a[j + len] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
}

STATIC void trinity77_poly_ntt(poly *a) { trinity77_ntt(a->coeffs); }

STATIC void trinity77_polyvec_ntt(polyvec *v) {
	for (u32 i = 0; i < L; ++i) trinity77_poly_ntt(&v->vec[i]);
}

STATIC void trinity77_poly_uniform(poly *a, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	int x = 0;
	while (x < N) {
		storm_xcrypt_buffer(ctx, buf);
		for (u8 i = 0; i < 8; i++) {
			u32 t = ((u32 *)buf)[i] & 0xFFFFFF;
			if (t < Q) {
				a->coeffs[x++] = t;
				if (x == N) break;
			}
		}
	}
	secure_zero(buf, 32);
}

STATIC void trinity77_poly_uniform_eta(poly *a, StormContext *ctx) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	u8 t0, t1;
	int x = 0;
	while (x < N) {
		storm_xcrypt_buffer(ctx, buf);
		for (u8 i = 0; i < 32; i++) {
			t0 = buf[i] & 0x0F;
			t1 = buf[i] >> 4;
			if (t0 < 15) {
				t0 = t0 - (205 * t0 >> 10) * 5;
				a->coeffs[x++] = 2 - t0;
			}
			if (x == N) break;
			if (t1 < 15) {
				t1 = t1 - (205 * t1 >> 10) * 5;
				a->coeffs[x++] = 2 - t1;
			}
			if (x == N) break;
		}
	}
	secure_zero(buf, 32);
}

STATIC void trinity77_polyvec_uniform_eta(polyvec *v, StormContext *ctx) {
	for (u32 i = 0; i < L; ++i) trinity77_poly_uniform_eta(&v->vec[i], ctx);
}

STATIC void trinity77_polyvec_matrix_expand(polyvec mat[L], StormContext *ctx) {
	for (u32 i = 0; i < L; ++i)
		for (u32 j = 0; j < L; ++j)
			trinity77_poly_uniform(&mat[i].vec[j], ctx);
}

STATIC void trinity77_sk_expand(const Trinity77SK *sk,
				Trinity77SKExpanded *exp) {
	__attribute__((aligned(32))) u8 rho[32];
	polyvec mat[L], s1hat;
	StormContext ctx, rctx;

	fastmemset(exp, 0, sizeof(Trinity77SKExpanded));
	storm_init(&ctx, sk->data);
	storm_xcrypt_buffer(&ctx, exp->rho);
	storm_xcrypt_buffer(&ctx, exp->tr);
	storm_xcrypt_buffer(&ctx, exp->tr + 32);

	fastmemcpy(rho, exp->rho, 32);
	storm_init(&rctx, rho);
	trinity77_polyvec_matrix_expand(mat, &rctx);
	trinity77_polyvec_uniform_eta(&exp->s1, &ctx);
	trinity77_polyvec_uniform_eta(&exp->s2, &ctx);

	s1hat = exp->s1;
	trinity77_polyvec_ntt(&s1hat);

	secure_zero(&ctx, sizeof(ctx));
}

PUBLIC void trinity77_sk(const u8 seed[32], Trinity77SK *sk) {
	fastmemcpy(sk->data, seed, 32);
}

PUBLIC void trinity77_pk(const Trinity77SK *sk, Trinity77PK *pk) {
	Trinity77PKImpl *impl = (void *)pk->data;
	Trinity77SKExpanded exp;

	trinity77_sk_expand(sk, &exp);

	fastmemcpy(&impl->rho, exp.rho, 32);
	fastmemcpy(&impl->t1, &exp.t1, sizeof(exp.t1));

	secure_zero(&exp, sizeof(exp));
}

