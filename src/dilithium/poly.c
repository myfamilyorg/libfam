#include <dilithium/ntt.h>
#include <dilithium/params.h>
#include <dilithium/poly.h>
#include <dilithium/reduce.h>
#include <dilithium/rounding.h>
#include <libfam/limits.h>
#include <libfam/storm.h>
#include <libfam/string.h>

#define STORM_RATE 32
__attribute__((aligned(32))) static const u8 POLY_CHALLENGE_DOMAIN[32] = {2, 3,
									  4};

/*************************************************
 * Name:        poly_reduce
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283008,6283008].
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_reduce(poly *a) {
	u32 i;

	for (i = 0; i < N; ++i) a->coeffs[i] = reduce32(a->coeffs[i]);
}

/*************************************************
 * Name:        poly_caddq
 *
 * Description: For all coefficients of in/out polynomial add Q if
 *              coefficient is negative.
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_caddq(poly *a) {
	u32 i;
	for (i = 0; i < N; ++i) a->coeffs[i] = caddq(a->coeffs[i]);
}

/*************************************************
 * Name:        poly_add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - poly *c: pointer to output polynomial
 *              - const poly *a: pointer to first summand
 *              - const poly *b: pointer to second summand
 **************************************************/
void poly_add(poly *c, const poly *a, const poly *b) {
	u32 i;
	for (i = 0; i < N; ++i) c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - poly *c: pointer to output polynomial
 *              - const poly *a: pointer to first input polynomial
 *              - const poly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
void poly_sub(poly *c, const poly *a, const poly *b) {
	u32 i;
	for (i = 0; i < N; ++i) c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
 * Name:        poly_shiftl
 *
 * Description: Multiply polynomial by 2^D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-D} in absolute value.
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_shiftl(poly *a) {
	u32 i;
	for (i = 0; i < N; ++i) a->coeffs[i] <<= D;
}

/*************************************************
 * Name:        poly_ntt
 *
 * Description: Inplace forward NTT. Coefficients can grow by
 *              8*Q in absolute value.
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_ntt(poly *a) { ntt(a->coeffs); }

/*************************************************
 * Name:        poly_invntt_tomont
 *
 * Description: Inplace inverse NTT and multiplication by 2^{32}.
 *              Input coefficients need to be less than Q in absolute
 *              value and output coefficients are again bounded by Q.
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_invntt_tomont(poly *a) { invntt_tomont(a->coeffs); }

/*************************************************
 * Name:        poly_pointwise_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 *
 * Arguments:   - poly *c: pointer to output polynomial
 *              - const poly *a: pointer to first input polynomial
 *              - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
	u32 i;
	for (i = 0; i < N; ++i)
		c->coeffs[i] =
		    montgomery_reduce((i64)a->coeffs[i] * b->coeffs[i]);
}

/*************************************************
 * Name:        poly_power2round
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute c0, c1 such that c mod Q = c1*2^D + c0
 *              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
 *              - poly *a0: pointer to output polynomial with coefficients c0
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void poly_power2round(poly *a1, poly *a0, const poly *a) {
	u32 i;
	for (i = 0; i < N; ++i)
		a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

/*************************************************
 * Name:        poly_decompose
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
 *              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
 *              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
 *              - poly *a0: pointer to output polynomial with coefficients c0
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void poly_decompose(poly *a1, poly *a0, const poly *a) {
	u32 i;
	for (i = 0; i < N; ++i)
		a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
}

/*************************************************
 * Name:        poly_make_hint
 *
 * Description: Compute hint polynomial. The coefficients of which indicate
 *              whether the low bits of the corresponding coefficient of
 *              the input polynomial overflow into the high bits.
 *
 * Arguments:   - poly *h: pointer to output hint polynomial
 *              - const poly *a0: pointer to low part of input polynomial
 *              - const poly *a1: pointer to high part of input polynomial
 *
 * Returns number of 1 bits.
 **************************************************/
u32 poly_make_hint(poly *h, const poly *a0, const poly *a1) {
	u32 i, s = 0;
	for (i = 0; i < N; ++i) {
		h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
		s += h->coeffs[i];
	}
	return s;
}

/*************************************************
 * Name:        poly_use_hint
 *
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 *
 * Arguments:   - poly *b: pointer to output polynomial with corrected high bits
 *              - const poly *a: pointer to input polynomial
 *              - const poly *h: pointer to input hint polynomial
 **************************************************/
void poly_use_hint(poly *b, const poly *a, const poly *h) {
	u32 i;
	for (i = 0; i < N; ++i)
		b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
}

/*************************************************
 * Name:        poly_chknorm
 *
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input coefficients were reduced by reduce32().
 *
 * Arguments:   - const poly *a: pointer to polynomial
 *              - i32 B: norm bound
 *
 * Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 **************************************************/
int poly_chknorm(const poly *a, i32 B) {
	u32 i;
	i32 t;

	if (B > (Q - 1) / 8) return 1;

	/* It is ok to leak which coefficient violates the bound since
	   the probability for each coefficient is independent of secret
	   data but we must not leak the sign of the centralized representative.
	 */
	for (i = 0; i < N; ++i) {
		/* Absolute value */
		t = a->coeffs[i] >> 31;
		t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

		if (t >= B) {
			return 1;
		}
	}

	return 0;
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, Q-1] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - i32 *a: pointer to output array (allocated)
 *              - u32 len: number of coefficients to be sampled
 *              - const u8 *buf: array of random bytes
 *              - u32 buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static u32 rej_uniform(i32 *a, u32 len, const u8 *buf, u32 buflen) {
	u32 ctr, pos;
	u32 t;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		t = buf[pos++];
		t |= (u32)buf[pos++] << 8;
		t |= (u32)buf[pos++] << 16;
		t &= 0x7FFFFF;

		a[ctr] = t;
		ctr += t < Q;
	}

	return ctr;
}

/*************************************************
 * Name:        poly_uniform
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,Q-1] by performing rejection sampling on the
 *              output stream of SHAKE128(seed|nonce)
 *
 * Arguments:   - poly *a: pointer to output polynomial
 *              - const u8 seed[]: byte array with seed of length SEEDBYTES
 *              - u16 nonce: 2-byte nonce
 **************************************************/
#define POLY_UNIFORM_NBLOCKS \
	((768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES)
void poly_uniform(poly *a, StormContext *ctx) {
	static u64 next = U64_MAX / 2;
	u32 ctr = 0;
	__attribute__((aligned(32))) u8 buf[32];
	for (u32 i = 0; i < 32 / 8; i++)
		((u64 *)buf)[i] = (i + next++) * 0x9E3779B97F4A7C15ULL;

	while (ctr < N) {
		storm_next_block(ctx, buf);
		ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, 32);
	}
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-ETA, ETA] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - i32 *a: pointer to output array (allocated)
 *              - u32 len: number of coefficients to be sampled
 *              - const u8 *buf: array of random bytes
 *              - u32 buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static u32 rej_eta(i32 *a, u32 len, const u8 *buf, u32 buflen) {
	u32 ctr, pos;
	u32 t0, t1;
	ctr = pos = 0;
	while (ctr < len && pos < buflen) {
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;

#if ETA == 2
		if (t0 < 15) {
			t0 = t0 - (205 * t0 >> 10) * 5;
			a[ctr++] = 2 - t0;
		}
		if (t1 < 15 && ctr < len) {
			t1 = t1 - (205 * t1 >> 10) * 5;
			a[ctr++] = 2 - t1;
		}
#elif ETA == 4
		if (t0 < 9) a[ctr++] = 4 - t0;
		if (t1 < 9 && ctr < len) a[ctr++] = 4 - t1;
#endif
	}

	return ctr;
}

/*************************************************
 * Name:        poly_uniform_eta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-ETA,ETA] by performing rejection sampling on the
 *              output stream from SHAKE256(seed|nonce)
 *
 * Arguments:   - poly *a: pointer to output polynomial
 *              - const u8 seed[]: byte array with seed of length CRHBYTES
 *              - u16 nonce: 2-byte nonce
 **************************************************/
#if ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS \
	((136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
#elif ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS \
	((227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
#endif
void poly_uniform_eta(poly *a, StormContext *ctx) {
	static u64 next = U64_MAX / 2;
	u32 ctr = 0;
	__attribute__((aligned(32))) u8 buf[32];
	for (u32 i = 0; i < 32 / 8; i++)
		((u64 *)buf)[i] = (i + next++) * 0x9E3779B97F4A7C15ULL;

	while (ctr < N) {
		storm_next_block(ctx, buf);
		ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, 32);
	}
}

/*************************************************
 * Name:        poly_uniform_gamma1m1
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
 *              of SHAKE256(seed|nonce)
 *
 * Arguments:   - poly *a: pointer to output polynomial
 *              - const u8 seed[]: byte array with seed of length CRHBYTES
 *              - u16 nonce: 16-bit nonce
 **************************************************/
#define POLY_UNIFORM_GAMMA1_NBLOCKS \
	((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
void poly_uniform_gamma1(poly *a, const u8 seed[CRHBYTES], u16 nonce) {
	__attribute__((aligned(32))) u8 buf[704];
	StormContext ctx;

	for (u64 i = 0; i < 704 >> 3; i++)
		((u64 *)buf)[i] = (i + nonce) * 0x9E3779B97F4A7C15ULL;
	storm_init(&ctx, seed);

	for (u32 i = 0; i < 704; i += 32) storm_next_block(&ctx, buf + i);

	polyz_unpack(a, buf);
}

/*************************************************
 * Name:        challenge
 *
 * Description: Implementation of H. Samples polynomial with TAU nonzero
 *              coefficients in {-1,1} using the output stream of
 *              SHAKE256(seed).
 *
 * Arguments:   - poly *c: pointer to output polynomial
 *              - const u8 mu[]: byte array containing seed of length
 *CTILDEBYTES
 **************************************************/
void poly_challenge(poly *c, const u8 seed[CTILDEBYTES]) {
	u32 i, b, pos;
	u64 signs;
	__attribute__((aligned(32))) u8 buf[STORM_RATE] = {0};
	StormContext state;

	storm_init(&state, POLY_CHALLENGE_DOMAIN);
	fastmemcpy(buf, seed, 32);
	storm_next_block(&state, buf);

	signs = 0;
	for (i = 0; i < 8; ++i) signs |= (u64)buf[i] << 8 * i;
	pos = 8;

	fastmemset(c->coeffs, 0, sizeof(c->coeffs));
	for (i = N - TAU; i < N; ++i) {
		do {
			if (pos >= STORM_RATE) {
				storm_next_block(&state, buf);
				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);
		signs >>= 1;
	}
}

/*************************************************
 * Name:        polyeta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - u8 *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void polyeta_pack(u8 *r, const poly *a) {
	u32 i;
	u8 t[8];
#if ETA == 2
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
#elif ETA == 4
	for (i = 0; i < N / 2; ++i) {
		t[0] = ETA - a->coeffs[2 * i + 0];
		t[1] = ETA - a->coeffs[2 * i + 1];
		r[i] = t[0] | (t[1] << 4);
	}
#endif
}

/*************************************************
 * Name:        polyeta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *a: byte array with bit-packed polynomial
 **************************************************/
void polyeta_unpack(poly *r, const u8 *a) {
	u32 i;
#if ETA == 2
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
#elif ETA == 4
	for (i = 0; i < N / 2; ++i) {
		r->coeffs[2 * i + 0] = a[i] & 0x0F;
		r->coeffs[2 * i + 1] = a[i] >> 4;
		r->coeffs[2 * i + 0] = ETA - r->coeffs[2 * i + 0];
		r->coeffs[2 * i + 1] = ETA - r->coeffs[2 * i + 1];
	}
#endif
}

/*************************************************
 * Name:        polyt1_pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - u8 *r: pointer to output byte array with at least
 *                            POLYT1_PACKEDBYTES bytes
 *              - const poly *a: pointer to input polynomial
 **************************************************/
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

/*************************************************
 * Name:        polyt1_unpack
 *
 * Description: Unpack polynomial t1 with 10-bit coefficients.
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *a: byte array with bit-packed polynomial
 **************************************************/
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

/*************************************************
 * Name:        polyt0_pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - u8 *r: pointer to output byte array with at least
 *                            POLYT0_PACKEDBYTES bytes
 *              - const poly *a: pointer to input polynomial
 **************************************************/
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

/*************************************************
 * Name:        polyt0_unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *a: byte array with bit-packed polynomial
 **************************************************/
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

/*************************************************
 * Name:        polyz_pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - u8 *r: pointer to output byte array with at least
 *                            POLYZ_PACKEDBYTES bytes
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void polyz_pack(u8 *r, const poly *a) {
	u32 i;
	u32 t[4];

#if GAMMA1 == (1 << 17)
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
#elif GAMMA1 == (1 << 19)
	for (i = 0; i < N / 2; ++i) {
		t[0] = GAMMA1 - a->coeffs[2 * i + 0];
		t[1] = GAMMA1 - a->coeffs[2 * i + 1];

		r[5 * i + 0] = t[0];
		r[5 * i + 1] = t[0] >> 8;
		r[5 * i + 2] = t[0] >> 16;
		r[5 * i + 2] |= t[1] << 4;
		r[5 * i + 3] = t[1] >> 4;
		r[5 * i + 4] = t[1] >> 12;
	}
#endif
}

/*************************************************
 * Name:        polyz_unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *a: byte array with bit-packed polynomial
 **************************************************/
void polyz_unpack(poly *r, const u8 *a) {
	u32 i;

#if GAMMA1 == (1 << 17)
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
#elif GAMMA1 == (1 << 19)
	for (i = 0; i < N / 2; ++i) {
		r->coeffs[2 * i + 0] = a[5 * i + 0];
		r->coeffs[2 * i + 0] |= (u32)a[5 * i + 1] << 8;
		r->coeffs[2 * i + 0] |= (u32)a[5 * i + 2] << 16;
		r->coeffs[2 * i + 0] &= 0xFFFFF;

		r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
		r->coeffs[2 * i + 1] |= (u32)a[5 * i + 3] << 4;
		r->coeffs[2 * i + 1] |= (u32)a[5 * i + 4] << 12;
		/* r->coeffs[2*i+1] &= 0xFFFFF; */ /* No effect, since we're
						      anyway at 20 bits */

		r->coeffs[2 * i + 0] = GAMMA1 - r->coeffs[2 * i + 0];
		r->coeffs[2 * i + 1] = GAMMA1 - r->coeffs[2 * i + 1];
	}
#endif
}

/*************************************************
 * Name:        polyw1_pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - u8 *r: pointer to output byte array with at least
 *                            POLYW1_PACKEDBYTES bytes
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void polyw1_pack(u8 *r, const poly *a) {
	u32 i;
#if GAMMA2 == (Q - 1) / 88
	for (i = 0; i < N / 4; ++i) {
		r[3 * i + 0] = a->coeffs[4 * i + 0];
		r[3 * i + 0] |= a->coeffs[4 * i + 1] << 6;
		r[3 * i + 1] = a->coeffs[4 * i + 1] >> 2;
		r[3 * i + 1] |= a->coeffs[4 * i + 2] << 4;
		r[3 * i + 2] = a->coeffs[4 * i + 2] >> 4;
		r[3 * i + 2] |= a->coeffs[4 * i + 3] << 2;
	}
#elif GAMMA2 == (Q - 1) / 32
	for (i = 0; i < N / 2; ++i)
		r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
#endif
}
