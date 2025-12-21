#include <kyber/cbd.h>
#include <kyber/params.h>

/*************************************************
 * Name:        load32_littleendian
 *
 * Description: load 4 bytes into a 32-bit integer
 *              in little-endian order
 *
 * Arguments:   - const u8 *x: pointer to input byte array
 *
 * Returns 32-bit unsigned integer loaded from x
 **************************************************/
static u32 load32_littleendian(const u8 x[4]) {
	u32 r;
	r = (u32)x[0];
	r |= (u32)x[1] << 8;
	r |= (u32)x[2] << 16;
	r |= (u32)x[3] << 24;
	return r;
}

/*************************************************
 * Name:        load24_littleendian
 *
 * Description: load 3 bytes into a 32-bit integer
 *              in little-endian order.
 *              This function is only needed for Kyber-512
 *
 * Arguments:   - const u8 *x: pointer to input byte array
 *
 * Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
 **************************************************/
#if KYBER_ETA1 == 3
static u32 load24_littleendian(const u8 x[3]) {
	u32 r;
	r = (u32)x[0];
	r |= (u32)x[1] << 8;
	r |= (u32)x[2] << 16;
	return r;
}
#endif

/*************************************************
 * Name:        cbd2
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=2
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *buf: pointer to input byte array
 **************************************************/
static void cbd2(poly *r, const u8 buf[2 * KYBER_N / 4]) {
	unsigned int i, j;
	u32 t, d;
	int16_t a, b;

	for (i = 0; i < KYBER_N / 8; i++) {
		t = load32_littleendian(buf + 4 * i);
		d = t & 0x55555555;
		d += (t >> 1) & 0x55555555;

		for (j = 0; j < 8; j++) {
			a = (d >> (4 * j + 0)) & 0x3;
			b = (d >> (4 * j + 2)) & 0x3;
			r->coeffs[8 * i + j] = a - b;
		}
	}
}

/*************************************************
 * Name:        cbd3
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=3.
 *              This function is only needed for Kyber-512
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const u8 *buf: pointer to input byte array
 **************************************************/
#if KYBER_ETA1 == 3
static void cbd3(poly *r, const u8 buf[3 * KYBER_N / 4]) {
	unsigned int i, j;
	u32 t, d;
	int16_t a, b;

	for (i = 0; i < KYBER_N / 4; i++) {
		t = load24_littleendian(buf + 3 * i);
		d = t & 0x00249249;
		d += (t >> 1) & 0x00249249;
		d += (t >> 2) & 0x00249249;

		for (j = 0; j < 4; j++) {
			a = (d >> (6 * j + 0)) & 0x7;
			b = (d >> (6 * j + 3)) & 0x7;
			r->coeffs[4 * i + j] = a - b;
		}
	}
}
#endif

void poly_cbd_eta1(poly *r, const u8 buf[KYBER_ETA1 * KYBER_N / 4]) {
#if KYBER_ETA1 == 2
	cbd2(r, buf);
#elif KYBER_ETA1 == 3
	cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

void poly_cbd_eta2(poly *r, const u8 buf[KYBER_ETA2 * KYBER_N / 4]) {
#if KYBER_ETA2 == 2
	cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}
