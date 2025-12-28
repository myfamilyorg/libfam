#include <dilithium_scalar/packing.h>
#include <dilithium_scalar/params.h>
#include <dilithium_scalar/poly.h>
#include <dilithium_scalar/polyvec.h>

/*************************************************
 * Name:        pack_pk
 *
 * Description: Bit-pack public key pk = (rho, t1).
 *
 * Arguments:   - u8 pk[]: output byte array
 *              - const u8 rho[]: byte array containing rho
 *              - const polyveck *t1: pointer to vector t1
 **************************************************/
void pack_pk(u8 pk[CRYPTO_PUBLICKEYBYTES], const u8 rho[SEEDBYTES],
	     const polyveck *t1) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) pk[i] = rho[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: Unpack public key pk = (rho, t1).
 *
 * Arguments:   - const u8 rho[]: output byte array for rho
 *              - const polyveck *t1: pointer to output vector t1
 *              - u8 pk[]: byte array containing bit-packed pk
 **************************************************/
void unpack_pk(u8 rho[SEEDBYTES], polyveck *t1,
	       const u8 pk[CRYPTO_PUBLICKEYBYTES]) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = pk[i];
	pk += SEEDBYTES;

	for (i = 0; i < K; ++i)
		polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - u8 sk[]: output byte array
 *              - const u8 rho[]: byte array containing rho
 *              - const u8 tr[]: byte array containing tr
 *              - const u8 key[]: byte array containing key
 *              - const polyveck *t0: pointer to vector t0
 *              - const polyvecl *s1: pointer to vector s1
 *              - const polyveck *s2: pointer to vector s2
 **************************************************/
void pack_sk(u8 sk[CRYPTO_SECRETKEYBYTES], const u8 rho[SEEDBYTES],
	     const u8 tr[TRBYTES], const u8 key[SEEDBYTES],
	     const polyveck *t0, const polyvecl *s1, const polyveck *s2) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = rho[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) sk[i] = key[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) sk[i] = tr[i];
	sk += TRBYTES;

	for (i = 0; i < L; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
	sk += L * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - const u8 rho[]: output byte array for rho
 *              - const u8 tr[]: output byte array for tr
 *              - const u8 key[]: output byte array for key
 *              - const polyveck *t0: pointer to output vector t0
 *              - const polyvecl *s1: pointer to output vector s1
 *              - const polyveck *s2: pointer to output vector s2
 *              - u8 sk[]: byte array containing bit-packed sk
 **************************************************/
void unpack_sk(u8 rho[SEEDBYTES], u8 tr[TRBYTES],
	       u8 key[SEEDBYTES], polyveck *t0, polyvecl *s1, polyveck *s2,
	       const u8 sk[CRYPTO_SECRETKEYBYTES]) {
	unsigned int i;

	for (i = 0; i < SEEDBYTES; ++i) rho[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < SEEDBYTES; ++i) key[i] = sk[i];
	sk += SEEDBYTES;

	for (i = 0; i < TRBYTES; ++i) tr[i] = sk[i];
	sk += TRBYTES;

	for (i = 0; i < L; ++i)
		polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += L * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
	sk += K * POLYETA_PACKEDBYTES;

	for (i = 0; i < K; ++i)
		polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}

/*************************************************
 * Name:        pack_sig
 *
 * Description: Bit-pack signature sig = (c, z, h).
 *
 * Arguments:   - u8 sig[]: output byte array
 *              - const u8 *c: pointer to challenge hash length SEEDBYTES
 *              - const polyvecl *z: pointer to vector z
 *              - const polyveck *h: pointer to hint vector h
 **************************************************/
void pack_sig(u8 sig[CRYPTO_BYTES], const u8 c[CTILDEBYTES],
	      const polyvecl *z, const polyveck *h) {
	unsigned int i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) sig[i] = c[i];
	sig += CTILDEBYTES;

	for (i = 0; i < L; ++i)
		polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
	sig += L * POLYZ_PACKEDBYTES;

	/* Encode h */
	for (i = 0; i < OMEGA + K; ++i) sig[i] = 0;

	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j)
			if (h->vec[i].coeffs[j] != 0) sig[k++] = j;

		sig[OMEGA + i] = k;
	}
}

/*************************************************
 * Name:        unpack_sig
 *
 * Description: Unpack signature sig = (c, z, h).
 *
 * Arguments:   - u8 *c: pointer to output challenge hash
 *              - polyvecl *z: pointer to output vector z
 *              - polyveck *h: pointer to output hint vector h
 *              - const u8 sig[]: byte array containing
 *                bit-packed signature
 *
 * Returns 1 in case of malformed signature; otherwise 0.
 **************************************************/
int unpack_sig(u8 c[CTILDEBYTES], polyvecl *z, polyveck *h,
	       const u8 sig[CRYPTO_BYTES]) {
	unsigned int i, j, k;

	for (i = 0; i < CTILDEBYTES; ++i) c[i] = sig[i];
	sig += CTILDEBYTES;

	for (i = 0; i < L; ++i)
		polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
	sig += L * POLYZ_PACKEDBYTES;

	/* Decode h */
	k = 0;
	for (i = 0; i < K; ++i) {
		for (j = 0; j < N; ++j) h->vec[i].coeffs[j] = 0;

		if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) return 1;

		for (j = k; j < sig[OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > k && sig[j] <= sig[j - 1]) return 1;
			h->vec[i].coeffs[sig[j]] = 1;
		}

		k = sig[OMEGA + i];
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = k; j < OMEGA; ++j)
		if (sig[j]) return 1;

	return 0;
}
