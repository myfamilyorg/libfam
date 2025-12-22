#ifndef API_H
#define API_H

#define pqcrystals_kyber512_SECRETKEYBYTES 1632
#define pqcrystals_kyber512_PUBLICKEYBYTES 800
#define pqcrystals_kyber512_CIPHERTEXTBYTES 768
#define pqcrystals_kyber512_KEYPAIRCOINBYTES 64
#define pqcrystals_kyber512_ENCCOINBYTES 32
#define pqcrystals_kyber512_BYTES 32

#define pqcrystals_kyber512_avx2_SECRETKEYBYTES \
	pqcrystals_kyber512_SECRETKEYBYTES
#define pqcrystals_kyber512_avx2_PUBLICKEYBYTES \
	pqcrystals_kyber512_PUBLICKEYBYTES
#define pqcrystals_kyber512_avx2_CIPHERTEXTBYTES \
	pqcrystals_kyber512_CIPHERTEXTBYTES
#define pqcrystals_kyber512_avx2_KEYPAIRCOINBYTES \
	pqcrystals_kyber512_KEYPAIRCOINBYTES
#define pqcrystals_kyber512_avx2_ENCCOINBYTES pqcrystals_kyber512_ENCCOINBYTES
#define pqcrystals_kyber512_avx2_BYTES pqcrystals_kyber512_BYTES

int pqcrystals_kyber512_avx2_keypair_derand(u8 *pk, u8 *sk, const u8 *coins);
int pqcrystals_kyber512_avx2_keypair(u8 *pk, u8 *sk);
int pqcrystals_kyber512_avx2_enc_derand(u8 *ct, u8 *ss, const u8 *pk,
					const u8 *coins);
int pqcrystals_kyber512_avx2_enc(u8 *ct, u8 *ss, const u8 *pk);
int pqcrystals_kyber512_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);

#define pqcrystals_kyber768_SECRETKEYBYTES 2400
#define pqcrystals_kyber768_PUBLICKEYBYTES 1184
#define pqcrystals_kyber768_CIPHERTEXTBYTES 1088
#define pqcrystals_kyber768_KEYPAIRCOINBYTES 64
#define pqcrystals_kyber768_ENCCOINBYTES 32
#define pqcrystals_kyber768_BYTES 32

#define pqcrystals_kyber768_avx2_SECRETKEYBYTES \
	pqcrystals_kyber768_SECRETKEYBYTES
#define pqcrystals_kyber768_avx2_PUBLICKEYBYTES \
	pqcrystals_kyber768_PUBLICKEYBYTES
#define pqcrystals_kyber768_avx2_CIPHERTEXTBYTES \
	pqcrystals_kyber768_CIPHERTEXTBYTES
#define pqcrystals_kyber768_avx2_KEYPAIRCOINBYTES \
	pqcrystals_kyber768_KEYPAIRCOINBYTES
#define pqcrystals_kyber768_avx2_ENCCOINBYTES pqcrystals_kyber768_ENCCOINBYTES
#define pqcrystals_kyber768_avx2_BYTES pqcrystals_kyber768_BYTES

int pqcrystals_kyber768_avx2_keypair_derand(u8 *pk, u8 *sk, const u8 *coins);
int pqcrystals_kyber768_avx2_keypair(u8 *pk, u8 *sk);
int pqcrystals_kyber768_avx2_enc_derand(u8 *ct, u8 *ss, const u8 *pk,
					const u8 *coins);
int pqcrystals_kyber768_avx2_enc(u8 *ct, u8 *ss, const u8 *pk);
int pqcrystals_kyber768_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);

#define pqcrystals_kyber1024_SECRETKEYBYTES 3168
#define pqcrystals_kyber1024_PUBLICKEYBYTES 1568
#define pqcrystals_kyber1024_CIPHERTEXTBYTES 1568
#define pqcrystals_kyber1024_KEYPAIRCOINBYTES 64
#define pqcrystals_kyber1024_ENCCOINBYTES 32
#define pqcrystals_kyber1024_BYTES 32

#define pqcrystals_kyber1024_avx2_SECRETKEYBYTES \
	pqcrystals_kyber1024_SECRETKEYBYTES
#define pqcrystals_kyber1024_avx2_PUBLICKEYBYTES \
	pqcrystals_kyber1024_PUBLICKEYBYTES
#define pqcrystals_kyber1024_avx2_CIPHERTEXTBYTES \
	pqcrystals_kyber1024_CIPHERTEXTBYTES
#define pqcrystals_kyber1024_avx2_KEYPAIRCOINBYTES \
	pqcrystals_kyber1024_KEYPAIRCOINBYTES
#define pqcrystals_kyber1024_avx2_ENCCOINBYTES pqcrystals_kyber1024_ENCCOINBYTES
#define pqcrystals_kyber1024_avx2_BYTES pqcrystals_kyber1024_BYTES

int pqcrystals_kyber1024_avx2_keypair_derand(u8 *pk, u8 *sk, const u8 *coins);
int pqcrystals_kyber1024_avx2_keypair(u8 *pk, u8 *sk);
int pqcrystals_kyber1024_avx2_enc_derand(u8 *ct, u8 *ss, const u8 *pk,
					 const u8 *coins);
int pqcrystals_kyber1024_avx2_enc(u8 *ct, u8 *ss, const u8 *pk);
int pqcrystals_kyber1024_avx2_dec(u8 *ss, const u8 *ct, const u8 *sk);

#endif
