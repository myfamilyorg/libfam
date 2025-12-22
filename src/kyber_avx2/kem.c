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

#include <kyber_avx2/indcpa.h>
#include <kyber_avx2/kem.h>
#include <kyber_avx2/verify.h>
#include <kyber_common/params.h>
#include <libfam/kem_impl.h>
#include <libfam/string.h>

void crypto_kem_keypair_derand(u8 *pk, u8 *sk, const u8 *coins) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES] = {0};

	indcpa_keypair_derand(pk, sk, coins);
	fastmemcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	fastmemset(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, 0, 32);
	storm_next_block(&ctx, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES);

	fastmemcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
		   coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void crypto_kem_keypair(u8 *pk, u8 *sk, Rng *rng) {
	__attribute__((aligned(32))) u8 coins[2 * KYBER_SYMBYTES] = {0};
	rng_gen(rng, coins, 2 * KYBER_SYMBYTES);
	crypto_kem_keypair_derand(pk, sk, coins);
}

void crypto_kem_enc_derand(u8 *ct, u8 *ss, const u8 *pk, const u8 *coins) {
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 pk_copy[KYBER_PUBLICKEYBYTES] = {0};
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES];
	StormContext ctx;

	fastmemcpy(buf, coins, KYBER_SYMBYTES);

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(pk_copy, pk, KYBER_PUBLICKEYBYTES);
	for (u32 i = 0; i < KYBER_PUBLICKEYBYTES; i += 32)
		storm_next_block(&ctx, pk_copy + i);
	storm_next_block(&ctx, buf + KYBER_SYMBYTES);

	storm_init(&ctx, HASH_DOMAIN);
	fastmemcpy(kr, buf, 2 * KYBER_SYMBYTES);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + 32);

	indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

	fastmemcpy(ss, kr, KYBER_SYMBYTES);
}

void crypto_kem_enc(u8 *ct, u8 *ss, const u8 *pk, Rng *rng) {
	__attribute__((aligned(32))) u8 coins[KYBER_SYMBYTES] = {0};
	rng_gen(rng, coins, KYBER_SYMBYTES);
	crypto_kem_enc_derand(ct, ss, pk, coins);
}

void crypto_kem_dec(u8 *ss, const u8 *ct, const u8 *sk) {
	int fail;
	__attribute__((aligned(32))) u8 buf[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 kr[2 * KYBER_SYMBYTES] = {0};
	__attribute__((aligned(32))) u8 cmp[KYBER_CIPHERTEXTBYTES] = {0};
	__attribute__((aligned(32))) u8 sk_copy[32] = {0};

	const u8 *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
	StormContext ctx;

	indcpa_dec(buf, ct, sk);

	fastmemcpy(buf + KYBER_SYMBYTES,
		   sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
		   KYBER_SYMBYTES);

	fastmemcpy(kr, buf, 2 * KYBER_SYMBYTES);
	storm_init(&ctx, HASH_DOMAIN);
	storm_next_block(&ctx, kr);
	storm_next_block(&ctx, kr + 32);

	indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	fastmemset(ss, 0, 32);
	fastmemcpy(sk_copy, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, 32);
	storm_init(&ctx, sk_copy);
	for (u32 i = 0; i < KYBER_CIPHERTEXTBYTES; i += 32)
		storm_next_block(&ctx, cmp + i);
	storm_next_block(&ctx, ss);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);
}
