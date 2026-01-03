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

#ifndef INDCPA_H
#define INDCPA_H

#include <kyber_avx2/ns.h>
#include <kyber_avx2/polyvec.h>
#include <libfam/kem_impl.h>

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const u8 seed[KYBER_SYMBYTES], int transposed);

#define indcpa_keypair_derand KYBER_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
			   u8 sk[KYBER_INDCPA_SECRETKEYBYTES],
			   const u8 coins[KYBER_SYMBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(u8 c[KYBER_INDCPA_BYTES], const u8 m[KYBER_INDCPA_MSGBYTES],
		const u8 pk[KYBER_INDCPA_PUBLICKEYBYTES],
		const u8 coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(u8 m[KYBER_INDCPA_MSGBYTES], const u8 c[KYBER_INDCPA_BYTES],
		const u8 sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
