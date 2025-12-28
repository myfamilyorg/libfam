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

#ifndef PARAMS_H
#define PARAMS_H

#ifndef __ASSEMBLER__
#include <libfam/types.h>
#endif /* __ASSEMBLER__ */

#include <dilithium_avx2/config.h>

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q - 1) / 88)
#define OMEGA 80
#define CTILDEBYTES 32

#define POLYT1_PACKEDBYTES 320
#define POLYT0_PACKEDBYTES 416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#define POLYZ_PACKEDBYTES 576
#define POLYW1_PACKEDBYTES 192

#define POLYETA_PACKEDBYTES 96

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K * POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES                                \
	(2 * SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + \
	 K * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES \
	(CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
