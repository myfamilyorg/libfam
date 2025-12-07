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

#ifndef _LATTICE_H
#define _LATTICE_H

#include <libfam/rng.h>
#include <libfam/types.h>

#define LATTICE_PK_SIZE 32
#define LATTICE_SK_SIZE 32
#define LATTICE_SIG_SIZE 3369

typedef struct {
	u8 data[LATTICE_PK_SIZE];
} LatticePK;

typedef struct {
	u8 data[LATTICE_SK_SIZE];
} LatticeSK;

typedef struct {
	u8 data[LATTICE_SIG_SIZE];
} LatticeSig;

typedef struct LatticeAggSig LatticeAggSig;

void lattice_keygen(const u8 seed[32], LatticeSK *sk);
void lattice_pubkey(const LatticeSK *sec_key, LatticePK *pk);
i32 lattice_sign(const LatticeSK *sk, const u8 *message, u64 message_len,
		 LatticeSig *sig);
i32 lattice_verify(LatticePK *pub_key, const u8 *message, u64 message_len,
		   const LatticeSig *sig);

i32 lattice_aggregate(const LatticeSig partials[], u64 n, LatticeAggSig **out,
		      u8 merkle_root[32]);
i32 lattice_aggregate_verify(LatticeAggSig *sig, const u8 *expected_msg,
			     u64 msg_len);
void lattice_aggregate_destroy(LatticeAggSig *agg);

#endif /* _LATTICE_H */
