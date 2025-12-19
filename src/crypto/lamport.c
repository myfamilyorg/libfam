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

#include <libfam/lamport.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/verihash.h>

static const __attribute__((aligned(32))) u8 LAMPORT_DOMAIN[32] = {1,  1, 1, 1,
								   17, 7, 7, 7};

void lamport_keyfrom(const u8 seed[32], LamportPubKey *pk, LamportSecKey *sk,
		     LamportType t) {
	sk->t = t;
	pk->t = t;
	if (t == LamportTypeStorm256) {
		Storm256Context ctx;
		storm256_init(&ctx, LAMPORT_DOMAIN);
		fastmemcpy(sk->data, seed, 32);
		for (u32 i = 0; i < 512; i++)
			storm256_next_block(&ctx, sk->data + i * 32);
		for (u32 i = 0; i < 512; i++) {
			storm256_init(&ctx, LAMPORT_DOMAIN);
			fastmemcpy(pk->data + i * 32, sk->data + i * 32, 32);
			storm256_next_block(&ctx, pk->data + i * 32);
		}
	} else {
		u8 buffer[32];
		fastmemcpy(buffer, seed, 32);

		for (u32 i = 0; i < 512; i++) {
			verihash256(buffer, 32, sk->data + i * 32);
			buffer[0]++;
			buffer[1] += i == 256;
		}
		for (u32 i = 0; i < 512; i++)
			verihash256(sk->data + i * 32, 32, pk->data + i * 32);
	}
}

void lamport_sign(const LamportSecKey *sk, const u8 message[32],
		  LamportSig *sig) {
	sig->t = sk->t;
	for (u32 i = 0; i < 256; i++) {
		u32 bit = (message[i >> 3] >> (i & 7)) & 1;
		u32 sk_idx = i + bit * 256;
		fastmemcpy(sig->data + i * 32, sk->data + sk_idx * 32, 32);
	}
}
i32 lamport_verify(const LamportPubKey *pk, const LamportSig *sig,
		   const u8 message[32]) {
	__attribute__((aligned(32))) u8 hash_out[32];
	Storm256Context ctx;
	for (u32 i = 0; i < 256; i++) {
		u32 bit = (message[i >> 3] >> (i & 7)) & 1;
		u32 pk_idx = i + bit * 256;
		if (pk->t == LamportTypeStorm256) {
			fastmemcpy(hash_out, sig->data + i * 32, 32);
			storm256_init(&ctx, LAMPORT_DOMAIN);
			storm256_next_block(&ctx, hash_out);
			if (fastmemcmp(hash_out, pk->data + pk_idx * 32, 32) !=
			    0)
				return -1;
		} else {
			verihash256(sig->data + i * 32, 32, hash_out);
			if (fastmemcmp(hash_out, pk->data + pk_idx * 32, 32) !=
			    0)
				return -1;
		}
	}
	return 0;
}
