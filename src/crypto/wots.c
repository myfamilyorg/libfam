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
#include <libfam/wots.h>

/* WOTS+ w = 256, n = 32 bytes */
#define WOTS_W 256
#define WOTS_LOG_W 8
#define WOTS_N 32
#define WOTS_LEN1 32 /* 256 message bits → 32 digits */
#define WOTS_LEN2 2  /* checksum: ceil((32*8)/8) = 32 bits → 2 digits */
#define WOTS_LEN (WOTS_LEN1 + WOTS_LEN2) /* 34 chains total */

/* Domain separators – feel free to change */
static const u8 DOMAIN_CHAIN[32] = {0x01, 'W', 'O', 'T', 'S', '+',
				    'c',  'h', 'a', 'i', 'n'};
static const u8 DOMAIN_BASE[32] = {0x01, 'W', 'O', 'T', 'S',
				   '+',	 'b', 'a', 's', 'e'};

/* Hash a single block with a domain separator */
static void storm_hash(u8 out[32], const u8 domain[32], const u8 in[32],
		       Storm256Context *ctx) {
	u8 block[32];
	fastmemcpy(block, in, 32);
	storm256_init(ctx, domain);
	storm256_next_block(ctx, block);
	fastmemcpy(out, block, 32);
}

/* Iterate a chain: start from `in`, apply hash `steps` times */
static void wots_chain(u8 out[32], const u8 in[32], unsigned steps) {
	u8 tmp[32];
	Storm256Context ctx;
	fastmemcpy(tmp, in, 32);
	storm256_init(&ctx, DOMAIN_CHAIN);

	for (u32 i = 0; i < steps; ++i) {
		storm_hash(tmp, DOMAIN_CHAIN, tmp, &ctx);
	}
	fastmemcpy(out, tmp, 32);
}

/* ------------------------------------------------------------------ */
void wots_keyfrom(const u8 seed[32], WotsPubKey *pk, WotsSecKey *sk) {
	Storm256Context ctx;
	u8 block[32];

	/* Expand seed into secret key (34 random 32-byte values) */
	storm256_init(&ctx, DOMAIN_BASE);
	fastmemcpy(block, seed, 32);
	storm256_next_block(&ctx, block); /* absorb seed */
	fastmemset(sk->data, 0, WOTS_SECKEY_SIZE);

	for (unsigned i = 0; i < WOTS_LEN; ++i) {
		storm256_next_block(&ctx, sk->data + i * WOTS_N);
	}

	/* Compute public key: each secret chain hashed (w-1) = 255 times */
	for (unsigned i = 0; i < WOTS_LEN; ++i) {
		const u8 *base = sk->data + i * WOTS_N;
		wots_chain(pk->data + i * WOTS_N, base, WOTS_W - 1);
	}
}

/* ------------------------------------------------------------------ */
void wots_sign(const WotsSecKey *sk, const u8 message[32], WotsSig *sig) {
	u16 checksum = 0;

	/* Message digits (32 bytes → 32 digits of 8 bits each) */
	for (unsigned i = 0; i < WOTS_LEN1; ++i) {
		u8 digit = message[i];
		checksum += (WOTS_W - 1) - digit; /* accumulate checksum */
		unsigned steps = digit;
		wots_chain(sig->data + i * WOTS_N, sk->data + i * WOTS_N,
			   steps);
	}

	/* Checksum digits (16 bits → 2 digits) */
	for (unsigned i = 0; i < WOTS_LEN2; ++i) {
		u8 digit = (checksum >> (8 * i)) & 0xFF;
		unsigned steps = digit;
		unsigned chain_idx = WOTS_LEN1 + i;
		wots_chain(sig->data + chain_idx * WOTS_N,
			   sk->data + chain_idx * WOTS_N, steps);
	}
}

/* ------------------------------------------------------------------ */
i32 wots_verify(const WotsPubKey *pk, const WotsSig *sig,
		const u8 message[32]) {
	u16 checksum = 0;
	u8 tmp[32];

	/* Verify message chains and recompute checksum */
	for (unsigned i = 0; i < WOTS_LEN1; ++i) {
		u8 digit = message[i];
		checksum += (WOTS_W - 1) - digit;
		unsigned steps = (WOTS_W - 1) - digit;
		const u8 *revealed = sig->data + i * WOTS_N;
		wots_chain(tmp, revealed, steps);
		if (fastmemcmp(tmp, pk->data + i * WOTS_N, WOTS_N) != 0)
			return -1;
	}

	/* Verify checksum chains */
	for (unsigned i = 0; i < WOTS_LEN2; ++i) {
		u8 expected_digit = (checksum >> (8 * i)) & 0xFF;
		unsigned steps = (WOTS_W - 1) - expected_digit;
		unsigned chain_idx = WOTS_LEN1 + i;
		const u8 *revealed = sig->data + chain_idx * WOTS_N;
		wots_chain(tmp, revealed, steps);
		if (fastmemcmp(tmp, pk->data + chain_idx * WOTS_N, WOTS_N) != 0)
			return -1;
	}

	return 0;
}
