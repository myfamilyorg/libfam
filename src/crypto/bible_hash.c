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

#include <libfam/bible.h>
#include <libfam/bible_hash.h>
#include <libfam/string.h>

enum SHA3_FLAGS { SHA3_FLAGS_NONE = 0, SHA3_FLAGS_KECCAK = 1 };

/*
 * This flag is used to configure "pure" Keccak, as opposed to NIST SHA3.
 */
#define SHA3_USE_KECCAK_FLAG 0x80000000
#define SHA3_CW(x) ((x) & (~SHA3_USE_KECCAK_FLAG))

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> ((sizeof(u64) * 8) - (y))))
#endif

#define LOOKUP_COUNT 48

static const u64 keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)};

static const u32 keccakf_rotc[24] = {1,	 3,  6,	 10, 15, 21, 28, 36,
				     45, 55, 2,	 14, 27, 41, 56, 8,
				     25, 43, 62, 18, 39, 61, 20, 44};

static const u32 keccakf_piln[24] = {10, 7,  11, 17, 18, 3,  5,	 16,
				     8,	 21, 24, 4,  15, 23, 19, 13,
				     12, 2,  20, 14, 22, 9,  6,	 1};

static void bkeccakf(u64 s[24]) {
	i32 i, j, round;
	u64 t, bc[4];
#define KECCAK_ROUNDS 24
	const Bible *bible_dat = bible();

	for (round = 0; round < KECCAK_ROUNDS; round++) {
		/* Theta */
		for (i = 0; i < 4; i++)
			bc[i] =
			    s[i] ^ s[i + 4] ^ s[i + 8] ^ s[i + 12] ^ s[i + 16];

		for (i = 0; i < 4; i++) {
			t = bc[(i + 4) % 4] ^ SHA3_ROTL64(bc[(i + 1) % 4], 1);
			for (j = 0; j < 24; j += 4) s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = s[j];
			s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		for (u32 i = 0; i < LOOKUP_COUNT; i++) {
			__attribute__((aligned(32))) u8 out[32];
			bible_lookup(bible_dat, s[i % 24], out);
			u64 v1 = *(u64 *)out;
			u64 v2 = *(u64 *)(out + 8);
			u64 v3 = *(u64 *)(out + 16);
			u64 v4 = *(u64 *)(out + 24);
			s[(i + 1) % 24] ^= v1 ^ v2 ^ v3 ^ v4;
		}

		/* Chi */
		for (j = 0; j < 24; j += 4) {
			for (i = 0; i < 4; i++) bc[i] = s[j + i];
			for (i = 0; i < 4; i++)
				s[j + i] ^=
				    (~bc[(i + 1) % 4]) & bc[(i + 2) % 4];
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}

/* *************************** Public Interface ************************ */

void bible_hash_init(BibleHash *ctx) {
	memset((u8 *)ctx, 0, sizeof(BibleHash));
	ctx->capacityWords = 2 * 256 / (8 * sizeof(u64));
}

void bible_hash_update(BibleHash *ctx, void const *bufIn, u64 len) {
	/* 0...7 -- how much is needed to have a word */
	u32 old_tail = (8 - ctx->byteIndex) & 7;

	u64 words;
	u32 tail;
	u64 i;

	const u8 *buf = bufIn;

	if (len < old_tail) { /* have no complete word or haven't started
			       * the word yet */
		/* endian-independent code follows: */
		while (len--)
			ctx->saved |= (u64)(*(buf++))
				      << ((ctx->byteIndex++) * 8);
		return;
	}

	if (old_tail) { /* will have one word to process */
		/* endian-independent code follows: */
		len -= old_tail;
		while (old_tail--)
			ctx->saved |= (u64)(*(buf++))
				      << ((ctx->byteIndex++) * 8);

		/* now ready to add saved to the sponge */
		ctx->u.s[ctx->wordIndex] ^= ctx->saved;
		ctx->byteIndex = 0;
		ctx->saved = 0;
		if (++ctx->wordIndex ==
		    (SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
			bkeccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

	/* now work in full words directly from input */

	words = len / sizeof(u64);
	tail = len - words * sizeof(u64);

	for (i = 0; i < words; i++, buf += sizeof(u64)) {
		const u64 t =
		    (u64)(buf[0]) | ((u64)(buf[1]) << 8 * 1) |
		    ((u64)(buf[2]) << 8 * 2) | ((u64)(buf[3]) << 8 * 3) |
		    ((u64)(buf[4]) << 8 * 4) | ((u64)(buf[5]) << 8 * 5) |
		    ((u64)(buf[6]) << 8 * 6) | ((u64)(buf[7]) << 8 * 7);
		ctx->u.s[ctx->wordIndex] ^= t;
		if (++ctx->wordIndex ==
		    (SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
			bkeccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

	/* finally, save the partial word */
	while (tail--)
		ctx->saved |= (u64)(*(buf++)) << ((ctx->byteIndex++) * 8);
}

#include <libfam/sysext.h>
#include <libfam/test_base.h>

void const *bible_hash_finalize(BibleHash *ctx) {
	u64 t = (u64)(((u64)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));
	ctx->u.s[ctx->wordIndex] ^= ctx->saved ^ t;
	write_num(2, SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1);
	pwrite(2, "\n", 1, 0);
	write_num(2, SPONGE_WORDS);
	pwrite(2, "\n", 1, 0);

	ctx->u.s[SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1] ^=
	    SHA3_CONST(0x8000000000000000UL);
	bkeccakf(ctx->u.s);

	{
		u32 i;
		for (i = 0; i < SPONGE_WORDS; i++) {
			const u32 t1 = (u32)ctx->u.s[i];
			const u32 t2 = (u32)((ctx->u.s[i] >> 16) >> 16);
			ctx->u.sb[i * 8 + 0] = (u8)(t1);
			ctx->u.sb[i * 8 + 1] = (u8)(t1 >> 8);
			ctx->u.sb[i * 8 + 2] = (u8)(t1 >> 16);
			ctx->u.sb[i * 8 + 3] = (u8)(t1 >> 24);
			ctx->u.sb[i * 8 + 4] = (u8)(t2);
			ctx->u.sb[i * 8 + 5] = (u8)(t2 >> 8);
			ctx->u.sb[i * 8 + 6] = (u8)(t2 >> 16);
			ctx->u.sb[i * 8 + 7] = (u8)(t2 >> 24);
		}
	}

	return (ctx->u.sb);
}
