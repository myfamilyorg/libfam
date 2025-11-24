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

#ifdef __AVX2__
#include <immintrin.h>
#endif /* __AVX2__ */

#include <libfam/sha3.h>
#include <libfam/string.h>
#include <libfam/test_base.h>
#include <libfam/utils.h>

#define KECCAK_ROUNDS 24

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

#ifdef __AVX2__
static void keccakf(u64 s[25]) {
	i32 i, j, round;
	u64 t;
	__m256i bc0;
	u64 bc4;

	for (round = 0; round < KECCAK_ROUNDS; round++) {
		/* Theta */
		bc0 = _mm256_xor_si256(
		    _mm256_loadu_si256((const __m256i *)s),
		    _mm256_xor_si256(
			_mm256_loadu_si256((const __m256i *)(s + 5)),
			_mm256_xor_si256(
			    _mm256_loadu_si256((const __m256i *)(s + 10)),
			    _mm256_xor_si256(
				_mm256_loadu_si256((const __m256i *)(s + 15)),
				_mm256_loadu_si256(
				    (const __m256i *)(s + 20))))));
		bc4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

		for (i = 0; i < 5; i++) {
			u64 bca, bcb;
			u8 ai = (i + 4) % 5;
			u8 bi = (i + 1) % 5;
			if (ai < 4)
				bca = ((u64 *)(&bc0))[ai];
			else
				bca = bc4;
			if (bi < 4)
				bcb = ((u64 *)(&bc0))[bi];
			else
				bcb = bc4;
			t = bca ^ SHA3_ROTL64(bcb, 1);
			for (j = 0; j < 25; j += 5) s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];

		for (i = 0; i < 24; i++) {
			u64 tmp;
			j = keccakf_piln[i];
			tmp = s[j];
			s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
			t = tmp;
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 4; i++) ((u64 *)&bc0)[i] = s[j + i];
			bc4 = s[j + 4];
			for (i = 0; i < 5; i++) {
				u8 i1 = (i + 1) % 5;
				u8 i2 = (i + 2) % 5;
				u64 b1, b2;
				if (i1 < 4)
					b1 = ~(((u64 *)&bc0)[i1]);
				else
					b1 = ~bc4;
				if (i2 < 4)
					b2 = ((u64 *)&bc0)[i2];
				else
					b2 = bc4;
				s[j + i] ^= b1 & b2;
			}
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}
#else
static void keccakf(u64 s[25]) {
	i32 i, j, round;
	u64 t, bc[5];
#define KECCAK_ROUNDS 24

	for (round = 0; round < KECCAK_ROUNDS; round++) {
		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] =
			    s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5) s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = s[j];
			s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++) bc[i] = s[j + i];
			for (i = 0; i < 5; i++)
				s[j + i] ^=
				    (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}
#endif /* !__AVX2__ */

/* *************************** Public Inteface ************************ */

PUBLIC i32 sha3_init(void *priv, u32 bitSize) {
	Sha3Context *ctx = (Sha3Context *)priv;
	if (bitSize < 256 || bitSize > 736 || bitSize % 32 != 0) return -1;
	memset((u8 *)ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 2 * bitSize / (8 * sizeof(u64));
	return 0;
}

PUBLIC enum SHA3_FLAGS sha3_setflags(void *priv, enum SHA3_FLAGS flags) {
	Sha3Context *ctx = (Sha3Context *)priv;
	flags &= SHA3_FLAGS_KECCAK;
	ctx->capacityWords |=
	    (flags == SHA3_FLAGS_KECCAK ? SHA3_USE_KECCAK_FLAG : 0);
	return flags;
}

PUBLIC void sha3_init256(void *priv) {
	sha3_init(priv, 256);
	sha3_setflags(priv, SHA3_FLAGS_NONE);
}

PUBLIC void sha3_init384(void *priv) {
	sha3_init(priv, 384);
	sha3_setflags(priv, SHA3_FLAGS_NONE);
}

PUBLIC void sha3_init512(void *priv) {
	sha3_init(priv, 512);
	sha3_setflags(priv, SHA3_FLAGS_NONE);
}

PUBLIC void sha3_update(void *priv, void const *bufIn, u64 len) {
	Sha3Context *ctx = (Sha3Context *)priv;
	u32 old_tail = (8 - ctx->byteIndex) & 7;
	u64 words;
	u32 tail;
	u64 i;
	const u8 *buf = bufIn;

	if (len < old_tail) {
		while (len--)
			ctx->saved |= (u64)(*(buf++))
				      << ((ctx->byteIndex++) * 8);
		return;
	}

	if (old_tail) {
		len -= old_tail;
		while (old_tail--)
			ctx->saved |= (u64)(*(buf++))
				      << ((ctx->byteIndex++) * 8);

		ctx->u.s[ctx->wordIndex] ^= ctx->saved;
		ctx->byteIndex = 0;
		ctx->saved = 0;
		if (++ctx->wordIndex ==
		    (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
			keccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

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
		    (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
			keccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

	while (tail--)
		ctx->saved |= (u64)(*(buf++)) << ((ctx->byteIndex++) * 8);
}

PUBLIC void const *sha3_finalize(void *priv) {
	Sha3Context *ctx = (Sha3Context *)priv;
	u64 t = (u64)(((u64)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));
	ctx->u.s[ctx->wordIndex] ^= ctx->saved ^ t;
	ctx->u.s[SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1] ^=
	    SHA3_CONST(0x8000000000000000UL);
	keccakf(ctx->u.s);

	{
		u32 i;
		for (i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
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
