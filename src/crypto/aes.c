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

#include <libfam/aes.H>
#include <libfam/format.H>
#include <libfam/misc.H>
#include <libfam/types.H>

#define Nb 4
#define Nk 8
#define Nr 14

typedef u8 state_t[4][4];

static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const u8 Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
			    0x20, 0x40, 0x80, 0x1b, 0x36};

#define getSBoxValue(num) (sbox[(num)])

static void KeyExpansion(u8* RoundKey, const u8* Key) {
	unsigned i, j, k;
	u8 tempa[4];

	for (i = 0; i < Nk; ++i) {
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	for (i = Nk; i < Nb * (Nr + 1); ++i) {
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];
		}

		if (i % Nk == 0) {
			{
				const u8 u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}
		if (i % Nk == 4) {
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
		}
		j = i * 4;
		k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void aes_init(AesContext* ctx, const u8* key, const u8* iv) {
	KeyExpansion(ctx->RoundKey, key);
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
void aes_set_iv(AesContext* ctx, const u8* iv) {
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

static void AddRoundKey(u8 round, state_t* state, const u8* RoundKey) {
	u8 i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			(*state)[i][j] ^=
			    RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

static void SubBytes(state_t* state) {
	u8 i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

static void ShiftRows(state_t* state) {
	u8 temp;

	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static u8 xtime(u8 x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

static void MixColumns(state_t* state) {
	u8 i;
	u8 Tmp, Tm, t;
	for (i = 0; i < 4; ++i) {
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^
		      (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1];
		Tm = xtime(Tm);
		(*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2];
		Tm = xtime(Tm);
		(*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3];
		Tm = xtime(Tm);
		(*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;
		Tm = xtime(Tm);
		(*state)[i][3] ^= Tm ^ Tmp;
	}
}

#define Multiply(x, y)                               \
	(((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ \
	 ((y >> 2 & 1) * xtime(xtime(x))) ^          \
	 ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^   \
	 ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

static void Cipher(state_t* state, const u8* RoundKey) {
	u8 round = 0;

	AddRoundKey(0, state, RoundKey);

	for (round = 1;; ++round) {
		SubBytes(state);
		ShiftRows(state);
		if (round == Nr) {
			break;
		}
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}
	AddRoundKey(Nr, state, RoundKey);
}

/* Symmetrical operation: same function for encrypting as for decrypting. Note
 * any IV/nonce should never be reused with the same key */
void aes_ctr_xcrypt_buffer(AesContext* ctx, u8* buf, u64 length) {
	u8 buffer[AES_BLOCKLEN];

	u64 i;
	i32 bi;
	for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi) {
		if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in
					   buffer */
		{
			memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
			Cipher((state_t*)buffer, ctx->RoundKey);

			/* Increment Iv and handle overflow */
			for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
				/* inc will overflow */
				if (ctx->Iv[bi] == 255) {
					ctx->Iv[bi] = 0;
					continue;
				}
				ctx->Iv[bi] += 1;
				break;
			}
			bi = 0;
		}

		buf[i] = (buf[i] ^ buffer[bi]);
	}
}

