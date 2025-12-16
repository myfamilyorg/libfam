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

#ifndef _DILITHIUM_H
#define _DILITHIUM_H

#include <libfam/types.h>

#define MLEN 128
#define SEEDLEN 32
#define SECRET_KEY_SIZE 2560
#define PUBLIC_KEY_SIZE 1312
#define SIGNATURE_SIZE (2420 + MLEN)

typedef struct {
	__attribute__((aligned(32))) u8 data[SECRET_KEY_SIZE];
} SecretKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[PUBLIC_KEY_SIZE];
} PublicKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[SIGNATURE_SIZE];
} Signature;

typedef struct {
	__attribute__((aligned(32))) u8 data[MLEN];
} Message;

void dilithium_keyfrom(SecretKey *sk, PublicKey *pk, u8 seed[SEEDLEN]);
void dilithium_sign(Signature *sig, const Message *msg, const SecretKey *sk);
i32 dilithium_verify(const Signature *sig, const PublicKey *pk);

#endif /* _DILITHIUM_H */
