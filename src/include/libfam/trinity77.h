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

#ifndef _TRINITY_H
#define _TRINITY_H

#include <libfam/types.h>

#define TRINITY77_PK_SIZE 8224
#define TRINITY77_SK_SIZE 32
#define TRINITY77_SIG_SIZE 15424

typedef struct {
	__attribute__((aligned(32))) u8 data[TRINITY77_PK_SIZE];
} Trinity77PK;

typedef struct {
	__attribute__((aligned(32))) u8 data[TRINITY77_SK_SIZE];
} Trinity77SK;

typedef struct {
	u8 data[TRINITY77_SIG_SIZE];
} Trinity77Sig;

void trinity77_sk(const u8 seed[32], Trinity77SK *sk);
void trinity77_pk(const Trinity77SK *sk, Trinity77PK *pk);
void trinity77_sign(const Trinity77SK *sk, const u8 message[128],
		    Trinity77Sig *sig);
i32 trinity77_verify(const Trinity77PK *pk, const u8 message[128],
		     const Trinity77Sig *sig);

#endif /* _TRINITY_H */
