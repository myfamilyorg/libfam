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

#ifndef _CONSTS_H
#define _CONSTS_H

#include <kyber_avx2/namespace.h>
#include <kyber_common/params.h>

#define cdecl(s) KYBER_NAMESPACE(##s)

#define STORM128_RATE 168
#define XOF_BLOCKBYTES 168
#define STORM_RATE 136
#define _16XQ 0
#define _16XQINV 16
#define _16XV 32
#define _16XFLO 48
#define _16XFHI 64
#define _16XMONTSQLO 80
#define _16XMONTSQHI 96
#define _16XMASK 112
#define _REVIDXB 128
#define _REVIDXD 144
#define _ZETAS_EXP 160
#define _16XSHIFT 624

#define Q KYBER_Q
#define MONT -1044	// 2^16 mod q
#define QINV -3327	// q^-1 mod 2^16
#define V 20159		// floor(2^26/q + 0.5)
#define FHI 1441	// mont^2/128
#define FLO -10079	// qinv*FHI
#define MONTSQHI 1353	// mont^2
#define MONTSQLO 20553	// qinv*MONTSQHI
#define MASK 4095
#define SHIFT 32

#ifndef __ASSEMBLER__
#include <kyber_avx2/align.h>
typedef ALIGNED_INT16(640) qdata_t;
#define qdata KYBER_NAMESPACE(qdata)
extern const qdata_t qdata;
#endif

#endif /* _CONSTS_H */
