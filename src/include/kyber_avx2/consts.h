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

#ifndef CONSTS_H
#define CONSTS_H

#include <kyber_avx2/ns.h>
#include <kyber_common/params.h>

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

/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#ifdef __ASSEMBLER__
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define cdecl2(s) decorate(s)
#define cdecl(s) cdecl2(KYBER_NAMESPACE(##s))
#else
#define cdecl(s) KYBER_NAMESPACE(##s)
#endif
#endif

#ifndef __ASSEMBLER__
#include <kyber_avx2/align.h>
typedef ALIGNED_INT16(640) qdata_t;
#define qdata KYBER_NAMESPACE(qdata)
extern const qdata_t qdata;
#endif

#endif
