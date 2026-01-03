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

#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <dilithium_avx2/params.h>

#ifndef STREAM256_BLOCKBYTES
#define STREAM256_BLOCKBYTES 136
#endif

#ifndef STREAM128_BLOCKBYTES
#define STREAM128_BLOCKBYTES 168
#endif

#define REJ_UNIFORM_NBLOCKS \
	((768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES)
#define REJ_UNIFORM_BUFLEN (REJ_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES)

#define REJ_UNIFORM_ETA_NBLOCKS \
	((136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
#define REJ_UNIFORM_ETA_BUFLEN (REJ_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES)

#define idxlut DILITHIUM_NAMESPACE(idxlut)
extern const u8 idxlut[256][8];

#define rej_uniform_avx DILITHIUM_NAMESPACE(rej_uniform_avx)
unsigned int rej_uniform_avx(i32 *r, const u8 buf[512]);

#define rej_eta_avx DILITHIUM_NAMESPACE(rej_eta_avx)
unsigned int rej_eta_avx(i32 *r, const u8 buf[128]);

#endif

