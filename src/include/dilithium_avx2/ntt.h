/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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

#ifndef NTT_H
#define NTT_H

#include <immintrin.h>

#define ntt_avx DILITHIUM_NAMESPACE(ntt_avx)
void ntt_avx(__m256i *a, const __m256i *qdata);
#define invntt_avx DILITHIUM_NAMESPACE(invntt_avx)
void invntt_avx(__m256i *a, const __m256i *qdata);

#define nttunpack_avx DILITHIUM_NAMESPACE(nttunpack_avx)
void nttunpack_avx(__m256i *a);

#define pointwise_avx DILITHIUM_NAMESPACE(pointwise_avx)
void pointwise_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
#define pointwise_acc_avx DILITHIUM_NAMESPACE(pointwise_acc_avx)
void pointwise_acc_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);

#endif
