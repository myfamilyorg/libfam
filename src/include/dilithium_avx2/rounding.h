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

#ifndef ROUNDING_H
#define ROUNDING_H

#include <dilithium_avx2/params.h>
#include <immintrin.h>

#define power2round_avx DILITHIUM_NAMESPACE(power2round_avx)
void power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a);
#define decompose_avx DILITHIUM_NAMESPACE(decompose_avx)
void decompose_avx(__m256i *a1, __m256i *a0, const __m256i *a);
#define make_hint_avx DILITHIUM_NAMESPACE(make_hint_avx)
unsigned int make_hint_avx(u8 hint[N], const __m256i *a0, const __m256i *a1);
#define use_hint_avx DILITHIUM_NAMESPACE(use_hint_avx)
void use_hint_avx(__m256i *b, const __m256i *a, const __m256i *hint);

#endif
