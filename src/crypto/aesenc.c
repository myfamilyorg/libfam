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

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#elif defined(__ARM_FEATURE_CRYPTO)
#define USE_NEON
#endif /* __ARM_FEATURE_CRYPTO */
#endif /* NO_VECTOR */

#ifdef USE_NEON
#include <arm_neon.h>
#endif /* USE_NEON */
#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

void aesenc256(const void *data, const void *key, void *out) {
#ifdef USE_AVX2
	*(__m256i *)out =
	    _mm256_aesenc_epi128(*(__m256i *)data, *(__m256i *)key);
#elif defined(USE_NEON)
#else
#endif
}

