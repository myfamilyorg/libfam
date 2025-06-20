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

#ifndef _LIMITS_H
#define _LIMITS_H

#ifndef UINT8_MIN
#define UINT8_MIN 0x0
#endif

#ifndef UINT16_MIN
#define UINT16_MIN 0x0
#endif

#ifndef UINT32_MIN
#define UINT32_MIN 0x0
#endif

#ifndef UINT64_MIN
#define UINT64_MIN 0x0
#endif

#ifndef UINT128_MIN
#define UINT128_MIN 0x0
#endif

#ifndef UINT8_MAX
#define UINT8_MAX 0xFF
#endif

#ifndef UINT16_MAX
#define UINT16_MAX 0xFFFF
#endif

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFF
#endif

#ifndef UINT64_MAX
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF
#endif

#ifndef UINT128_MAX
#define UINT128_MAX \
	(((u128)0xFFFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL)
#endif

#ifndef INT8_MIN
#define INT8_MIN (-0x7F - 1)
#endif

#ifndef INT16_MIN
#define INT16_MIN (-0x7FFF - 1)
#endif

#ifndef INT32_MIN
#define INT32_MIN (-0x7FFFFFFF - 1)
#endif

#ifndef INT64_MIN
#define INT64_MIN (-0x7FFFFFFFFFFFFFFF - 1)
#endif

#define INT128_MIN (((i128)0x80000000UL << 96))

#ifndef INT8_MAX
#define INT8_MAX 0x7F
#endif

#ifndef INT16_MAX
#define INT16_MAX 0x7FFF
#endif

#ifndef INT32_MAX
#define INT32_MAX 0x7FFFFFFF
#endif

#ifndef INT64_MAX
#define INT64_MAX 0x7FFFFFFFFFFFFFFF
#endif

#ifndef INT128_MAX
#define INT128_MAX                                                         \
	(((i128)0x7FFFFFFFUL << 96) | ((i128)0xFFFFFFFFUL << 64) | \
	 0xFFFFFFFFUL)
#endif

#ifndef INT_MAX
#define INT_MAX __INT_MAX__
#endif

#ifndef SIZE_MAX
#define SIZE_MAX UINT64_MAX
#endif

#endif /* _LIMITS_H */

