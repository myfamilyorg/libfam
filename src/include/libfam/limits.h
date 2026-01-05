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

#ifndef _LIMITS_H
#define _LIMITS_H

#ifndef U8_MIN
#define U8_MIN ((u8)0x0)
#endif

#ifndef U16_MIN
#define U16_MIN ((u16)0x0)
#endif

#ifndef U32_MIN
#define U32_MIN ((u32)0x0)
#endif

#ifndef U64_MIN
#define U64_MIN ((u64)0x0)
#endif

#ifndef U128_MIN
#define U128_MIN ((u128)0x0)
#endif

#ifndef U8_MAX
#define U8_MAX ((u8)0xFF)
#endif

#ifndef U16_MAX
#define U16_MAX ((u16)0xFFFF)
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)0xFFFFFFFF)
#endif

#ifndef U64_MAX
#define U64_MAX ((u64)0xFFFFFFFFFFFFFFFF)
#endif

#ifndef U128_MAX
#define U128_MAX (((u128)0xFFFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL)
#endif

#ifndef I8_MIN
#define I8_MIN ((i8)(-0x7F - 1))
#endif

#ifndef I16_MIN
#define I16_MIN ((i16)(-0x7FFF - 1))
#endif

#ifndef I32_MIN
#define I32_MIN ((i32)(-0x7FFFFFFF - 1))
#endif

#ifndef I64_MIN
#define I64_MIN ((i64)(-0x7FFFFFFFFFFFFFFF - 1))
#endif

#ifndef I128_MIN
#define I128_MIN \
	((i128)(((u128)0x8000000000000000UL << 64) | 0x0000000000000000UL))
#endif

#ifndef I8_MAX
#define I8_MAX ((i8)0x7F)
#endif

#ifndef I16_MAX
#define I16_MAX ((i16)0x7FFF)
#endif

#ifndef I32_MAX
#define I32_MAX ((i32)0x7FFFFFFF)
#endif

#ifndef I64_MAX
#define I64_MAX ((i64)0x7FFFFFFFFFFFFFFF)
#endif

#ifndef I128_MAX
#define I128_MAX \
	((i128)(((i128)0x7FFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL))
#endif

#endif /* _LIMITS_H */

