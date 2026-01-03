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

#ifndef REDUCE_H
#define REDUCE_H

#include <dilithium_scalar/params.h>

#define MONT -4186625  // 2^32 % Q
#define QINV 58728449  // q^(-1) mod 2^32

#define montgomery_reduce DILITHIUM_NAMESPACE(montgomery_reduce)
i32 montgomery_reduce(i64 a);

#define reduce32 DILITHIUM_NAMESPACE(reduce32)
i32 reduce32(i32 a);

#define caddq DILITHIUM_NAMESPACE(caddq)
i32 caddq(i32 a);

#define freeze DILITHIUM_NAMESPACE(freeze)
i32 freeze(i32 a);

#endif
