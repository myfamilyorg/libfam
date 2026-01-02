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

#ifndef _STORM_VECTORS_H
#define _STORM_VECTORS_H

typedef struct {
	__attribute__((aligned(32))) u8 key[32];
	__attribute__((aligned(32))) u8 input[2][32];
	__attribute__((aligned(32))) u8 expected[2][32];
} StormVector;

static const StormVector storm_vectors[] = {
    {.key = {1,	 2,  3,	 4,  5,	 6,  7,	 8,  9,	 10, 11, 12, 13, 14, 15, 16,
	     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
     .input = {{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	       {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}},
     .expected = {{215, 88,  7,	  23, 111, 246, 46,  245, 240, 254, 144,
		   97,	68,  37,  31, 75,  78,	252, 181, 91,  164, 39,
		   168, 163, 255, 24, 209, 137, 12,  170, 82,  107},
		  {70, 68, 210, 116, 252, 96,  205, 209, 189, 255, 46,
		   64, 93, 146, 93,  206, 153, 228, 19,	 253, 164, 3,
		   40, 16, 42,	246, 132, 127, 44,  147, 71,  250}}}

};

#endif /* _STORM_VECTORS_H */
