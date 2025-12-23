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

#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/test_base.h>

Test(storm_vectors) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute((aligned(32))) u8 buf1[32] = {
	    9,	 93,  216, 137, 224, 212, 105, 200, 163, 28,  146,
	    246, 75,  164, 149, 109, 209, 70,  183, 116, 224, 157,
	    245, 221, 5,   53,	245, 155, 165, 135, 142, 218};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf1);

	u8 exp1[32] = {204, 193, 116, 178, 204, 191, 250, 240, 24,  241, 23,
		       185, 255, 250, 66,  221, 100, 77,  187, 202, 221, 228,
		       223, 20,	 106, 134, 78,	38,  178, 172, 110, 153};
	ASSERT(!memcmp(buf1, exp1, sizeof(buf1)), "buf1");
	storm_next_block(&ctx, buf1);

	u8 exp2[32] = {104, 232, 235, 200, 225, 117, 15,  17,  193, 182, 235,
		       70,  96,	 116, 156, 217, 123, 199, 27,  10,  131, 152,
		       172, 145, 79,  14,  208, 70,  27,  207, 59,  211};

	ASSERT(!memcmp(buf1, exp2, sizeof(buf1)), "buf1 round2");

	__attribute((aligned(32))) u8 buf2[32] = {
	    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	    16, 15, 14, 13, 12, 11, 10, 9,  8,	7,  6,	5,  4,	3,  2,	1};
	storm_init(&ctx, SEED);
	storm_next_block(&ctx, buf2);

	u8 exp3[32] = {140, 187, 82,  252, 180, 187, 246, 27,  94,  60, 140,
		       8,   58,	 82,  23,  211, 56,  168, 6,   16,  22, 181,
		       32,  164, 138, 211, 201, 50,  77,  254, 156, 40};
	ASSERT(!memcmp(buf2, exp3, sizeof(buf2)), "buf2");

	storm_next_block(&ctx, buf2);

	u8 exp4[32] = {115, 33,	 96,  112, 88, 80, 97, 17,  236, 164, 249,
		       136, 197, 55,  160, 85, 30, 92, 154, 49,	 11,  80,
		       164, 112, 126, 77,  25, 42, 22, 18,  14,	 15};
	ASSERT(!memcmp(buf2, exp4, sizeof(buf2)), "buf2 round2");
}

Test(storm_cipher) {
	StormContext ctx;
	__attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
	__attribute__((aligned(32))) u8 buffer1[32] = {0};
	__attribute__((aligned(32))) u8 buffer2[32] = {0};
	__attribute__((aligned(32))) u8 buffer3[32] = {0};
	__attribute__((aligned(32))) u8 buffer4[32] = {0};
	__attribute__((aligned(32))) u8 buffer5[32] = {0};

	storm_init(&ctx, SEED);
	faststrcpy(buffer1, "test1");
	storm_xcrypt_buffer(&ctx, buffer1);
	faststrcpy(buffer2, "test2");
	storm_xcrypt_buffer(&ctx, buffer2);
	faststrcpy(buffer3, "blahblah");
	storm_xcrypt_buffer(&ctx, buffer3);
	faststrcpy(buffer4, "ok");
	storm_xcrypt_buffer(&ctx, buffer4);
	faststrcpy(buffer5, "x");
	storm_xcrypt_buffer(&ctx, buffer5);

	ASSERT(memcmp(buffer1, "test1", 5), "ne1");
	ASSERT(memcmp(buffer2, "test2", 5), "ne2");
	ASSERT(memcmp(buffer3, "blahblah", 8), "ne3");
	ASSERT(memcmp(buffer4, "ok", 2), "ne4");
	ASSERT(memcmp(buffer5, "x", 1), "ne5");

	StormContext ctx2;
	storm_init(&ctx2, SEED);

	storm_xcrypt_buffer(&ctx2, buffer1);
	ASSERT(!memcmp(buffer1, "test1", 5), "eq1");
	storm_xcrypt_buffer(&ctx2, buffer2);
	ASSERT(!memcmp(buffer2, "test2", 5), "eq2");

	storm_xcrypt_buffer(&ctx2, buffer3);
	ASSERT(!memcmp(buffer3, "blahblah", 8), "eq3");

	storm_xcrypt_buffer(&ctx2, buffer4);
	ASSERT(!memcmp(buffer4, "ok", 2), "eq4");

	storm_xcrypt_buffer(&ctx2, buffer5);
	ASSERT(!memcmp(buffer5, "x", 1), "eq5");
}

