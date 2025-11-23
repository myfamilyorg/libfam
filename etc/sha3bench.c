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

#include <libfam/main.h>
#include <libfam/sha3.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>
#include <libfam/types.h>

#define SIZE (1024 * 1024 * 4)

i32 main(i32 argc, u8 **argv, u8 **envp) {
	u8 ptr[SIZE] = {0};
	Sha3Context ctx;
	ptr[0] = 1;

	sha3_init256(&ctx);
	i64 timer = micros();
	sha3_update(&ctx, ptr, SIZE);
	timer = micros() - timer;

	const u8 *out = sha3_finalize(&ctx);
	pwrite(2, out, 32, 0);
	pwrite(2, "\n", 1, 0);
	write_num(2, timer);
	pwrite(2, "\n", 1, 0);

	return 0;
}
