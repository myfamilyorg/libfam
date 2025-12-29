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

#include <libfam/compress.h>
#include <libfam/test.h>

Test(compress1) {
	u8 out[MAX_COMPRESS_LEN + 3];
	i32 fd = file("resources/akjv5.txt");
	u8 *in = fmap(fd, MAX_COMPRESS_LEN, 0);
	ASSERT(in, "fmap");

	i64 timer = micros();
	for (u32 i = 0; i < 100; i++)
		ASSERT(
		    compress_block(in, MAX_COMPRESS_LEN, out, sizeof(out)) > 0,
		    "compress_block");
	timer = micros() - timer;
	// println("ms={}", timer);
	(void)timer;

	munmap(in, MAX_COMPRESS_LEN);
	close(fd);
}

Test(compress2) {
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = file(path);
	u64 file_size = min(fsize(fd), 128 * 1024);
	u8 *in = fmap(fd, file_size, 0);
	u64 bound = compress_bound(file_size);
	u8 *out = alloc(bound);
	u8 *verify = alloc(file_size);
	ASSERT(out, "out");
	ASSERT(verify, "verify");
	i64 comp_sum = 0, decomp_sum = 0;

	i64 timer = micros();
	i32 result = compress_block(in, file_size, out, bound);
	timer = micros() - timer;
	comp_sum += timer;

	ASSERT(result > 0, "compress_block");
	timer = micros();
	result = decompress_block(out, result, verify, file_size);
	timer = micros() - timer;
	decomp_sum += timer;

	// println("file_size={},result={}", file_size, result);
	ASSERT_EQ(result, file_size, "file_size");

	if (memcmp(verify, in, file_size)) {
		for (u32 i = 0; i < file_size; i++) {
			if (verify[i] != in[i]) {
				println("in[{}]={c}, verify[{}]={c}", i, in[i],
					i, verify[i]);
			}
		}
	}
	ASSERT(!memcmp(verify, in, file_size), "verify");

	(void)comp_sum;
	(void)decomp_sum;

	munmap(in, file_size);
	release(verify);
	release(out);
	close(fd);
}

Bench(compress) {
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = file(path);
	u64 file_size = min(fsize(fd), 128 * 1024);
	u8 *in = fmap(fd, file_size, 0);
	u64 bound = compress_bound(file_size);
	u8 *out = alloc(bound);
	u8 *verify = alloc(file_size);
	ASSERT(out, "out");
	ASSERT(verify, "verify");
	i64 comp_sum = 0, decomp_sum = 0;
	u64 iter = 1000;

	for (u32 i = 0; i < iter; i++) {
		i64 timer = cycle_counter();
		i32 result = compress_block(in, file_size, out, bound);
		timer = cycle_counter() - timer;
		comp_sum += timer;

		ASSERT(result > 0, "compress_block");
		timer = cycle_counter();
		result = decompress_block(out, result, verify, file_size);
		timer = cycle_counter() - timer;
		decomp_sum += timer;

		ASSERT_EQ(result, file_size, "file_size");

		if (memcmp(verify, in, file_size)) {
			for (u32 i = 0; i < file_size; i++) {
				if (verify[i] != in[i]) {
					println("in[{}]={c}, verify[{}]={c}", i,
						in[i], i, verify[i]);
				}
			}
		}
		ASSERT(!memcmp(verify, in, file_size), "verify");
	}

	(void)comp_sum;
	(void)decomp_sum;

	munmap(in, file_size);
	release(verify);
	release(out);
	close(fd);

	println("comp_sum={},decomp_sum={} (cycles per byte)",
		(f64)comp_sum / iter / file_size,
		(f64)decomp_sum / iter / file_size);
}

