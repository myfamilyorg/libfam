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
	u8 out[10000] = {0};
	u8 in[256 + 32 + 20] = "abcdefgabcd11223344455667788";
	u8 verify[3000] = {0};
	i32 res = compress_block(in, sizeof(in), out, sizeof(out));
	// println("compress_result={}", res);
	res = decompress_block(out, res, verify, sizeof(verify));
	ASSERT_EQ(res, sizeof(in), "size");
	ASSERT(!memcmp(in, verify, sizeof(in)), "verify");
}

Test(compress2) {
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = file(path);
	u32 size = fsize(fd);
	u8 *in = fmap(fd, size, 0);
	u8 out[100000] = {0}, verify[100000] = {0};
	i32 result = compress_block(in, size, out, sizeof(out));
	// println("compress_result={}", result);
	u64 sum = 0, iter = 1000;
	for (u32 i = 0; i < iter; i++) {
		u64 timer = cycle_counter();
		result = decompress_block(out, result, verify, sizeof(verify));
		timer = cycle_counter() - timer;
		sum += timer;
	}
	// println("cycles={}", sum / iter);
	(void)sum;
	ASSERT_EQ(size, result, "size");
	ASSERT(!memcmp(in, verify, size), "verify");
	munmap(in, size);
}

Test(compressfile1) {
	const u8 *path = "./resources/akjv5.txt";
	const u8 *outpath = "/tmp/akjv5.txt.tmp";
	const u8 *outpath2 = "/tmp/akjv5.txt.conf";
	unlink(outpath);
	unlink(outpath2);

	i64 timer = micros();
	i32 infd = file(path);
	i32 outfd = file(outpath);
	ASSERT(!compress_file(infd, 0, outfd, 0), "compress_file");
	u64 insize = fsize(outfd);
	u64 outsize = fsize(infd);
	close(infd);
	close(outfd);
	timer = micros() - timer;
	// println("compress={},size={}/{}", timer, insize, outsize);

	timer = micros();
	infd = file(outpath);
	outfd = file(outpath2);
	decompress_file(infd, 0, outfd, 0);
	close(infd);
	close(outfd);
	timer = micros() - timer;
	// println("decompress={}", timer);

	(void)insize;
	(void)outsize;

	i32 fd1 = file(outpath2);
	i32 fd2 = file(path);

	ASSERT_EQ(fsize(fd1), fsize(fd2), "fsize");

	void *ptr1 = fmap(fd1, fsize(fd1), 0);
	void *ptr2 = fmap(fd2, fsize(fd2), 0);

	ASSERT(!memcmp(ptr1, ptr2, fsize(fd1)), "equal");

	munmap(ptr1, fsize(fd1));
	munmap(ptr2, fsize(fd2));
	close(fd1);
	close(fd2);

	ASSERT_BYTES(0);
}

Test(compress_raw) {
	u8 in[1024] = {'a', 'b', 'c'}, out[1024] = {0}, verify[1024] = {0};
	ASSERT_EQ(compress_block(in, 3, out, 6), 6, "compress3");
	i32 x = decompress_block(out, 6, verify, sizeof(verify));
	ASSERT_EQ(x, 3, "decompress3");
	ASSERT(!memcmp(verify, (u8[]){'a', 'b', 'c'}, 3), "verify");

	ASSERT_EQ(compress_block(in, 0, out, 3), 3, "compress0");
	ASSERT_EQ(decompress_block(out, 3, verify, 0), 0, "verify0");

	verify[0] = 'x';
	ASSERT_EQ(compress_block(in, 1, out, 4), 4, "compress1");
	ASSERT_EQ(decompress_block(out, 4, verify, 1), 1, "verify1");
	ASSERT_EQ(verify[0], 'a', "a");
}

