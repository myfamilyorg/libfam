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

#include <libfam/bitstream.h>
#include <libfam/compress.h>
#include <libfam/rng.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

#define PERF_SIZE 2000
#define PERF_ITER 128

Test(bitstream_perf) {
	u64 len_sum = 0;
	i64 write_micros = 0, read_micros = 0;
	u8 lengths[PERF_SIZE] = {0};
	u16 codes[PERF_SIZE] = {0};
	u8 data[PERF_SIZE * 4] = {0};
	Rng rng;
	i32 i, j, c;

	ASSERT(!rng_init(&rng), "rng init");

	for (c = 0; c < PERF_ITER; c++) {
		BitStreamWriter writer = {data};
		BitStreamReader reader = {data, sizeof(data)};
		rng_gen(&rng, lengths, sizeof(lengths));
		rng_gen(&rng, codes, sizeof(codes));
		for (i = 0; i < PERF_SIZE; i++)
			lengths[i] = lengths[i] < 16 ? 1 : lengths[i] >> 4,
			codes[i] &= (1 << lengths[i]) - 1;

		i64 start = micros();
		for (i = 0; i < PERF_SIZE; i++) {
			if (writer.bits_in_buffer + lengths[i] > 60)
				bitstream_writer_flush(&writer);
			bitstream_writer_push(&writer, codes[i], lengths[i]);
		}
		bitstream_writer_flush(&writer);
		write_micros += micros() - start;

		start = micros();
		for (i = 0; i < PERF_SIZE;) {
			u32 value = 0;
			if (reader.bits_in_buffer < lengths[i]) {
				bitstream_reader_load(&reader);

				for (j = 0; j < 4 && i < PERF_SIZE; j++) {
					value = bitstream_reader_read(
					    &reader, lengths[i]);
					bitstream_reader_clear(&reader,
							       lengths[i]);
					ASSERT_EQ(value, codes[i],
						  "codes equal1");
					len_sum += lengths[i];
					i++;
				}
			} else {
				value =
				    bitstream_reader_read(&reader, lengths[i]);
				bitstream_reader_clear(&reader, lengths[i]);
				ASSERT_EQ(value, codes[i], "codes equal2");
				len_sum += lengths[i];
				i++;
			}
			(void)value;
		}
		read_micros += micros() - start;
	}

	/*
	u64 read_mbps = 1000000 * ((len_sum / 8) / read_micros) / (1024 * 1024);
	u64 write_mbps =
	    1000000 * ((len_sum / 8) / write_micros) / (1024 * 1024);
	(void)read_mbps;
	(void)write_mbps;
	println("");
	println(
	    "read_micros={},write_micros={},len={},read={} MBps,write={} MBps",
	    read_micros, write_micros, len_sum, read_mbps, write_mbps);
	    */
	(void)len_sum;
	(void)write_micros;
	(void)read_micros;
}

#define COMPRESS1_ITER 1

Test(compress1) {
	u64 bytes_consumed;
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = file(path);
	u64 file_size = min(fsize(fd), 128 * 1024);
	u8 *in = fmap(fd, file_size, 0);
	u64 bound = compress_bound(file_size);
	u8 *out = alloc(bound);
	u8 *verify = alloc(file_size + 32);
	ASSERT(out, "out");
	ASSERT(verify, "verify");
	i64 comp_sum = 0, decomp_sum = 0;

	for (u32 i = 0; i < COMPRESS1_ITER; i++) {
		i64 timer = micros();
		i32 result = compress_block(in, file_size, out, bound);
		timer = micros() - timer;
		comp_sum += timer;

		ASSERT(result > 0, "compress_block");
		timer = micros();
		result = decompress_block(out, result, verify, file_size + 32,
					  &bytes_consumed);
		timer = micros() - timer;
		decomp_sum += timer;

		ASSERT_EQ(result, file_size, "file_size {} != {}", result,
			  file_size);
		ASSERT(!memcmp(verify, in, file_size), "verify");
	}

	(void)decomp_sum;
	(void)comp_sum;
	/*println("avg comp={},decomp={}", comp_sum / COMPRESS1_ITER, decomp_sum
	 * / COMPRESS1_ITER);*/

	munmap(in, file_size);
	release(verify);
	release(out);
	close(fd);
}

