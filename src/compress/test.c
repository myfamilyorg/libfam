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
#include <libfam/compress_impl.h>
#include <libfam/rng.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

#define PERF_SIZE 2000
#define PERF_ITER (128)

Test(bitstream_perf) {
	u64 len_sum = 0;
	u8 lengths[PERF_SIZE] = {0};
	u8 codes[PERF_SIZE] = {0};
	u8 data[PERF_SIZE * 2] = {0};
	Rng rng;
	i32 i, c;

	ASSERT(!rng_init(&rng), "rng init");
	i64 write_micros = 0, read_micros = 0;
	(void)write_micros;
	(void)read_micros;

	for (c = 0; c < PERF_ITER; c++) {
		BitStreamWriter writer = {data};
		BitStreamReader reader = {data, sizeof(data)};
		rng_gen(&rng, lengths, sizeof(lengths));
		rng_gen(&rng, codes, sizeof(codes));
		for (i = 0; i < PERF_SIZE; i++)
			lengths[i] = lengths[i] < 16 ? 1 : lengths[i] >> 4,
			codes[i] &= (1ULL << lengths[i]) - 1;

		i64 start = micros();
		for (i = 0; i < PERF_SIZE; i++) {
			if (writer.bits_in_buffer + lengths[i] > 64)
				bitstream_writer_flush(&writer);
			bitstream_writer_push(&writer, codes[i], lengths[i]);
		}
		bitstream_writer_flush(&writer);
		write_micros += micros() - start;

		start = micros();
		for (i = 0; i < PERF_SIZE; i++) {
			u32 value;
			(void)value;
			if (reader.bits_in_buffer < lengths[i]) {
				bitstream_reader_load(&reader);
				value =
				    bitstream_reader_read(&reader, lengths[i]);
				bitstream_reader_clear(&reader, lengths[i]);
				ASSERT_EQ(value, codes[i], "codes equal1");
				len_sum += lengths[i];
			} else {
				value =
				    bitstream_reader_read(&reader, lengths[i]);
				bitstream_reader_clear(&reader, lengths[i]);
				ASSERT_EQ(value, codes[i], "codes equal2");
				len_sum += lengths[i];
			}
		}
		read_micros += micros() - start;
	}

	u64 read_mbps = 1000000 * ((len_sum / 8) / read_micros) / (1024 * 1024);
	u64 write_mbps =
	    1000000 * ((len_sum / 8) / write_micros) / (1024 * 1024);
	(void)read_mbps;
	(void)write_mbps;
}

Test(bitstream_overflow) {
	u8 data[1] = {0};
	BitStreamReader rdr = {data, sizeof(data)};
	ASSERT_EQ(bitstream_reader_load(&rdr), -1, "overflow");
}

#define ITER (16)

Test(compress1) {
	u64 bytes_consumed;
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

	for (u32 i = 0; i < ITER; i++) {
		i64 timer = micros();
		i32 result = compress_block(in, file_size, out, bound);
		timer = micros() - timer;
		comp_sum += timer;

		ASSERT(result > 0, "compress_block");
		timer = micros();
		result = decompress_block(out, result, verify, file_size,
					  &bytes_consumed);
		timer = micros() - timer;
		decomp_sum += timer;

		ASSERT_EQ(result, file_size, "file_size");
		ASSERT(!memcmp(verify, in, file_size), "verify");
	}

	/*println("avg comp={},decomp={}", comp_sum / ITER, decomp_sum /
	 * ITER);*/
	(void)comp_sum;
	(void)decomp_sum;

	munmap(in, file_size);
	release(verify);
	release(out);
	close(fd);
}

Test(compress_rand) {
	u64 bytes_consumed;
	const u8 *path = "./resources/rand.txt";
	i32 fd = file(path);
	u64 file_size = min(fsize(fd), 128 * 1024);
	u8 *in = fmap(fd, file_size, 0);
	u64 bound = compress_bound(file_size);
	u8 *out = alloc(bound);
	u8 *verify = alloc(file_size);
	ASSERT(out, "out");
	ASSERT(verify, "verify");
	i64 comp_sum = 0, decomp_sum = 0;

	for (u32 i = 0; i < ITER; i++) {
		i64 timer = micros();
		i32 result = compress_block(in, file_size, out, bound);
		timer = micros() - timer;
		comp_sum += timer;

		ASSERT(result > 0, "compress_block");
		timer = micros();
		result = decompress_block(out, result, verify, file_size,
					  &bytes_consumed);
		timer = micros() - timer;
		decomp_sum += timer;

		ASSERT_EQ(result, file_size, "file_size");
		ASSERT(!memcmp(verify, in, file_size), "verify");
	}

	/*println("avg comp={},decomp={}", comp_sum / ITER, decomp_sum /
	 * ITER);*/
	(void)comp_sum;
	(void)decomp_sum;

	munmap(in, file_size);
	release(verify);
	release(out);
	close(fd);
}

Test(compress_other) {
	u8 out[1024];
	u8 verify[1024];
	u64 bytes_consumed;
	i32 len;
	ASSERT((len = compress_block("", 0, out, 1024)) > 0, "compress");
	ASSERT(!decompress_block(out, len, verify, sizeof(verify),
				 &bytes_consumed),
	       "decompress");
	ASSERT_EQ(bytes_consumed, 3, "bc=3");

	ASSERT(compress_block("", 0, out, 0) < 0, "compress_bound");
	ASSERT(decompress_block("", 0, out, 0, &bytes_consumed) < 0,
	       "decompress with len=0");

	ASSERT((len = compress_block("b", 1, out, 1024)) > 0, "compress2");
	ASSERT_EQ(
	    decompress_block(out, len, verify, sizeof(verify), &bytes_consumed),
	    1, "len=1");
	ASSERT_EQ(bytes_consumed, 4, "bc=4");
	ASSERT_EQ(verify[0], 'b', "v[0]='b'");

	const u8 *data = "aaaaaaaaaaaaaaa";
	ASSERT((len = compress_block(data, strlen(data), out, 1024)) > 0,
	       "compress");
	ASSERT_EQ(
	    decompress_block(out, len, verify, sizeof(verify), &bytes_consumed),
	    strlen(data), "repeat a");
	ASSERT(!memcmp(data, verify, strlen(data)), "aaa..");
}

Test(compress_oob) {
	u64 bytes_consumed;
	u8 data2[1024], out2[2048], verify2[2048];
	/* Note: valgrind reports uninitialized memory access with gcc -O3,
	 * however this data is initialized by compress_block and correctly
	 * processed, or so it seems. For now, we zero the first 58 bytes, which
	 * should not be necessary. */
	for (u32 i = 0; i < 58; i++) out2[i] = 0;
	for (u32 i = 0; i < 1024; i++) data2[i] = 'x';
	i32 len = compress_block(data2, 1024, out2, 2048);
	len = decompress_block(out2, len, verify2, 1024, &bytes_consumed);
	ASSERT_EQ(len, 1024, "len=1024");
	ASSERT(!memcmp(verify2, data2, 1024), "verify2");
	ASSERT_EQ(bytes_consumed, 58, "bc=58 {}", bytes_consumed);
	for (u32 i = 0; i < 1024; i++)
		ASSERT_EQ(
		    decompress_block(out2, len, verify2, i, &bytes_consumed),
		    -1, "overflow");
}

Test(compress_file1) {
	unlink("/tmp/1.cz");
	unlink("/tmp/1cmp.txt");
	const u8 *fname = "resources/akjv5.txt";
	i32 in_fd = file(fname);
	i32 out_fd = file("/tmp/1.cz");
	ASSERT(!compress_file(in_fd, out_fd, "test.txt"), "compress_file");
	close(in_fd);
	close(out_fd);

	in_fd = file("/tmp/1.cz");
	out_fd = file("/tmp/1cmp.txt");
	ASSERT(!decompress_file(in_fd, out_fd), "decompress_file");
	close(in_fd);
	close(out_fd);

	i32 cmp_fd = file("/tmp/1cmp.txt");
	i32 cmp_orig = file(fname);
	u64 size = fsize(cmp_fd);
	u64 cmp_size = fsize(cmp_orig);

	ASSERT_EQ(size, cmp_size, "sizes");
	u8 *cmp = fmap(cmp_fd, size, 0);
	u8 *orig = fmap(cmp_orig, size, 0);

	ASSERT(cmp && orig, "fmap");
	ASSERT(!memcmp(cmp, orig, size), "equal");

	munmap(cmp, size);
	munmap(orig, size);

	close(cmp_fd);
	close(cmp_orig);
	unlink("/tmp/1.cz");
	unlink("/tmp/1cmp.txt");
}

Test(bitstream_partial_masks) {
	for (u8 bit_offset = 0; bit_offset < 8; bit_offset++) {
		for (u8 bits_to_write = 0; bits_to_write <= 8;
		     bits_to_write++) {
			u8 expected_mask = 0xFF;
			if (bits_to_write > 0) {
				expected_mask &= ~(((1ULL << bits_to_write) - 1)
						   << bit_offset);
			}
			ASSERT_EQ(
			    bitstream_partial_masks[bit_offset][bits_to_write],
			    expected_mask,
			    "Mask for bit_offset={}, bits_to_write={}",
			    bit_offset, bits_to_write);
		}
	}
	println("sz={}", sizeof(HuffmanLookup));
}
