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
#include <libfam/huff.h>
#include <libfam/rng.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

#define PERF_SIZE 2000
#define PERF_ITER (128)

Test(bitstream_perf) {
	u64 len_sum = 0;
	u8 lengths[PERF_SIZE];
	u8 codes[PERF_SIZE];
	u8 data[PERF_SIZE * 4000];
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
			codes[i] &= (lengths[i] - 1);

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
	/*
	println("");
	println(
	    "read_micros={},write_micros={},len={},read={} MBps,write={} MBps",
	    read_micros, write_micros, len_sum, read_mbps, write_mbps);
	    */
}

Test(huff1) {
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT] = {0};
	HuffSymbols lookup[LOOKUP_SIZE] = {0};
	lengths['a'] = 3;
	lengths['b'] = 3;
	lengths['c'] = 3;
	codes['a'] = 0x7;
	codes['b'] = 0x6;
	codes['c'] = 0x3;
	huff_lookup(lookup, lengths, codes);
	HuffSymbols res;
	res = lookup[0x7];
	ASSERT_EQ(res.bits_consumed, 3, "3 bits");
	ASSERT_EQ(res.output.output_bytes[0], 'a', "a");
	ASSERT_EQ(res.out_bytes, 0, "out_bytes");
	ASSERT_EQ(res.match_flags, 0, "match");

	u64 bits = 0x7 << 3 | 0x6;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 6, "6 bits");
	ASSERT_EQ(res.output.output_bytes[0], 'b', "b");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a");

	bits = (0x7 << 6) | (0x3 << 3) | 0x7;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 9, "9 bits");
	ASSERT_EQ(res.output.output_bytes[0], 'a', "a");
	ASSERT_EQ(res.output.output_bytes[1], 'c', "c");
	ASSERT_EQ(res.output.output_bytes[2], 'a', "a");
	ASSERT_EQ(res.out_bytes, 2, "out_bytes2");
}

Test(huff2) {
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT] = {0};
	HuffSymbols lookup[LOOKUP_SIZE] = {0};
	HuffSymbols res;
	u64 bits;
	lengths['a'] = 3;
	lengths['b'] = 3;
	lengths['c'] = 3;
	lengths[MATCH_OFFSET + 15] = 3;
	lengths[MATCH_OFFSET + 4] = 3;
	codes['a'] = 0x7;
	codes['b'] = 0x6;
	codes['c'] = 0x3;
	codes[MATCH_OFFSET + 15] = 0x2;
	codes[MATCH_OFFSET + 4] = 0x1;
	huff_lookup(lookup, lengths, codes);
	bits = 0x2;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 3 + 15, "consumed");
	ASSERT_EQ(res.output.output_bytes[0], 16, "match 16 = 15 + 1");
	ASSERT_EQ(res.out_bytes, 0, "1 output byte");

	bits = (0x7 << 3) | 0x2;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 3 + 15, "consumed");
	ASSERT_EQ(res.output.output_bytes[0], 16, "match 16 = 15 + 1");
	ASSERT_EQ(res.out_bytes, 0, "1 output byte");

	bits = (0x7 << (4 + 3)) | 0x1;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 3 + 4 + 3, "consumed");
	ASSERT_EQ(res.output.output_bytes[0], 5, "match 5 = 4 + 1");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a");
	ASSERT_EQ(res.out_bytes, 1, "2 output byte");

	bits = (0x6 << (4 + 3 + 3)) | (0x7 << (4 + 3)) | 0x1;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 3 + 4 + 3 + 3, "consumed");
	ASSERT_EQ(res.output.output_bytes[0], 5, "match 5 = 4 + 1");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a");
	ASSERT_EQ(res.output.output_bytes[2], 'b', "a");
	ASSERT_EQ(res.out_bytes, 2, "3 output byte");

	bits = (0x3 << (4 + 3 + 3 + 3)) | (0x6 << (4 + 3 + 3)) |
	       (0x7 << (4 + 3)) | 0x1;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 3 + 4 + 3 + 3 + 3, "consumed");
	ASSERT_EQ(res.output.output_bytes[0], 5, "match 5 = 4 + 1");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a");
	ASSERT_EQ(res.output.output_bytes[2], 'b', "a");
	ASSERT_EQ(res.out_bytes, 3, "4 output byte");
}

Test(huff3) {
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT] = {0};
	HuffSymbols lookup[LOOKUP_SIZE] = {0};
	HuffSymbols res;
	u64 bits;
	lengths['a'] = 2;
	lengths['b'] = 3;
	lengths['c'] = 3;
	lengths[MATCH_OFFSET + 15] = 3;
	lengths[MATCH_OFFSET + 4] = 3;
	codes['a'] = 0x3;
	codes['b'] = 0x6;
	codes['c'] = 0x8;
	codes[MATCH_OFFSET + 15] = 0x2;
	codes[MATCH_OFFSET + 4] = 0x4;
	huff_lookup(lookup, lengths, codes);

	bits = 0xFFF;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 2 * 4, "consumed");
	ASSERT_EQ(res.out_bytes, 3, "4 output byte");
	ASSERT_EQ(res.output.output_bytes[0], 'a', "a1");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a2");
	ASSERT_EQ(res.output.output_bytes[2], 'a', "a3");
	ASSERT_EQ(res.output.output_bytes[3], 'a', "a4");

	bits = (0x3 << 7) | 0x4;
	res = lookup[bits];
	ASSERT_EQ(res.bits_consumed, 4 + 3 + 2, "consumed");
	ASSERT_EQ(res.out_bytes, 1, "2 output byte");
	ASSERT_EQ(res.output.output_bytes[0], 5, "mc = 5");
	ASSERT_EQ(res.output.output_bytes[1], 'a', "a");
}

Test(compress32) {
	u64 bytes_consumed;
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = file(path);
	u64 file_size = fsize(fd);
	u8 *in = fmap(fd, file_size, 0);
	u64 bound = compress_bound(file_size);
	u8 *out = alloc(bound);
	u8 *verify = alloc(file_size);
	ASSERT(out, "out");
	ASSERT(verify, "verify");
	i32 result = compress32(in, file_size, out, bound);
	ASSERT(result > 0, "compress32");
	result = decompress32(out, result, verify, file_size, &bytes_consumed);
	for (u32 i = 0; i < file_size; i++) {
		if (verify[i] != in[i])
			println("verify[{}]={},in[{}]={}", i, verify[i], i,
				in[i]);
	}
	ASSERT_EQ(result, file_size, "file_size");
	ASSERT(!memcmp(verify, in, result), "verify");
	release(out);
	release(verify);
}

