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

#include <libfam/alloc.h>
#include <libfam/alloc_impl.h>
#include <libfam/atomic.h>
#include <libfam/bitmap.h>
#include <libfam/bitstream.h>
#include <libfam/debug.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/rng.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

Test(atomic) {
	u32 x32 = 2;
	u64 x64 = 2;

	mfence();

	__aor32(&x32, 1);
	ASSERT_EQ(x32, 3, "or32");

	__aand32(&x32, 1);
	ASSERT_EQ(x32, 1, "and1");

	__aadd32(&x32, 5);
	ASSERT_EQ(x32, 6, "add5");

	__asub32(&x32, 3);
	ASSERT_EQ(x32, 3, "sub3");

	__aor64(&x64, 1);
	ASSERT_EQ(x64, 3, "or64");

	__aand64(&x64, 1);
	ASSERT_EQ(x64, 1, "and1");

	__aadd64(&x64, 5);
	ASSERT_EQ(x64, 6, "add64_5");

	__asub64(&x64, 3);
	ASSERT_EQ(x64, 3, "sub3");

	u64 a64 = 0, b64 = 1;
	ASSERT(!__cas64(&a64, &b64, 37), "cas64 fail");
	ASSERT_EQ(a64, 0, "a64==0");
	a64 = b64;
	ASSERT(__cas64(&a64, &b64, 37), "cas64 success");
	ASSERT_EQ(a64, 37, "a64=37");

	u32 a32 = 0, b32 = 1;
	ASSERT(!__cas32(&a32, &b32, 37), "cas32 fail");
	ASSERT_EQ(a32, 0, "a32==0");
	a32 = b32;
	ASSERT(__cas32(&a32, &b32, 37), "cas32 success");
	ASSERT_EQ(a32, 37, "a32=37");

	u32 a1;
	u64 a2;

	__astore32(&a1, 1);
	__astore64(&a2, 2);

	ASSERT_EQ(__aload32(&a1), 1, "aload32");
	ASSERT_EQ(__aload64(&a2), 2, "aload64");
}

#define ACOUNT 128
#define AITER 500

Test(atomic_thread64) {
	i32 i;
	i32 pids[ACOUNT];
	u64 *count = smap(sizeof(u64));
	u64 *aloop = smap(sizeof(u64));
	*count = 0;
	*aloop = 0;

	for (i = 0; i < ACOUNT; i++) {
		pids[i] = two();
		if (!pids[i]) {
			u64 expected;
			u64 desired;
			for (i = 0; i < AITER; i++) {
				do {
					expected = __aload64(count);
					desired = expected + 1;
					__aadd64(aloop, 3);
					__asub64(aloop, 2);
				} while (!__cas64(count, &expected, desired));
			}
			_exit(0);
		}
	}

	for (i = 0; i < ACOUNT; i++) await(pids[i]);
	ASSERT(*aloop >= *count, "at least *count loops");
	ASSERT_EQ(*count, AITER * ACOUNT, "count==AITER * ACOUNT");
	munmap(count, sizeof(u64));
	munmap(aloop, sizeof(u64));
}

Test(atomic_thread32) {
	i32 i;
	i32 pids[ACOUNT];
	u32 *count = smap(sizeof(u32));
	u32 *aloop = smap(sizeof(u32));
	*count = 0;
	*aloop = 0;

	for (i = 0; i < ACOUNT; i++) {
		pids[i] = two();
		if (!pids[i]) {
			u32 expected;
			u32 desired;
			for (i = 0; i < AITER; i++) {
				do {
					expected = __aload32(count);
					desired = expected + 1;
					__aadd32(aloop, 2);
					__asub32(aloop, 1);
				} while (!__cas32(count, &expected, desired));
			}
			_exit(0);
		}
	}

	for (i = 0; i < ACOUNT; i++) await(pids[i]);
	ASSERT(*aloop >= *count, "at least *count loops");
	ASSERT_EQ(*count, AITER * ACOUNT, "count==AITER * ACOUNT");
	munmap(count, sizeof(u32));
	munmap(aloop, sizeof(u32));
}

#define TA_COUNT 128
#define TA_ITER (1024 * 4)

Test(bitmap1) {
	i32 i;
	i32 pids[TA_COUNT];
	u64 *count = smap(sizeof(u64));
	BitMap *bmp = smap(bitmap_bound(TA_ITER * TA_COUNT));
	ASSERT(!bitmap_init(bmp, TA_ITER * TA_COUNT), "bitmap_init");
	ASSERT(count, "count smap");

	for (i = 0; i < TA_COUNT; i++) {
		pids[i] = two();
		if (!pids[i]) {
			u64 arr[TA_ITER] = {0};
			for (i = 0; i < TA_ITER; i++) {
				i64 bit = bitmap_find_free_bit(bmp);
				ASSERT(bit >= 0, "bit");
				arr[i] = bit;
			}
			for (i = 0; i < TA_ITER; i++)
				bitmap_release_bit(bmp, arr[i]);
			__aadd64(count, 1);
			_exit(0);
		}
	}

	for (i = 0; i < TA_COUNT; i++) await(pids[i]);
	ASSERT_EQ(__aload64(count), TA_COUNT, "complete=128");
	munmap(bmp, bitmap_bound(TA_ITER));
	munmap(count, sizeof(u64));
}

Test(bitmap2) {
	i32 i;
	BitMap *bmp = smap(bitmap_bound(TA_ITER * TA_COUNT));
	ASSERT(!bitmap_init(bmp, 1024), "bitmap_init");
	for (i = 0; i < 66; i++) {
		i64 next = bitmap_find_free_bit(bmp);
		ASSERT_EQ(next, i, "next");
	}
	bitmap_release_bit(bmp, 4);
	ASSERT_EQ(bitmap_find_free_bit(bmp), 4, "next free is 4");
	ASSERT_EQ(bitmap_find_free_bit(bmp), 66, "skip to 66");

	_debug_no_write = true;
	_debug_no_exit = true;
	/* Invalid release */
	errno = 0;
	bitmap_release_bit(bmp, U64_MAX << 6);
	ASSERT_EQ(errno, EINVAL, "invalid");
	bitmap_release_bit(bmp, 66);
	/* Double free */
	errno = 0;
	bitmap_release_bit(bmp, 66);
	ASSERT_EQ(errno, EINVAL, "double free");

	_debug_no_write = false;
	_debug_no_exit = false;

	munmap(bmp, 1024);
}

Test(bitmap_max) {
	BitMap *bmp = map(100);
	ASSERT(!bitmap_init(bmp, 3), "bitmap_init");
	ASSERT_EQ(bitmap_size(bmp), PAGE_SIZE, "size=100");
	ASSERT_EQ(bitmap_find_free_bit(bmp), 0, "0");
	ASSERT_EQ(bitmap_find_free_bit(bmp), 1, "1");
	ASSERT_EQ(bitmap_find_free_bit(bmp), 2, "2");
	i64 v = bitmap_find_free_bit(bmp);
	ASSERT_EQ(v, -1, "-1");
	v = bitmap_find_free_bit(bmp);
	ASSERT_EQ(v, -1, "-1");
	bitmap_release_bit(bmp, 2);
	v = bitmap_find_free_bit(bmp);
	ASSERT_EQ(v, 2, "2");
	v = bitmap_find_free_bit(bmp);
	ASSERT_EQ(v, -1, "-1");
	munmap(bmp, 100);
}

Test(string_u128_fns) {
	u128 i;
	u128 v1 = 1234;
	i128 v2 = -5678;
	u8 buf[MAX_I128_STRING_LEN];
	ASSERT(u128_to_string(buf, v1, Int128DisplayTypeDecimal) > 0,
	       "u128_to_string");
	ASSERT(!strcmp(buf, "1234"), "1234");

	ASSERT(i128_to_string(buf, v2, Int128DisplayTypeDecimal) > 0,
	       "i128_to_string");
	ASSERT(!strcmp(buf, "-5678"), "-5678");

	for (i = 0; i < 100000 * 10000; i += 10000) {
		u128 v = i;
		u128 vout;
		u128_to_string(buf, v, Int128DisplayTypeDecimal);
		string_to_u128(buf, strlen(buf), &vout);
		ASSERT_EQ(v, vout, "v=vout");
	}

	ASSERT_EQ(i128_to_string(buf, 0x123, Int128DisplayTypeHexUpper), 5,
		  "len=5");
	ASSERT(!strcmp(buf, "0x123"), "string 0x123");

	ASSERT_EQ(i128_to_string(buf, 0xF, Int128DisplayTypeBinary), 4,
		  "binary 0xF");
	ASSERT(!strcmp(buf, "1111"), "string 1111");
}

#define PERF_SIZE 200
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
	/*println("");
	println(
	    "read_micros={},write_micros={},len={},read={} MBps,write={} MBps",
	    read_micros, write_micros, len_sum, read_mbps, write_mbps);*/
}

Test(bitstream_overflow) {
	u8 data[1024] = {0};
	BitStreamReader strm = {data};
	bitstream_reader_load(&strm);
	ASSERT_EQ(strm.bit_offset, 0, "overflow no bytes read");
}

u128 __umodti3(u128 a, u128 b);
u128 __udivti3(u128 a, u128 b);

Test(stubs) {
	u128 v1 = (u128)111 << 77;
	u128 v2 = (u128)333 << 77;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod0");
	v1 = 1;
	v2 = (u128)U64_MAX + 1;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod1");
}

Test(alloc1) {
	Alloc *a = alloc_init(AllocMap, 8);
	void *tmp = balloc(a, 8);
	brelease(a, tmp);
	void *tmp2 = balloc(a, 8);
	ASSERT_EQ(tmp2, tmp, "return previously freed ptr");
	void *tmp3 = balloc(a, 8);
	ASSERT_EQ(tmp3, tmp2 + 8, "next ptr");
	void *tmp4 = balloc(a, 8);
	ASSERT_EQ(tmp4, tmp3 + 8, "next next ptr");
	brelease(a, tmp2);
	void *tmp5 = balloc(a, 8);
	ASSERT_EQ(tmp5, tmp2, "re allocate freed ptr");
	void *tmp6 = balloc(a, 8);
	ASSERT_EQ(tmp6, tmp4 + 8, "next from tmp4");
	ASSERT_EQ(alloc_allocated_bytes(a), 32);
	alloc_reset_allocated_bytes(a);
	ASSERT_EQ(alloc_allocated_bytes(a), 0);
	alloc_destroy(a);
}

#define ALLOC_COUNT (1024)
#define ALLOC_ITER 1

Test(alloc2) {
	i32 i, j, k;
	Rng rng;
	ASSERT(!rng_init(&rng), "rng");
	Alloc *a = alloc_init(AllocMap, 32);
	u8 **ptrs = map(sizeof(u8 *) * ALLOC_COUNT);
	ASSERT(a, "alloc");
	ASSERT(ptrs, "ptrs");
	for (i = 0; i < ALLOC_ITER; i++) {
		for (j = 0; j < ALLOC_COUNT; j++) {
			u16 size;
			rng_gen(&rng, &size, sizeof(u16));
			size = 2 + (size % 1024);
			ptrs[j] = balloc(a, size);
			memcpy(ptrs[j], &size, sizeof(u16));
			for (k = 2; k < size; k++) ptrs[j][k] = 'a' + (k % 26);
		}

		for (j = 0; j < ALLOC_COUNT; j++) {
			u16 size;
			memcpy(&size, ptrs[j], sizeof(u16));
			for (k = 2; k < size; k++)
				ASSERT_EQ(ptrs[j][k], 'a' + (k % 26), "k");
			brelease(a, ptrs[j]);
		}
	}

	alloc_destroy(a);
	munmap(ptrs, sizeof(void *) * ALLOC_COUNT);
}

#define ALLOC_THREADS 32
#define ALLOC_TCOUNT (32 * 1024)

Test(alloc3) {
	i32 i;
	i32 pids[ALLOC_THREADS];
	Alloc *a = alloc_init(AllocSmap, 512);
	u64 *count = smap(sizeof(u64));
	*count = 0;

	for (i = 0; i < ALLOC_THREADS; i++) {
		pids[i] = two();
		if (!pids[i]) {
			Rng rng;
			ASSERT(!rng_init(&rng), "rng");
			i32 j, k;
			u8 **ptrs = map(sizeof(u8 *) * ALLOC_TCOUNT);
			u16 *sizes = map(sizeof(u16) * ALLOC_TCOUNT);
			for (j = 0; j < ALLOC_TCOUNT; j++) {
				u16 size;
				rng_gen(&rng, &size, sizeof(u16));
				size = 2 + (size % 1024);
				sizes[j] = size;
				ptrs[j] = balloc(a, size);
				ASSERT(ptrs[j], "ptrs[j]");
				memcpy(ptrs[j], &size, sizeof(u16));
				for (k = 2; k < size; k++)
					ptrs[j][k] = 'a' + (k % 26);
			}

			for (j = 0; j < ALLOC_TCOUNT; j++) {
				u16 size;
				memcpy(&size, ptrs[j], sizeof(u16));
				for (k = 2; k < size; k++)
					ASSERT_EQ(ptrs[j][k], 'a' + (k % 26),
						  "k");
				brelease(a, ptrs[j]);
			}

			munmap(ptrs, sizeof(u8 *) * ALLOC_TCOUNT);
			munmap(sizes, sizeof(u16) * ALLOC_TCOUNT);
			__aadd64(count, 1);
			_exit(0);
		}
	}
	for (i = 0; i < ALLOC_THREADS; i++) await(pids[i]);
	ASSERT_EQ(*count, ALLOC_THREADS, "athreads complete");
	alloc_destroy(a);
	munmap(count, sizeof(u64));
}

#define ALLOC_MAP_SIZE (1024 * 1024 * 2)

Test(alloc_map) {
	i32 i;
	Alloc *a = alloc_init(AllocMap, 2);
	ASSERT(a, "alloc_init");
	u8 *p = balloc(a, ALLOC_MAP_SIZE);
	ASSERT(p, "alloc_map");
	for (i = 0; i < ALLOC_MAP_SIZE; i++) p[i] = i % 256;
	brelease(a, p);
	a->t = 100;
	ASSERT(!balloc(a, ALLOC_MAP_SIZE), "balloc invalid type");
	a->t = AllocMap;
	alloc_destroy(a);
}

Test(resize1) {
	Alloc *a = alloc_init(AllocSmap, 2);
	ASSERT_EQ(alloc_allocated_bytes(a), 0, "0");
	u8 *p = balloc(a, 5);
	ASSERT_EQ(alloc_allocated_bytes(a), 8, "8");

	ASSERT(p, "resize");
	p[0] = 1;
	p[1] = 2;
	p[2] = 3;
	p[3] = 4;
	p[4] = 5;
	p = bresize(a, p, 8);
	ASSERT_EQ(alloc_allocated_bytes(a), 8, "8");

	ASSERT_EQ(p[0], 1, "p[0]==1");
	ASSERT_EQ(p[1], 2, "p[1]==2");
	ASSERT_EQ(p[2], 3, "p[2]==3");
	ASSERT_EQ(p[3], 4, "p[3]==4");
	ASSERT_EQ(p[4], 5, "p[4]==5");
	p[5] = 6;
	p = bresize(a, p, 11);
	ASSERT_EQ(alloc_allocated_bytes(a), 16, "16");

	ASSERT_EQ(p[0], 1, "p[0]==1");
	ASSERT_EQ(p[1], 2, "p[1]==2");
	ASSERT_EQ(p[2], 3, "p[2]==3");
	ASSERT_EQ(p[3], 4, "p[3]==4");
	ASSERT_EQ(p[4], 5, "p[4]==5");
	ASSERT_EQ(p[5], 6, "p[5]==6");
	p = bresize(a, p, ALLOC_MAP_SIZE);
	ASSERT_EQ(alloc_allocated_bytes(a), ALLOC_MAP_SIZE, "ALLOC_MAP_SIZE");
	ASSERT_EQ(p[0], 1, "p[0]==1");
	ASSERT_EQ(p[1], 2, "p[1]==2");
	ASSERT_EQ(p[2], 3, "p[2]==3");
	ASSERT_EQ(p[3], 4, "p[3]==4");
	ASSERT_EQ(p[4], 5, "p[4]==5");
	ASSERT_EQ(p[5], 6, "p[5]==6");
	p = bresize(a, p, 8);
	ASSERT_EQ(p[0], 1, "p[0]==1");
	ASSERT_EQ(p[1], 2, "p[1]==2");
	ASSERT_EQ(p[2], 3, "p[2]==3");
	ASSERT_EQ(p[3], 4, "p[3]==4");
	ASSERT_EQ(p[4], 5, "p[4]==5");
	ASSERT_EQ(p[5], 6, "p[5]==6");
	ASSERT_EQ(alloc_allocated_bytes(a), 8, "8");
	bresize(a, p, 0);
	ASSERT(!alloc_allocated_bytes(a), "0");
	alloc_destroy(a);
}

Test(slab_sizes) {
	ASSERT_EQ(calculate_slab_size(1), 8, "1");
	ASSERT_EQ(calculate_slab_size(8), 8, "8");
	ASSERT_EQ(calculate_slab_index(1), 0, "index1");
	ASSERT_EQ(calculate_slab_index(8), 0, "index8");
	u32 value = 8;
	u32 exp_index = 1;
	while ((value << 1) <= MAX_SLAB_SIZE) {
		ASSERT_EQ(calculate_slab_size(value + 1), value << 1, "v+1");
		ASSERT_EQ(calculate_slab_size(value << 1), value << 1, "v*2");
		ASSERT_EQ(calculate_slab_index(value + 1), exp_index,
			  "index+1");
		ASSERT_EQ(calculate_slab_index(value << 1), exp_index,
			  "index*2");
		value <<= 1;
		exp_index++;
	}

	ASSERT_EQ(calculate_slab_size(MAX_SLAB_SIZE + 1), 0, "max");
}

Test(bits_per_slab_index) {
	i32 i;
	for (i = 0; i < SLAB_COUNT; i++) {
		u64 bits = BITS_PER_SLAB_INDEX[i];
		u64 slab_size = 8U << i;
		u64 needed =
		    bitmap_bound(bits) + sizeof(Chunk) + bits * slab_size;
		ASSERT(needed <= CHUNK_SIZE, "sufficient size");
		bits++;
		needed = bitmap_bound(bits) + sizeof(Chunk) + bits * slab_size;
		if (needed <= CHUNK_SIZE) {
			u64 potential = bits;
			while (true) {
				u64 needed = bitmap_bound(potential) +
					     sizeof(Chunk) +
					     potential * slab_size;
				if (needed > CHUNK_SIZE) break;
				potential++;
			}
			write(2, "p: ", 3);
			write_num(2, potential - 1);
		}
		ASSERT(needed > CHUNK_SIZE, "additional space");
	}
}

Test(alloc_all_slabs) {
	Alloc *a = alloc_init(AllocMap, 2);
	u8 *ptr1 = balloc(a, MAX_SLAB_SIZE);
	u8 *ptr2 = balloc(a, MAX_SLAB_SIZE);
	ASSERT_EQ(ptr1 + MAX_SLAB_SIZE, ptr2, "ptr1,ptr2");
	u8 *ptr3 = balloc(a, MAX_SLAB_SIZE);
	ASSERT_EQ(ptr2 + MAX_SLAB_SIZE, ptr3, "ptr2,ptr3");
	u8 *ptr4 = balloc(a, MAX_SLAB_SIZE);
	ASSERT(ptr3 + MAX_SLAB_SIZE != ptr4, "new block");
	u8 *ptr5 = balloc(a, MAX_SLAB_SIZE);
	ASSERT_EQ(ptr4 + MAX_SLAB_SIZE, ptr5, "ptr4,ptr5");
	u8 *ptr6 = balloc(a, MAX_SLAB_SIZE);
	ASSERT_EQ(ptr5 + MAX_SLAB_SIZE, ptr6, "ptr5,ptr6");
	u8 *ptr7 = balloc(a, MAX_SLAB_SIZE);
	ASSERT(ptr6 + MAX_SLAB_SIZE != ptr7, "mapped");
	ASSERT(ptr7 > (u8 *)a + TOTAL_SIZE(2) || ptr7 < (u8 *)a,
	       "ptr7 not in Alloc");

	brelease(a, ptr1);
	brelease(a, ptr2);
	brelease(a, ptr3);
	brelease(a, ptr4);
	brelease(a, ptr5);
	brelease(a, ptr6);
	brelease(a, ptr7);

	alloc_destroy(a);
}

