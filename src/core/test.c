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
#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/memory.h>
#include <libfam/rng.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

INIT_GLOBAL_ALLOCATOR(64);

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
	if (getenv("VALGRIND")) return;
	i32 i;
	i32 pids[ACOUNT] = {0};
	u64 *count = smap(sizeof(u64));
	u64 *aloop = smap(sizeof(u64));
	*count = 0;
	*aloop = 0;

	for (i = 0; i < ACOUNT; i++) {
		pids[i] = fork();
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
	if (getenv("VALGRIND")) return;
	i32 i;
	i32 pids[ACOUNT];
	u32 *count = smap(sizeof(u32));
	u32 *aloop = smap(sizeof(u32));
	*count = 0;
	*aloop = 0;

	for (i = 0; i < ACOUNT; i++) {
		pids[i] = fork();
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
	if (getenv("VALGRIND")) return;
	i32 i;
	i32 pids[TA_COUNT];
	u64 *count = smap(sizeof(u64));
	BitMap *bmp = smap(bitmap_bound(TA_ITER * TA_COUNT));
	ASSERT(!bitmap_init(bmp, TA_ITER * TA_COUNT), "bitmap_init");
	ASSERT(count, "count smap");

	for (i = 0; i < TA_COUNT; i++) {
		pids[i] = fork();
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
	errno = 0;
	bitmap_release_bit(bmp, U64_MAX << 6);
	ASSERT_EQ(errno, EINVAL, "invalid");
	bitmap_release_bit(bmp, 66);
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

	ASSERT(u128_to_string(buf, 9993, Int128DisplayTypeCommas) > 0,
	       "commas");
	ASSERT(!strcmp(buf, "9,993"), "comma verify");
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
Test(memory) {
	void *a = alloc(1);
	ASSERT(allocated_bytes(), "alloc");
	release(a);
	ASSERT(!allocated_bytes(), "release");
	a = alloc(1);
	ASSERT(allocated_bytes(), "alloc");
	reset_allocated_bytes();
	ASSERT(!allocated_bytes(), "release");
	a = resize(a, 1024);
	ASSERT(a, "a alloc");
	release(a);
	reset_allocated_bytes();
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
	ASSERT_EQ(alloc_allocated_bytes(a), 32, "32 b");
	alloc_reset_allocated_bytes(a);
	ASSERT_EQ(alloc_allocated_bytes(a), 0, "alloc b 0");
	alloc_destroy(a);
}

#define ALLOC_COUNT (1024)
#define ALLOC_ITER 1

Test(alloc2) {
	i32 i, j, k;
	Rng rng;

	u8 *v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	rng_init(&rng, NULL);
	Alloc *a = alloc_init(AllocMap, 32);
	u8 **ptrs = map(sizeof(u8 *) * ALLOC_COUNT);
	ASSERT(a, "alloc");
	ASSERT(ptrs, "ptrs");
	for (i = 0; i < ALLOC_ITER; i++) {
		for (j = 0; j < ALLOC_COUNT; j++) {
			u16 size = 0;
			rng_gen(&rng, &size, sizeof(u16));
			size = 2 + (size % 1024);
			ptrs[j] = balloc(a, size);
			memcpy(ptrs[j], &size, sizeof(u16));
			for (k = 2; k < size; k++) ptrs[j][k] = 'a' + (k % 26);
		}

		for (j = 0; j < ALLOC_COUNT; j++) {
			u16 size = 0;
			memcpy(&size, ptrs[j], sizeof(u16));
			for (k = 2; k < size; k++)
				ASSERT_EQ(ptrs[j][k], 'a' + (k % 26), "k");
			brelease(a, ptrs[j]);
		}
	}

	alloc_destroy(a);
	munmap(ptrs, sizeof(void *) * ALLOC_COUNT);
}

Test(alloc_cas_loop) {
	_debug_alloc_cas_loop = 1;
	void *tmp = alloc(32);
	release(tmp);
	ASSERT_BYTES(0);
}

#define ALLOC_THREADS 4
#define ALLOC_TCOUNT (4 * 1024)

Test(alloc3) {
	u8 *v = getenv("VALGRIND");
	if (v && strlen(v) == 1 && !memcmp(v, "1", 1)) return;

	i32 i;
	i32 pids[ALLOC_THREADS];
	Alloc *a = alloc_init(AllocSmap, 32);
	ASSERT(a, "alloc_init");
	u64 *count = smap(sizeof(u64));
	*count = 0;

	for (i = 0; i < ALLOC_THREADS; i++) {
		pids[i] = fork();
		if (!pids[i]) {
			Rng rng;
			rng_init(&rng, NULL);
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
			pwrite(2, "p: ", 3, 0);
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

Test(format1) {
	Formatter f = FORMATTER_INIT;
	FORMAT(&f, "{}", 1);
	ASSERT(!strcmp("1", format_to_string(&f)), "1");
	format_clear(&f);
	FORMAT(&f, "{}", -1);
	ASSERT(!strcmp("-1", format_to_string(&f)), "-1");
	format_clear(&f);
	FORMAT(&f, "x={x}", 0xFE);
	ASSERT(!strcmp("x=0xfe", format_to_string(&f)), "x=0xfe");
	format_clear(&f);
	FORMAT(&f, "x={X},...", 255);
	ASSERT(!strcmp("x=0xFF,...", format_to_string(&f)), "x=0xFF,...");
	format_clear(&f);
	FORMAT(&f, "a={},b={},c={},d={x}", "test", 1.23456, 9999, 253);
	ASSERT(!strcmp("a=test,b=1.23456,c=9999,d=0xfd", format_to_string(&f)),
	       "multi");
	format_clear(&f);
	FORMAT(&f, "a={c},b={b} {nothing", (u8)'a', 3);
	ASSERT(!strcmp("a=a,b=11 {nothing", format_to_string(&f)),
	       "char and bin");
	format_clear(&f);
	u64 x = 101;
	FORMAT(&f, "{}", x);
	ASSERT(!strcmp("101", format_to_string(&f)), "101");
	format_clear(&f);
	FORMAT(&f, "{n}", 1001);
	ASSERT(!strcmp("1,001", format_to_string(&f)), "101 commas");
	format_clear(&f);
	FORMAT(&f, "x=${n.2}", 1234567.930432);
	ASSERT(!strcmp("x=$1,234,567.93", format_to_string(&f)),
	       "dollar format");
	format_clear(&f);
	ASSERT_BYTES(0);
}

Test(format2) {
	Formatter f = FORMATTER_INIT;
	FORMAT(&f, "'{:5x}'", 10);
	ASSERT(!strcmp("'  0xa'", format_to_string(&f)), "alignment hex");
	format_clear(&f);
	FORMAT(&f, "'{{' {}", 10);
	ASSERT(!strcmp("'{' 10", format_to_string(&f)), "esc bracket left");
	format_clear(&f);
	FORMAT(&f, "'}}' {n}", 1000);
	ASSERT(!strcmp("'}' 1,000", format_to_string(&f)),
	       "esc bracket right and commas");
	format_clear(&f);
	FORMAT(&f, "{nn}", 10);
	ASSERT(!strcmp("{nn}", format_to_string(&f)), "formatting error");
	format_clear(&f);
	FORMAT(&f, "'{:<20}'", 10);
	ASSERT(!strcmp("'10                  '", format_to_string(&f)),
	       "formatting error");
	format_clear(&f);
	FORMAT(&f, "'{:>20}'", 10);
	ASSERT(!strcmp("'                  10'", format_to_string(&f)),
	       "formatting error");
	format_clear(&f);
	FORMAT(&f, "{n{}", 10);
	ASSERT(!strcmp("{n{}", format_to_string(&f)), "formatting error - int");
	format_clear(&f);
	i8 x = 'v';
	FORMAT(&f, "{c}", x);
	ASSERT(!strcmp("v", format_to_string(&f)), "i8 as char");
	format_clear(&f);
	FORMAT(&f, "{z}", "abc");
	ASSERT(!strcmp("{z}", format_to_string(&f)),
	       "formatting error - string");
	format_clear(&f);
	Printable p = {.t = 100, .data.ivalue = 100};
	format_append(&f, "{}", p);
	ASSERT(!strcmp("", format_to_string(&f)),
	       "formatting error - invalid type");
	format_clear(&f);
	_debug_alloc_failure = true;
	FORMAT(&f, "{}", "abc");
	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure");
	format_clear(&f);
	FORMAT(&f, "{{");
	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure");
	format_clear(&f);
	FORMAT(&f, "}}");
	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure");
	format_clear(&f);
	_debug_alloc_failure = false;
}

Test(strstr) {
	const char *s = "abcdefghi";
	ASSERT_EQ(strstr(s, "def"), s + 3, "strstr1");
	ASSERT_EQ(strstr(s, "x"), NULL, "no match");
}

