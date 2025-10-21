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
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/linux_time.h>
#include <libfam/memory.h>
#include <libfam/rng.h>
#include <libfam/spin.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

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
			_famexit(0);
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
			_famexit(0);
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
			_famexit(0);
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
	_debug_no_famexit = true;
	errno = 0;
	bitmap_release_bit(bmp, U64_MAX << 6);
	ASSERT_EQ(errno, EINVAL, "invalid");
	bitmap_release_bit(bmp, 66);
	errno = 0;
	bitmap_release_bit(bmp, 66);
	ASSERT_EQ(errno, EINVAL, "double free");

	_debug_no_write = false;
	_debug_no_famexit = false;

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
			_famexit(0);
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

Test(sysext) {
	const u8 *path = "/tmp/01234567789abc.txt";
	i32 fd;
	u128 v1, v2;

	getentropy(&v1, sizeof(u128));
	getentropy(&v2, sizeof(u128));
	ASSERT(v1 != v2, "getentropy");

	unlink(path);
	ASSERT(!exists(path), "!exists");
	fd = file(path);
	flush(fd);
	ASSERT(exists(path), "exists");
	close(fd);
	unlink(path);
}

typedef struct {
	i32 value1;
	i32 value2;
	i32 value3;
	i32 value4;
	i32 value5;
	u32 uvalue1;
	u32 uvalue2;
} SharedStateData;

Test(futex1) {
	if (getenv("VALGRIND")) return;
	void *base = smap(sizeof(SharedStateData));
	i32 cpid;
	SharedStateData *state = (SharedStateData *)base;
	state->uvalue1 = (u32)0;
	if ((cpid = two())) {
		while (state->uvalue1 == 0) {
			futex(&state->uvalue1, FUTEX_WAIT, 0, NULL, NULL, 0);
		}
		ASSERT(state->uvalue1, "value1");
		state->value2++;
	} else {
		state->uvalue1 = 1;
		futex(&state->uvalue1, FUTEX_WAKE, 1, NULL, NULL, 0);
		_famexit(0);
	}
	await(cpid);
	ASSERT(state->value2, "value2");
	munmap(base, sizeof(SharedStateData));
}

Test(sys) {
	struct epoll_event ev = {0};
	i32 fd, fd2;
	i32 pid = getpid();
	i32 ret = kill(pid, 0);
	i32 ret2 = kill(I32_MAX, 0);
	const u8 *path = "/tmp/systest.dat";
	ASSERT(!ret, "our pid");
	ASSERT(ret2, "invalid pid");
	errno = 0;
	ASSERT(getrandom(NULL, 512, 0), "len>256");
	ASSERT_EQ(errno, EIO, "eio");
	ASSERT(getrandom(NULL, 128, 0), "null buf");
	ASSERT_EQ(errno, EFAULT, "efault");

	_debug_no_famexit = true;
	abort();
	_debug_no_famexit = false;

	unlink(path);
	fd = file(path);
	fd2 = fcntl(fd, F_DUPFD);
	ASSERT(fd != fd2, "ne");
	ASSERT(fd > 0, "fd>0");
	ASSERT(fd2 > 0, "fd2>0");
	close(fd);
	close(fd2);
	unlink(path);
	msleep(1);

	fd = epoll_create1(0);
	ASSERT(fd > 0, "epfd>0");
	ASSERT_EQ(epoll_ctl(fd, EPOLL_CTL_ADD, -1, &ev), -1, "epoll_ctl");
	ASSERT_EQ(errno, EBADF, "ebadfd");
	errno = 0;
	ASSERT_EQ(epoll_pwait(fd, NULL, 0, 1, NULL, 0), -1, "epoll_pwait");
	ASSERT_EQ(errno, EINVAL, "einval");
	close(fd);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT(fd > 0, "fd>0");
	ASSERT(shutdown(fd, 0), "shutdown");
	ASSERT(accept(fd, NULL, NULL), "accept");
	ASSERT(bind(fd, NULL, 0), "bind");
	ASSERT(connect(fd, NULL, 0), "connect");
	ASSERT(setsockopt(fd, 0, 0, NULL, 0), "setsockopt");

	struct sockaddr_in address = {0};
	socklen_t addr_len = sizeof(address);
	ASSERT(getsockname(-1, (struct sockaddr *)&address, &addr_len),
	       "getsockname");
	ASSERT(!listen(fd, 0), "listen");
	ASSERT(getsockopt(0, 0, 0, NULL, NULL), "getsockopt is err");
	close(fd);

	fd2 = fcntl(fd, F_GETLEASE);

	ASSERT_EQ(mmap(NULL, 1024, 100, 100, 100, 100), MAP_FAILED,
		  "mmap fail");
}

Test(file) {
	u8 buf[10];
	const char *path = "/tmp/core_file.txt";
	unlink(path);
	i32 i, fd = file(path);
	ASSERT(fd > 0, "fd");
	ASSERT(write(fd, "test", 4), "write");
	lseek(fd, 0, SEEK_SET);
	ASSERT_EQ(read(fd, buf, sizeof(buf)), 4, "read");
	ASSERT(!memcmp(buf, "test", 4), "memcmp");
	ASSERT(!yield(), "yield");

	fresize(fd, 2);
	ASSERT(!close(fd), "close");

	fd = file(path);
	ASSERT_EQ(fsize(fd), 2, "len=2");
	char *ptr = fmap(fd, 2, 0);
	ASSERT_EQ(ptr[0], 't', "t");
	ASSERT_EQ(ptr[1], 'e', "e");
	munmap(ptr, 2);
	close(fd);

	ptr = map(128);
	for (i = 0; i < 128; i++) ASSERT(!ptr[i], "!ptr");

	munmap(ptr, 128);

	unlink(path);
}

Test(pipetwo) {
	if (getenv("VALGRIND")) return;
	u8 buf[10] = {0};
	i32 pid;
	i32 fds[2];
	ASSERT(!pipe(fds), "pipe");
	if ((pid = two())) {
		i32 len = read(fds[0], buf, sizeof(buf));
		ASSERT_EQ(len, 3, "len=3");
	} else {
		strcpy(buf, "abc");
		write(fds[1], buf, 3);
		_famexit(0);
	}
	ASSERT(pid > 0, "pid>0");
	ASSERT(!reap(pid), "reap");
	close(fds[0]);
	close(fds[1]);
}

Test(pipefork) {
	if (getenv("VALGRIND")) return;
	u8 buf[10] = {0};
	i32 pid;
	i32 fds[2];
	ASSERT(!pipe(fds), "pipe");
	if ((pid = fork())) {
		close(fds[1]);
		i32 len = read(fds[0], buf, sizeof(buf));
		ASSERT_EQ(len, 3, "len=3");
		ASSERT(!memcmp(buf, "abc", 3), "abc");
	} else {
		close(fds[0]);
		strcpy(buf, "abc");
		write(fds[1], buf, 3);
		_famexit(0);
	}
	await(pid);
	close(fds[0]);
}

bool sig_recv = false;
void test_handler(i32 sig) {
	ASSERT_EQ(sig, SIGUSR1, "sigusr1");
	sig_recv = true;
}
#define SIGSET_T_SIZE 8

Test(signal) {
	if (getenv("VALGRIND")) return;
	i32 fds[2];
	u8 buf[10];
	struct rt_sigaction act = {0};
	i32 pid;
	act.k_sa_handler = test_handler;
	act.k_sa_flags = SA_RESTORER;
	act.k_sa_restorer = restorer;
	ASSERT(!rt_sigaction(SIGUSR1, &act, NULL, SIGSET_T_SIZE),
	       "rt_sigaction");
	ASSERT(!pipe(fds), "pipe");
	if ((pid = fork())) {
		i32 len;
		close(fds[1]);
		kill(pid, SIGUSR1);
		len = read(fds[0], buf, sizeof(buf));
		ASSERT_EQ(len, 1, "read x");
		ASSERT_EQ(buf[0], 'x', "buf[0]=x");
	} else {
		close(fds[0]);
		while (!sig_recv) yield();
		write(fds[1], "x", 1);
		_famexit(0);
	}
	await(pid);
	close(fds[0]);
}

u8 LOCALHOST[4] = {127, 0, 0, 1};

u16 test_ntohs(u16 net) { return ((net & 0xFF) << 8) | ((net >> 8) & 0xFF); }
u16 test_htons(u16 host) { return ((host & 0xFF) << 8) | ((host >> 8) & 0xFF); }

i32 test_socket_listen(i32 *fd, const u8 addr[4], u16 port, u16 backlog) {
	i32 opt = 1, flags;
	i32 error = 0;
	i32 len = sizeof(error);
	struct sockaddr_in address = {0};
	socklen_t addr_len;
	i32 ret;

	if (!fd || !addr) {
		errno = EINVAL;
		return -1;
	}

	ret = socket(AF_INET, SOCK_STREAM, 0);

	if (ret < 0) return -1;

	if (getsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &error, &len)) {
		close(ret);
		return -1;
	}

	if (setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		close(ret);
		return -1;
	}

	if ((flags = fcntl(ret, F_GETFL, 0)) == -1) {
		close(ret);
		return -1;
	}
	if (fcntl(ret, F_SETFL, flags | O_NONBLOCK) == -1) {
		close(ret);
		return -1;
	}

	address.sin_family = AF_INET;
	memcpy(&address.sin_addr, addr, 4);
	address.sin_port = test_htons(port);

	if (bind(ret, (struct sockaddr *)&address, sizeof(address))) {
		close(ret);
		return -1;
	}
	if (listen(ret, backlog) == -1) {
		close(ret);
		return -1;
	}

	addr_len = sizeof(address);
	if (getsockname(ret, (struct sockaddr *)&address, &addr_len) == -1) {
		close(ret);
		return -1;
	}

	*fd = ret;
	return test_ntohs(address.sin_port);
}

Test(sock_sys) {
	i32 server = 0, client = 0, inbound = 0;
	struct sockaddr_in address = {0};
	i32 port = test_socket_listen(&server, LOCALHOST, 0, 10);
	ASSERT(port > 0, "port");
	ASSERT(server > 0, "server");

	address.sin_family = AF_INET;
	memcpy(&address.sin_addr, LOCALHOST, 4);
	address.sin_port = test_htons(port);
	client = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT(client > 0, "client");
	ASSERT(!connect(client, (struct sockaddr *)&address, sizeof(address)),
	       "connect");

	inbound = accept(server, NULL, NULL);
	ASSERT(inbound > 0, "inbound");
	ASSERT(!shutdown(client, SHUT_RDWR), "shutdown");

	close(server);
	close(inbound);
	close(client);
}

Test(epoll) {
	struct epoll_event events[1];
	struct epoll_event ev = {0};
	i32 efd = epoll_create1(0);
	i32 server = 0;
	i32 port = test_socket_listen(&server, LOCALHOST, 0, 10);

	ASSERT(server > 0, "server");
	ASSERT(port > 0, "port");

	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	ev.data.ptr = &server;

	ASSERT(!epoll_ctl(efd, EPOLL_CTL_ADD, server, &ev), "epoll_ctl");
	ASSERT(!epoll_pwait(efd, events, 1, 1, NULL, 0), "epoll_pwait");

	close(efd);
	close(server);
}

#define MSYNC_SIZE 4096

Test(msync) {
	const u8 *path = "/tmp/msync_test";
	unlink(path);
	i32 fd = file(path);
	ASSERT(fd > 0, "fd");
	ASSERT(!fresize(fd, MSYNC_SIZE), "fresize");
	u8 data2[MSYNC_SIZE] = {0};
	u8 *data = fmap(fd, MSYNC_SIZE, 0);
	data[0] = 99;
	ASSERT(!msync(data, MSYNC_SIZE, MS_SYNC), "msync");
	read(fd, data2, MSYNC_SIZE);
	ASSERT_EQ(data2[0], 99, "synced");

	munmap(data, MSYNC_SIZE);
	close(fd);
	unlink(path);
}

/*
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

*/

Test(strstr) {
	const char *s = "abcdefghi";
	ASSERT_EQ(strstr(s, "def"), s + 3, "strstr1");
	ASSERT_EQ(strstr(s, "x"), NULL, "no match");
}

Test(fstatat) {
	const u8 *path = "/tmp/fstat1.txt";
	unlink(path);
	i32 fd = file(path);
	ASSERT(fd > 0, "fd");
	struct stat st;
	errno = 0;
	i32 res;
	errno = 0;
	ASSERT(!(res = fstatat(AT_FDCWD, path, &st, 0)), "fstatat 1");
	ASSERT(st.st_mtime, "non 0");
	ASSERT_EQ(st.st_mode, 33152, "default permissions");
	ASSERT(!fchmod(fd, 755), "chmod");
	struct timevalfam times[2] = {0};
	ASSERT(!utimesat(AT_FDCWD, path, times, 0), "utime");
	errno = 0;
	ASSERT(!(res = fstatat(AT_FDCWD, path, &st, 0)), "fstatat 2");
	ASSERT(!st.st_mtime, "set to 0");
	ASSERT_EQ(st.st_mode, 33523, "updated permissions");
	memset(&st, 0, sizeof(st));
	ASSERT(!fstatat(AT_FDCWD, path, &st, 0), "fstatat");
	ASSERT(!st.st_mtime, "set to 0");
	ASSERT_EQ(st.st_mode, 33523, "updated permissions");

	times[0].tv_sec = 7;
	times[1].tv_sec = 8;
	ASSERT(!utimesat(AT_FDCWD, path, times, 0), "utime");
	ASSERT(!fstatat(AT_FDCWD, path, &st, 0), "fstatat");
	ASSERT_EQ(st.st_mtime, 8, "set to 8");
	ASSERT_EQ(st.st_atime, 7, "set to 7");
	st.st_mtime = st.st_atime = 0;
	ASSERT(!fstat(fd, &st), "fstat");
	ASSERT_EQ(st.st_mtime, 8, "set to 8");
	ASSERT_EQ(st.st_atime, 7, "set to 7");

	close(fd);
	unlink(path);
}

/*

Test(ioruring) {
	struct io_uring_params params = {0};
	i32 fd = io_uring_setup(2, &params);
	ASSERT(fd > 0, "io_uring_setup failed");

	u32 sq_ring_size =
	    params.sq_off.array + params.sq_entries * sizeof(u32);
	u32 cq_ring_size = params.cq_off.cqes +
			   params.cq_entries * sizeof(struct io_uring_cqe);
	u8 *sq_ring = mmap(NULL, sq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, IORING_OFF_SQ_RING);
	ASSERT(sq_ring != MAP_FAILED, "sq_ring mmap failed");
	u8 *cq_ring = mmap(NULL, cq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, IORING_OFF_CQ_RING);
	ASSERT(cq_ring != MAP_FAILED, "cq_ring mmap failed");

	struct io_uring_sqe *sqes =
	    mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe),
		 PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQES);
	ASSERT(sqes != MAP_FAILED, "sqes mmap failed");

	u32 *sq_tail = (u32 *)(sq_ring + params.sq_off.tail);
	u32 *sq_array = (u32 *)(sq_ring + params.sq_off.array);
	u32 *cq_head = (u32 *)(cq_ring + params.cq_off.head);
	u32 *cq_tail = (u32 *)(cq_ring + params.cq_off.tail);
	u32 *ring_mask = (u32 *)(cq_ring + params.cq_off.ring_mask);
	struct io_uring_cqe *cqes =
	    (struct io_uring_cqe *)(cq_ring + params.cq_off.cqes);

	(void)cq_head;
	(void)cq_tail;
	(void)ring_mask;
	(void)cqes;

	sqes[0].opcode = IORING_OP_NOP;
	sqes[0].flags = 0;
	sqes[0].user_data = 123;

	sq_array[0] = 0;
	__aadd32(sq_tail, 1);
	i32 to_submit = 1;
	i32 min_complete = 1;
	i32 res = io_uring_enter2(fd, to_submit, min_complete,
				  IORING_ENTER_GETEVENTS, NULL, 0);

	ASSERT_EQ(res, 1, "io_uring_enter2 returned {}, expected 1", res);

	munmap(sq_ring, sq_ring_size);
	munmap(cq_ring, cq_ring_size);
	munmap(sqes, params.sq_entries * sizeof(struct io_uring_sqe));
	close(fd);
}

Test(ioruring_read_file) {
	// Initialize io_uring
	struct io_uring_params params = {0};
	i32 fd = io_uring_setup(2, &params);
	ASSERT(fd > 0, "io_uring_setup failed");

	// Map submission and completion queues
	u32 sq_ring_size =
	    params.sq_off.array + params.sq_entries * sizeof(u32);
	u32 cq_ring_size = params.cq_off.cqes +
			   params.cq_entries * sizeof(struct io_uring_cqe);
	u8 *sq_ring = mmap(NULL, sq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, IORING_OFF_SQ_RING);
	ASSERT(sq_ring != MAP_FAILED, "sq_ring mmap failed");
	u8 *cq_ring = mmap(NULL, cq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, IORING_OFF_CQ_RING);
	ASSERT(cq_ring != MAP_FAILED, "cq_ring mmap failed");

	struct io_uring_sqe *sqes =
	    mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe),
		 PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQES);
	ASSERT(sqes != MAP_FAILED, "sqes mmap failed");

	// Setup queue pointers
	u32 *sq_tail = (u32 *)(sq_ring + params.sq_off.tail);
	u32 *sq_array = (u32 *)(sq_ring + params.sq_off.array);
	u32 *cq_head = (u32 *)(cq_ring + params.cq_off.head);
	u32 *cq_tail = (u32 *)(cq_ring + params.cq_off.tail);
	u32 *ring_mask = (u32 *)(cq_ring + params.cq_off.ring_mask);
	struct io_uring_cqe *cqes =
	    (struct io_uring_cqe *)(cq_ring + params.cq_off.cqes);

	// Open file to read
	const char *filename = "resources/test_micro.txt";
	i32 file_fd = file(filename);
	ASSERT(file_fd >= 0, "Failed to open file: {}", strerror(errno));

	// Allocate buffer for reading
	const u64 read_size = 1024;
	void *buffer = alloc(read_size);
	ASSERT(buffer != NULL, "Failed to allocate buffer");

	// Setup read operation
	sqes[0].opcode = IORING_OP_READ;
	sqes[0].flags = 0;
	sqes[0].fd = file_fd;
	sqes[0].addr = (u64)buffer;
	sqes[0].len = read_size;
	sqes[0].off = 0;  // Read from start of file
	sqes[0].user_data = 123;

	sq_array[0] = 0;
	__aadd32(sq_tail, 1);

	// Submit and wait for completion
	i32 to_submit = 1;
	i32 min_complete = 1;
	i32 res = io_uring_enter2(fd, to_submit, min_complete,
				  IORING_ENTER_GETEVENTS, NULL, 0);
	ASSERT_EQ(res, 1, "io_uring_enter2 returned {}, expected 1", res);

	// Check completion
	ASSERT(*cq_head != *cq_tail, "No completion events");
	i32 cqe_idx = *cq_head & *ring_mask;
	ASSERT_EQ(cqes[cqe_idx].user_data, 123, "Unexpected user_data");
	ASSERT(cqes[cqe_idx].res >= 0, "Read failed: {}",
	       strerror(-cqes[cqe_idx].res));
	ASSERT_EQ(cqes[cqe_idx].res, 128, "file_size");
	ASSERT(!memcmp(buffer, "abc 123", 7), "start of file data");

	// Cleanup
	release(buffer);
	close(file_fd);
	munmap(sq_ring, sq_ring_size);
	munmap(cq_ring, cq_ring_size);
	munmap(sqes, params.sq_entries * sizeof(struct io_uring_sqe));
	close(fd);
}

#define OUT_FILE_1 "/tmp/test_out1.txt"

Test(iouring_module) {
	unlink(OUT_FILE_1);
	IoUring *iou = NULL;
	ASSERT(!iouring_init(&iou, 4), "iouring_init");
	u8 buf[1025] = {0};
	u64 id;

	i32 fd_in = file("resources/akjv5.txt");
	i32 fd_out = file(OUT_FILE_1);

	iouring_init_read(iou, fd_in, buf, 1024, 0, 123);
	iouring_submit(iou, 1);

	ASSERT(iouring_pending(iou, 123), "pending 456");
	i32 res = iouring_spin(iou, &id);
	ASSERT(!iouring_pending(iou, 123), "pending 456");

	ASSERT_EQ(res, 1024, "1024");
	ASSERT_EQ(id, 123, "123");

	iouring_init_write(iou, fd_out, buf, 1024, 0, 456);
	iouring_submit(iou, 1);

	ASSERT(iouring_pending(iou, 456), "pending 456");
	res = iouring_wait(iou, &id);
	ASSERT(!iouring_pending(iou, 456), "pending 456");

	ASSERT_EQ(id, 456, "456");

	close(fd_in);
	close(fd_out);
	unlink(OUT_FILE_1);

	iouring_destroy(iou);
	ASSERT_BYTES(0);
}
*/

Test(spin_lock) {
	SpinLock lock1 = {0};
	ASSERT_EQ(lock1.value, 0, "0a");
	spin_lock(&lock1);
	ASSERT_EQ(lock1.value, 1, "1");
	spin_unlock(&lock1);
	ASSERT_EQ(lock1.value, 0, "0b");
}

#define SPIN_PROCS 256
#define SPIN_ITER 4096

Test(spin_threads) {
	if (getenv("VALGRIND")) return;

	i32 i;
	i32 pids[SPIN_PROCS] = {0};
	u64 *count = smap(sizeof(u64));
	SpinLock *sl = smap(sizeof(SpinLock));
	*count = 0;
	*sl = SPINLOCK_INIT;

	for (i = 0; i < SPIN_PROCS; i++) {
		pids[i] = two();
		if (!pids[i]) {
			for (i = 0; i < SPIN_ITER; i++) {
				spin_lock(sl);
				*count = *count + 1;
				spin_unlock(sl);
			}
			_famexit(0);
		}
	}

	for (i = 0; i < SPIN_PROCS; i++) await(pids[i]);
	ASSERT_EQ(*count, SPIN_ITER * SPIN_PROCS,
		  "count==SPIN_ITER * SPIN_PROCS");
	munmap(count, sizeof(u64));
	munmap(sl, sizeof(SpinLock));
}
