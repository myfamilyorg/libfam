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

#include <libfam/bible.h>
#include <libfam/linux.h>
#include <libfam/sha3.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>
#include <libfam/xxdir_dat.h>

#define WYHASH_P1 0xff51afd7ed558ccdULL
#define WYHASH_P2 0xc4ceb9fe1a85ec53ULL
#define GOLDEN_PRIME 0x517cc1b727220a95ULL
#define PHI_PRIME 0x9e3779b97f4a7c15ULL
#define LANE1_SALT (PHI_PRIME - 1)
#define LANE2_SALT (PHI_PRIME + 1)
#define LOOKUP_ROUNDS 48
#define GENESIS_MIX 0x123456789abcdef0ULL

#if TEST == 1
#define EXTENDED_BIBLE_SIZE (xxdir_file_size_0 + 1024 * 1024)
#else
#define EXTENDED_BIBLE_SIZE (256 * 1024 * 1024)
#endif
#define BIBLE_EXTENDED_INDICES (EXTENDED_BIBLE_SIZE >> 5)

struct Bible {
	u64 flags;
	u64 padding[3];
	u8 data[];
};

STATIC void bible_extended_lookup(const Bible *bible, u64 r, u8 out[32]) {
	r = (r % BIBLE_EXTENDED_INDICES) << 5;
	__builtin_memcpy(out, bible->data + r, 32);
}

PUBLIC const Bible *bible_gen(void) {
	u8 seed[32];
	Sha3Context ctx;
	u64 counter = 0;

	Bible *ret =
	    mmap(NULL, sizeof(Bible) + EXTENDED_BIBLE_SIZE,
		 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret == MAP_FAILED) return NULL;

	ret->flags = 0;
	__builtin_memcpy(ret->data, xxdir_file_0, xxdir_file_size_0);
	sha3_init256(&ctx);
	sha3_update(&ctx, xxdir_file_0, xxdir_file_size_0);
	__builtin_memcpy(&seed, sha3_finalize(&ctx), sizeof(seed));

	for (u64 offset = xxdir_file_size_0; offset < EXTENDED_BIBLE_SIZE;
	     offset += 32) {
		Sha3Context ctx;
		sha3_init256(&ctx);
		sha3_update(&ctx, &counter, sizeof(counter));
		sha3_update(&ctx, seed, sizeof(seed));
		__builtin_memcpy(ret->data + offset, sha3_finalize(&ctx), 32);
		__builtin_memcpy(seed, ret->data + offset, sizeof(seed));
		counter++;
	}

	return ret;
}

const Bible *bible_load(const u8 *path) {
	const Bible *ret = NULL;
	i32 fd = -1;
	fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0) goto cleanup;

	ret = mmap(NULL, sizeof(Bible) + EXTENDED_BIBLE_SIZE,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ret == MAP_FAILED) {
		ret = NULL;
		goto cleanup;
	}
cleanup:
	if (fd >= 0) close(fd);
	return ret;
}

PUBLIC i32 bible_store(const Bible *bible, const u8 *path) {
	i32 fd = -1;
	u64 to_write = sizeof(Bible) + EXTENDED_BIBLE_SIZE;
INIT:
	fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) ERROR();
	while (to_write) {
		i64 v = pwrite(fd, bible, to_write, 0);
		if (v < 0) ERROR();
		to_write -= v;
	}

CLEANUP:
	if (fd >= 0) close(fd);
	RETURN;
}

void bible_pow_hash(const Bible *b, const u8 *input, u64 input_len,
		    u8 out[32]) {
	u8 bdata[32];
	u64 h = input_len ^ GOLDEN_PRIME;
	for (u64 i = 0; i < input_len; i++) h = (h ^ input[i]) * PHI_PRIME;
	u64 s[4] = {h ^ PHI_PRIME, h ^ LANE1_SALT, h ^ LANE2_SALT,
		    h ^ GOLDEN_PRIME};

	for (u64 i = 0; i < LOOKUP_ROUNDS; i++) {
		bible_extended_lookup(b, s[0] ^ s[1] ^ s[2] ^ s[3], bdata);
		u64 *d = (void *)bdata;
		s[0] = (s[0] ^ d[0]) * GOLDEN_PRIME;
		s[1] = (s[1] ^ d[1]) * GOLDEN_PRIME;
		s[2] = (s[2] ^ d[2]) * GOLDEN_PRIME;
		s[3] = (s[3] ^ d[3]) * GOLDEN_PRIME;
	}

	__builtin_memcpy(out, s, 32);
}

void bible_destroy(const Bible *b) {
	munmap((void *)b, sizeof(Bible) + EXTENDED_BIBLE_SIZE);
}
