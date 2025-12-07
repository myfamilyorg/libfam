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
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>
#include <libfam/xxdir_dat.h>

#define WYHASH_P1 0xff51afd7ed558ccdULL
#define WYHASH_P2 0xc4ceb9fe1a85ec53ULL
#define GOLDEN_PRIME 0x517cc1b727220a95ULL
#define PHI_PRIME 0x9e3779b97f4a7c15ULL
#define LOOKUP_ROUNDS 32
#define STORM_ITER (LOOKUP_ROUNDS * 1024)

#define EXTENDED_BIBLE_SIZE (256 * 1024 * 1024)
#define BIBLE_EXTENDED_INDICES (EXTENDED_BIBLE_SIZE >> 5)
#define BIBLE_EXTENDED_MASK (BIBLE_EXTENDED_INDICES - 1)

struct __attribute__((aligned(64))) Bible {
	u64 flags;
	u64 padding[7];
	u8 data[];
};

PUBLIC const Bible *bible_gen(void) {
	u8 buffer[32];
	StormContext ctx;

	Bible *ret =
	    mmap(NULL, sizeof(Bible) + EXTENDED_BIBLE_SIZE,
		 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret == MAP_FAILED) return NULL;
	ret->flags = 0;
	fastmemcpy(ret->data, xxdir_file_0, xxdir_file_size_0);

	storm_init(&ctx, (u8[32]){0});
	u64 off = 0;
	while (off < xxdir_file_size_0) {
		fastmemcpy(buffer, xxdir_file_0 + off, 32);
		storm_xcrypt_buffer(&ctx, buffer);
		off += 32;
	}

	for (u64 offset = xxdir_file_size_0; offset < EXTENDED_BIBLE_SIZE;
	     offset += 32) {
		for (u32 i = 0; i < STORM_ITER; i++) {
			StormContext ctx;
			storm_init(&ctx, buffer);
			storm_xcrypt_buffer(&ctx, buffer);
		}
		fastmemcpy(ret->data + offset, buffer, 32);
	}

	return ret;
}

const Bible *bible_load(const u8 *path) {
	const Bible *ret = NULL;
	i32 fd = -1;
	fd = open(path, O_RDWR, 0);

	if (fd >= 0) {
		ret = fmap(fd, sizeof(Bible) + EXTENDED_BIBLE_SIZE, 0);
		close(fd);
	}

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

PUBLIC void bible_sbox8_64(u64 sbox[256]) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	StormContext ctx;
	storm_init(&ctx, (u8[32]){0});

	u8 *sbox_u8 = (void *)sbox;
	for (u32 i = 0; i < 256 / 4; i++) {
		storm_xcrypt_buffer(&ctx, buf);
		fastmemcpy(sbox_u8 + i * 32, buf, 32);
	}
}

PUBLIC void bible_hash(const Bible *b, const u8 input[HASH_INPUT_LEN],
		       u8 out[32], const u64 sbox[256]) {
	u64 d[4];
	u64 s[4] = {GOLDEN_PRIME, PHI_PRIME, WYHASH_P1, WYHASH_P2};

	for (u64 quarter = 0; quarter < 4; quarter++) {
		u64 r =
		    (u64)b->data +
		    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
		const u8 *quarter_data = input + quarter * 32;
		const u8 *in = (const u8 *)d;

		fastmemcpy(d, (void *)r, 32);
		d[0] ^= ((u64 *)quarter_data)[0];
		d[1] ^= ((u64 *)quarter_data)[1];
		d[2] ^= ((u64 *)quarter_data)[2];
		d[3] ^= ((u64 *)quarter_data)[3];

		for (int lane = 0; lane < 4; lane++) {
			u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
				 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
				 in[lane + 24] ^ in[lane + 28];
			s[lane] ^= sbox[idx];
		}
	}

	for (u64 i = 0; i < LOOKUP_ROUNDS; i++) {
		u64 r =
		    (u64)b->data +
		    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
		const u8 *in = (const u8 *)d;
		fastmemcpy(d, (void *)r, 32);

		for (i32 lane = 0; lane < 4; lane++) {
			u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
				 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
				 in[lane + 24] ^ in[lane + 28];

			s[lane] ^= sbox[idx];
		}
	}

	fastmemcpy(out, s, 32);
}

i32 mine_block(const Bible *bible, const u8 header[HASH_INPUT_LEN],
	       const u8 target[32], u8 out[32], u32 *nonce, u32 max_iter,
	       u64 sbox[256]) {
	if (max_iter == 0) return -1;
	u8 header_copy[HASH_INPUT_LEN];
	*nonce = 0;
	fastmemcpy(header_copy, header, HASH_INPUT_LEN);
	do {
		((u32 *)header_copy)[31] = *nonce;
		bible_hash(bible, header_copy, out, sbox);
	} while (memcmp(target, out, 32) < 0 && ++(*nonce) < max_iter);
	return *nonce == max_iter ? -1 : 0;
}

void bible_destroy(const Bible *b) {
	munmap((void *)b, sizeof(Bible) + EXTENDED_BIBLE_SIZE);
}
