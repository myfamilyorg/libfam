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
#include <libfam/utils.h>
#include <libfam/xxdir_dat.h>

#define WYHASH_P1 0xff51afd7ed558ccdULL
#define WYHASH_P2 0xc4ceb9fe1a85ec53ULL
#define PHI_PRIME 0x9e3779b97f4a7c15ULL
#define GENESIS_MIX 0x123456789abcdef0ULL

Bible __bible = {0};

PUBLIC const Bible *bible(void) {
	if (__bible.text) return &__bible;
	u8 *btext = mmap(NULL, EXTENDED_BIBLE_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (btext == MAP_FAILED) return NULL;
	memcpy(btext, xxdir_file_0, xxdir_file_size_0);
	__bible.text = btext;
	return &__bible;
}

PUBLIC void bible_extend(void) {
	u64 seed;
	Sha3Context ctx;
	u64 counter = 0;

	sha3_init256(&ctx);
	sha3_update(&ctx, xxdir_file_0, xxdir_file_size_0);
	memcpy(&seed, sha3_finalize(&ctx), sizeof(seed));

	for (u64 offset = xxdir_file_size_0; offset < EXTENDED_BIBLE_SIZE;
	     offset += 32) {
		u64 idx = counter++;
		idx ^= idx >> 33;
		idx *= WYHASH_P1;
		idx ^= idx >> 33;
		idx *= WYHASH_P2;
		idx ^= idx >> 33;

		u64 prev = ((u64 *)(__bible.text + offset - 32))[0];
		idx ^= prev;
		idx ^= seed;
		((u64 *)(__bible.text + offset))[0] = idx;
		((u64 *)(__bible.text + offset))[1] = idx * PHI_PRIME;
		((u64 *)(__bible.text + offset))[2] = idx ^ GENESIS_MIX;
		((u64 *)(__bible.text + offset))[3] = idx + counter;
	}
}
