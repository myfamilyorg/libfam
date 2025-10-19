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

#ifdef __AVX2__
#include <immintrin.h>
#endif /* __AVX2__ */
#include <libfam/builtin.h>
#include <libfam/lz_hashtable.h>

#define HASH_CONSTANT 0x9e3779b9U
#define HASH_SHIFT 16
#define MAX_MATCH_LEN 256
#define MIN_MATCH_LEN 4

LzMatch lz_find_matches(LzHashtable *hash, const u8 *text, u32 cpos) {
	u16 pos, dist, len = 0, ucpos = cpos;
	u32 mpos, key = *(u32 *)(text + cpos);
	u32 index = (key * HASH_CONSTANT) >> HASH_SHIFT;
	pos = hash->table[index];
	hash->table[index] = ucpos;
	dist = ucpos - pos;
	if (!dist) return (LzMatch){.len = 0, .dist = 0};
	mpos = cpos - dist;

#ifdef __AVX2__
	u32 mask;
	do {
		__m256i vec1 =
		    _mm256_loadu_si256((__m256i *)(text + mpos + len));
		__m256i vec2 =
		    _mm256_loadu_si256((__m256i *)(text + cpos + len));
		__m256i cmp = _mm256_cmpeq_epi8(vec1, vec2);
		mask = _mm256_movemask_epi8(cmp);

		len += (mask != 0xFFFFFFFF) * ctz_u32(~mask) +
		       ((mask == 0xFFFFFFFF) << 5);
	} while (mask == 0xFFFFFFFF && len < MAX_MATCH_LEN);
#else

	while (len < MAX_MATCH_LEN && text[mpos + len] == text[cpos + len])
		len++;
#endif /* !__AVX2__ */

	if (len >= MIN_MATCH_LEN) {
		u32 key;
		key = *(u32 *)(text + cpos + 1);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 1;
		key = *(u32 *)(text + cpos + 2);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 2;
		key = *(u32 *)(text + cpos + 3);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 3;
	}

	return (LzMatch){.len = len, .dist = dist};
}

LzMatch lz_find_matches2(LzHashtable *hash, const u8 *text, u32 cpos) {
	u16 pos, dist, len = 0, ucpos = cpos;
	u32 mpos, key = *(u32 *)(text + cpos);
	u32 index = (key * HASH_CONSTANT) >> HASH_SHIFT;
	pos = hash->table[index];
	hash->table[index] = ucpos;
	dist = ucpos - pos;
	if (!dist) return (LzMatch){.index = 0, .len = 0, .dist = 0};
	mpos = cpos - dist;

	u32 mask;
	do {
		__m256i vec1 =
		    _mm256_loadu_si256((__m256i *)(text + mpos + len));
		__m256i vec2 =
		    _mm256_loadu_si256((__m256i *)(text + cpos + len));
		__m256i cmp = _mm256_cmpeq_epi8(vec1, vec2);
		mask = _mm256_movemask_epi8(cmp);

		len += (mask != 0xFFFFFFFF) * ctz_u32(~mask) +
		       ((mask == 0xFFFFFFFF) << 5);
	} while (mask == 0xFFFFFFFF && len < MAX_MATCH_LEN);

	if (len >= MIN_MATCH_LEN) {
		u32 key;
		key = *(u32 *)(text + cpos + 1);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 1;
		key = *(u32 *)(text + cpos + 2);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 2;
		key = *(u32 *)(text + cpos + 3);
		hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = ucpos + 3;
	}

	return (LzMatch){.index = 0, .len = len, .dist = dist};
}

