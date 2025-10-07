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

#ifdef __x86_64__
#include <immintrin.h>
#endif /* __x86_64__ */
#include <libfam/bitstream.h>
#include <libfam/builtin.h>
#include <libfam/compress_impl.h>
#include <libfam/utils.h>

STATIC u16 compress_get_match_code(u16 len, u32 dist) {
	u32 len_bits = 31 - clz_u32(len - 3);
	u32 dist_bits = 31 - clz_u32(dist);
	return ((len_bits << LEN_SHIFT) | dist_bits);
}

STATIC u8 compress_length_extra_bits(u16 match_code) {
	return match_code >> LEN_SHIFT;
}

STATIC u8 compress_distance_extra_bits(u16 match_code) {
	return match_code & DIST_MASK;
}

STATIC u16 compress_length_base(u16 match_code) {
	u32 len_bits = match_code >> LEN_SHIFT;
	return (1 << len_bits) - 1;
}

STATIC u16 compress_distance_base(u16 match_code) {
	u32 distance_bits = match_code & DIST_MASK;
	return 1 << distance_bits;
}

STATIC u16 compress_length_extra_bits_value(u16 code, u16 actual_length) {
	u16 base_length = compress_length_base(code);
	return actual_length - base_length - 4;
}

STATIC u16 compress_distance_extra_bits_value(u16 code, u16 actual_distance) {
	u32 distance_bits = code & DIST_MASK;
	u16 base_distance = 1 << distance_bits;
	return actual_distance - base_distance;
}

STATIC MatchInfo lz_hash_get(const LzHash *hash, const u8 *text, u32 cpos) {
	u16 pos, dist, len = 0;
	u32 mpos, key = *(u32 *)(text + cpos);
	pos = hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT];
	dist = (u16)cpos - pos;
	if (!dist) return (MatchInfo){.len = 0, .dist = 0};
	mpos = cpos - dist;
	while (len < MAX_MATCH_LEN && text[mpos + len] == text[cpos + len])
		len++;
	return (MatchInfo){.len = len, .dist = dist};
}

STATIC void lz_hash_set(LzHash *hash, const u8 *text, u32 cpos) {
	u32 key = *(u32 *)(text + cpos);
	hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = (u16)cpos;
}

STATIC void compress_calculate_frequencies(const u8 *in, u32 len,
					   u32 frequencies[SYMBOL_COUNT]) {
	u32 max, i = 0, j = 0, k = 0;
	LzHash hash = {0};

	max = len >= MAX_MATCH_LEN ? len - MAX_MATCH_LEN : 0;
	while (i < max) {
		u16 symbol, mlen;
		MatchInfo mi = lz_hash_get(&hash, in, i);
		lz_hash_set(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			symbol = MATCH_OFFSET +
				 compress_get_match_code(mi.len, mi.dist);
			mlen = mi.len;
		} else
			mlen = 0, symbol = in[i];
		frequencies[symbol]++;
		for (j = i + 1, k = i + mlen; j < k; j++)
			lz_hash_set(&hash, in, j);
		i = j;
	}
	while (i < len) frequencies[in[i++]]++;
	frequencies[SYMBOL_TERM]++;
}

STATIC void compress_init_node(HuffmanNode *node, u16 symbol, u64 freq) {
	node->symbol = symbol;
	node->freq = freq;
	node->left = node->right = NULL;
}

STATIC void compress_swap_nodes(HuffmanNode **a, HuffmanNode **b) {
	HuffmanNode *temp = *a;
	*a = *b;
	*b = temp;
}

STATIC void compress_heapify(HuffmanMinHeap *heap, u64 idx) {
	u64 smallest = idx;
	u64 left = 2 * idx + 1;
	u64 right = 2 * idx + 2;

	if (left < heap->size &&
	    heap->nodes[left]->freq < heap->nodes[smallest]->freq)
		smallest = left;
	if (right < heap->size &&
	    heap->nodes[right]->freq < heap->nodes[smallest]->freq)
		smallest = right;

	if (smallest != idx) {
		compress_swap_nodes(&heap->nodes[idx], &heap->nodes[smallest]);
		compress_heapify(heap, smallest);
	}
}

STATIC void compress_insert_heap(HuffmanMinHeap *heap, HuffmanNode *node) {
	u64 i = ++heap->size - 1;
	heap->nodes[i] = node;

	while (i && heap->nodes[(i - 1) / 2]->freq > heap->nodes[i]->freq) {
		compress_swap_nodes(&heap->nodes[i], &heap->nodes[(i - 1) / 2]);
		i = (i - 1) / 2;
	}
}

STATIC HuffmanNode *compress_extract_min(HuffmanMinHeap *heap) {
	HuffmanNode *min;
	if (heap->size == 0) return NULL;

	min = heap->nodes[0];
	heap->nodes[0] = heap->nodes[heap->size - 1];
	heap->size--;
	compress_heapify(heap, 0);

	return min;
}

STATIC void compress_compute_lengths(HuffmanNode *node, u8 length,
				     u8 lengths[SYMBOL_COUNT]) {
	if (!node) return;
	if (!node->left && !node->right) lengths[node->symbol] = length;
	compress_compute_lengths(node->left, length + 1, lengths);
	compress_compute_lengths(node->right, length + 1, lengths);
}

STATIC void compress_build_tree(const u32 frequencies[SYMBOL_COUNT],
				u8 lengths[SYMBOL_COUNT],
				HuffmanMinHeap *heap) {
	i32 i;
	u16 node_counter = 0;
	HuffmanNode nodes[SYMBOL_COUNT * 2 + 1];

	heap->size = 0;

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (frequencies[i]) {
			HuffmanNode *next = &nodes[node_counter++];
			compress_init_node(next, i, frequencies[i]);
			compress_insert_heap(heap, next);
		}
	}

	if (heap->size == 1) {
		HuffmanNode *node = compress_extract_min(heap);
		lengths[node->symbol] = 1;
	} else {
		while (heap->size > 1) {
			HuffmanNode *left = compress_extract_min(heap);
			HuffmanNode *right = compress_extract_min(heap);
			HuffmanNode *parent = &nodes[node_counter++];
			compress_init_node(parent, 0xFFFF,
					   left->freq + right->freq);
			parent->left = left;
			parent->right = right;
			compress_insert_heap(heap, parent);
		}
	}
}

STATIC void compress_limit_lengths(const u32 frequencies[SYMBOL_COUNT],
				   u8 lengths[SYMBOL_COUNT]) {
	i32 i;
	u32 excess = 0;
	u32 needed = 0;

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i] > MAX_CODE_LENGTH) {
			excess +=
			    (lengths[i] - MAX_CODE_LENGTH) * frequencies[i];
			lengths[i] = MAX_CODE_LENGTH;
			needed += frequencies[i];
		}
	}

	while (excess > 0 && needed > 0) {
		for (i = 0; i < SYMBOL_COUNT && excess > 0; i++) {
			if (lengths[i] > 0 && lengths[i] < MAX_CODE_LENGTH &&
			    frequencies[i] > 0) {
				u32 delta = (excess < frequencies[i])
						? excess
						: frequencies[i];
				lengths[i]++;
				excess -= delta;
				needed -= delta;
			}
		}
	}

	u64 sum = 0;
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i] > 0) {
			sum += 1ULL << (MAX_CODE_LENGTH - lengths[i]);
		}
	}

	while (sum > (1ULL << MAX_CODE_LENGTH)) {
		for (i = SYMBOL_COUNT - 1; i >= 0; i--)
			if (lengths[i] > 1 && lengths[i] < MAX_CODE_LENGTH) {
				lengths[i]++;
				break;
			}
		sum = 0;
		for (i = 0; i < SYMBOL_COUNT; i++) {
			if (lengths[i] > 0) {
				sum += 1ULL << (MAX_CODE_LENGTH - lengths[i]);
			}
		}
	}
}

STATIC void compress_calculate_lengths(const u32 frequencies[SYMBOL_COUNT],
				       u8 lengths[SYMBOL_COUNT]) {
	HuffmanMinHeap heap;
	HuffmanNode *root;
	compress_build_tree(frequencies, lengths, &heap);
	if ((root = compress_extract_min(&heap)) != NULL) {
		compress_compute_lengths(root, 0, lengths);
		compress_limit_lengths(frequencies, lengths);
	}
}

STATIC void compress_calculate_codes(const u8 lengths[SYMBOL_COUNT],
				     u16 codes[SYMBOL_COUNT]) {
	u32 i, j, code = 0;
	u32 length_count[MAX_CODE_LENGTH + 1] = {0};
	u32 length_start[MAX_CODE_LENGTH + 1] = {0};
	u32 length_pos[MAX_CODE_LENGTH + 1] = {0};

	for (i = 0; i < SYMBOL_COUNT; i++) length_count[lengths[i]]++;

	for (i = 1; i <= MAX_CODE_LENGTH; i++) {
		code <<= 1;
		length_start[i] = code;
		code += length_count[i];
	}

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i] == 0)
			codes[i] = 0;
		else {
			u8 len = lengths[i];
			codes[i] = length_start[len] + length_pos[len]++;
			codes[i] &= (1U << len) - 1;

			u16 reversed = 0;
			u16 temp = codes[i];
			for (j = 0; j < len; j++) {
				reversed = (reversed << 1) | (temp & 1);
				temp >>= 1;
			}
			codes[i] = reversed;
		}
	}
}

STATIC i32 compress_write_lengths(BitStreamWriter *strm,
				  const u8 lengths[SYMBOL_COUNT]) {
	i32 i;
INIT:
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i]) {
			WRITE(strm, lengths[i], 4);
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT && lengths[run] == 0) run++;
			run -= i;
			if (run >= 11) {
				run = run > 138 ? 127 : run - 11;
				WRITE(strm, 14, 4);
				WRITE(strm, run, 7);
				i += run + 10;
			} else if (run >= 3) {
				run = run - 3;
				WRITE(strm, 15, 4);
				WRITE(strm, run, 3);
				i += run + 2;
			} else
				WRITE(strm, 0, 4);
		}
	}
CLEANUP:
	RETURN;
}

STATIC i32 compress_read_lengths(BitStreamReader *strm,
				 u8 lengths[SYMBOL_COUNT]) {
	i32 i = 0, j;
INIT:
	while (i < SYMBOL_COUNT) {
		u8 code = TRY_READ(strm, 4);
		if (code < 14)
			lengths[i++] = code;
		else if (code == 14) {
			u8 zeros = TRY_READ(strm, 7) + 11;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++) lengths[i++] = 0;
		} else if (code == 15) {
			u8 zeros = TRY_READ(strm, 3) + 3;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++) lengths[i++] = 0;
		}
	}
CLEANUP:
	RETURN;
}

STATIC i32 compress_write(const u16 codes[SYMBOL_COUNT],
			  const u8 lengths[SYMBOL_COUNT], const u8 *in, u64 len,
			  BitStreamWriter *strm, bool fin) {
	u64 i, j, k, max;
	LzHash hash = {0};
INIT:
	WRITE(strm, fin, 1);
	if (compress_write_lengths(strm, lengths) < 0) ERROR();

	j = 0;
	i = 0;
	max = len >= MAX_MATCH_LEN ? len - MAX_MATCH_LEN : 0;

	while (i < max) {
		u16 symbol, mlen;
		MatchInfo mi = lz_hash_get(&hash, in, i);
		lz_hash_set(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			u8 match_code =
			    compress_get_match_code(mi.len, mi.dist);
			symbol = MATCH_OFFSET + match_code;
			mlen = mi.len;
			WRITE(strm, codes[symbol], lengths[symbol]);
			u16 len_extra_value = compress_length_extra_bits_value(
			    match_code, mi.len);
			u16 dist_extra_value =
			    compress_distance_extra_bits_value(match_code,
							       mi.dist);
			u8 len_extra_bits =
			    compress_length_extra_bits(match_code);
			u8 dist_extra_bits =
			    compress_distance_extra_bits(match_code);

			if (len_extra_bits)
				WRITE(strm, len_extra_value, len_extra_bits);
			if (dist_extra_bits)
				WRITE(strm, dist_extra_value, dist_extra_bits);
		} else {
			mlen = 0;
			symbol = in[i];
			WRITE(strm, codes[symbol], lengths[symbol]);
		}

		for (j = i + 1, k = i + mlen; j < k; j++)
			lz_hash_set(&hash, in, j);
		i = j;
	}
	while (i < len) {
		u16 symbol = in[i];
		WRITE(strm, codes[symbol], lengths[symbol]);
		i++;
	}

	WRITE(strm, codes[SYMBOL_TERM], lengths[SYMBOL_TERM]);
CLEANUP:
	RETURN;
}

STATIC void compress_build_lookup_table(
    const u8 lengths[SYMBOL_COUNT], const u16 codes[SYMBOL_COUNT],
    u16 lookup_table[(1U << MAX_CODE_LENGTH)]) {
	i32 i, j;
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i]) {
			i32 index = codes[i] & ((1U << lengths[i]) - 1);
			i32 fill_depth = 1U << (MAX_CODE_LENGTH - lengths[i]);
			for (j = 0; j < fill_depth; j++) {
				lookup_table[index | (j << lengths[i])] =
				    (lengths[i] << 12) | i;
			}
		}
	}
}

#ifdef __x86_64__
INLINE STATIC void copy_with_avx2(u8 *out_dest, const u8 *out_src,
				  u64 actual_length) {
	if (out_src + 32 < out_dest) {
		u64 chunks = (actual_length + 31) >> 5;
		while (chunks--) {
			__m256i vec = _mm256_loadu_si256((__m256i *)out_src);
			_mm256_storeu_si256((__m256i *)out_dest, vec);
			out_src += 32;
			out_dest += 32;
		}
	} else {
		u64 remainder = actual_length;
		while (remainder--) {
			*out_dest++ = *out_src++;
		}
	}
}
#endif /* _x86_64__ */

INLINE STATIC i32 compress_proc_match(u16 symbol, BitStreamReader *strm,
				      u8 *out, u64 capacity, u64 *itt) {
	u16 match_code, base_length, len_extra, actual_length, base_dist,
	    dist_extra, actual_distance;
	match_code = symbol - MATCH_OFFSET;
	u16 len_extra_bits = compress_length_extra_bits(match_code);
	u16 dist_extra_bits = compress_distance_extra_bits(match_code);
	base_length = compress_length_base(match_code);
	base_dist = compress_distance_base(match_code);

	len_extra = bitstream_reader_read(strm, len_extra_bits);
	bitstream_reader_clear(strm, len_extra_bits);
	dist_extra = bitstream_reader_read(strm, dist_extra_bits);
	bitstream_reader_clear(strm, dist_extra_bits);

	actual_length = 4 + base_length + len_extra;
	actual_distance = base_dist + dist_extra;
	if (actual_length + *itt > capacity) {
		errno = EOVERFLOW;
		return -1;
	}

	u8 *out_dest = out + *itt;
	u8 *out_src = out + *itt - actual_distance;
	*itt += actual_length;

#ifdef __x86_64__
	copy_with_avx2(out_dest, out_src, actual_length);
#else
	while (actual_length--) *out_dest++ = *out_src++;
#endif /* !__x86_64__ */
	return 0;
}

STATIC i64 compress_read_symbols(BitStreamReader *strm,
				 const u8 lengths[SYMBOL_COUNT],
				 const u16 codes[SYMBOL_COUNT], u8 *out,
				 u64 capacity) {
	u16 lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
	u64 itt = 0;
	u16 symbol = 0;
	u8 load_threshold = MAX_CODE_LENGTH + 7 + 15;

	compress_build_lookup_table(lengths, codes, lookup_table);

	while (true) {
		if (__builtin_expect(strm->bits_in_buffer < load_threshold, 0))
			bitstream_reader_load(strm);

		u16 bits = bitstream_reader_read(strm, MAX_CODE_LENGTH);
		u16 entry = lookup_table[bits];
		u8 length = entry >> 12;
		symbol = entry & 0x1FF;

		bitstream_reader_clear(strm, length);
		if (symbol < SYMBOL_TERM) {
			if (itt >= capacity) {
				errno = EOVERFLOW;
				return -1;
			}
			out[itt++] = symbol;
		} else if (symbol == SYMBOL_TERM)
			break;
		else if (compress_proc_match(symbol, strm, out, capacity,
					     &itt) < 0)
			return -1;
	}
	return itt;
}

PUBLIC u64 compress_bound(u64 len) { return len + (len << 7) + 1024; }

PUBLIC i64 compress(const u8 *in, u64 len, u8 *out, u64 capacity) {
	u64 offset = 0;
	BitStreamWriter strm = {out};
	bool fin = false;
INIT:
	if (capacity < compress_bound(len)) ERROR(EINVAL);
	WRITE(&strm, COMPRESS_MAGIC, 32);
	while (!fin) {
		u32 frequencies[SYMBOL_COUNT] = {0};
		u8 lengths[SYMBOL_COUNT] = {0};
		u16 codes[SYMBOL_COUNT];
		fin = offset + HUFFMAN_BLOCK_SIZE >= len;
		u64 max = fin ? len - offset : HUFFMAN_BLOCK_SIZE;
		compress_calculate_frequencies(in + offset, max, frequencies);
		compress_calculate_lengths(frequencies, lengths);
		compress_calculate_codes(lengths, codes);

		compress_write(codes, lengths, in + offset, max, &strm, fin);
		offset += HUFFMAN_BLOCK_SIZE;
	}
	WRITE(&strm, 0, 64); /* pad */
	if (strm.bits_in_buffer) bitstream_writer_flush(&strm);
	OK((strm.bit_offset + 7) / 8);
CLEANUP:
	RETURN;
}

PUBLIC i64 decompress(const u8 *in, u64 len, u8 *out, u64 capacity) {
	BitStreamReader strm = {in, len};
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT];
	i64 res, ret = 0;
	bool fin = false;
INIT:
	if (len < sizeof(u64)) ERROR(EINVAL);
	u32 magic = TRY_READ(&strm, 32);
	if (magic != COMPRESS_MAGIC) ERROR(EPROTO);
	while (!fin) {
		fin = TRY_READ(&strm, 1);
		if (compress_read_lengths(&strm, lengths) < 0) ERROR();
		compress_calculate_codes(lengths, codes);
		res = compress_read_symbols(&strm, lengths, codes, out + ret,
					    capacity - ret);
		if (res < 0) OK(res);
		ret += res;
	}
	OK(ret);
CLEANUP:
	RETURN;
}

