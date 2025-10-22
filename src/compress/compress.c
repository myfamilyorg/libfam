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
#include <libfam/bitstream.h>
#include <libfam/builtin.h>
#include <libfam/compress.h>
#include <libfam/compress_impl.h>
#include <libfam/format.h>
#include <libfam/memory.h>
#include <libfam/utils.h>

STATIC MatchInfo lz_hash_get(LzHash *restrict hash, const u8 *restrict text,
			     u32 cpos) {
	u16 pos, dist, len = 0;
	u32 mpos, key = *(u32 *)(text + cpos);
	pos = hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT];
	hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = cpos;
	dist = (u16)cpos - pos;
	if (!dist) return (MatchInfo){.len = 0, .dist = 0};
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

		len += (mask != 0xFFFFFFFF) * __builtin_ctz(~mask) +
		       (mask == 0xFFFFFFFF) * 32;
	} while (mask == 0xFFFFFFFF && len < MAX_MATCH_LEN);
#else
	while (len < MAX_MATCH_LEN && text[mpos + len] == text[cpos + len])
		len++;
#endif /* !__AVX2__ */

	return (MatchInfo){.len = len, .dist = dist};
}

STATIC void lz_hash_set(LzHash *restrict hash, const u8 *restrict text,
			u32 cpos) {
	u32 key = *(u32 *)(text + cpos);
	hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = (u16)cpos;
}

void compress_find_matches(const u8 *in, u32 len,
			   u8 match_array[restrict 2 * MAX_COMPRESS_LEN + 1],
			   u32 frequencies[restrict SYMBOL_COUNT]) {
	u32 i = 0, max, out_itt = 0;
	LzHash hash = {0};
	max = len >= 32 + MAX_MATCH_LEN ? len - (32 + MAX_MATCH_LEN) : 0;

	while (i < max) {
		MatchInfo mi = lz_hash_get(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			u8 mc = get_match_code(mi.len, mi.dist);
			u8 len_extra = length_extra_bits_value(mc, mi.len);
			u16 dist_extra = distance_extra_bits_value(mc, mi.dist);
			u8 len_extra_bits_count = length_extra_bits(mc);
			u32 combined_extra =
			    ((u32)dist_extra << len_extra_bits_count) |
			    len_extra;
			u16 match_symbol = mc + MATCH_OFFSET;
			frequencies[match_symbol]++;
			((u32 *)(match_array + out_itt))[0] =
			    (combined_extra << 8) | (mc + 2);
			out_itt += 4;

			lz_hash_set(&hash, in, i + 1);
			lz_hash_set(&hash, in, i + 2);
			lz_hash_set(&hash, in, i + 3);
			i += mi.len;
		} else {
			frequencies[in[i]]++;
			match_array[out_itt + 1] = in[i];
			i++;
			out_itt += 2;
		}
	}
	while (i < len) {
		frequencies[in[i]]++;
		match_array[out_itt + 1] = in[i];
		out_itt += 2;
		i++;
	}
	match_array[out_itt++] = 1;
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
				     CodeLength code_lengths[SYMBOL_COUNT]) {
	if (!node) return;
	if (!node->left && !node->right)
		code_lengths[node->symbol].length = length;
	compress_compute_lengths(node->left, length + 1, code_lengths);
	compress_compute_lengths(node->right, length + 1, code_lengths);
}

STATIC void compress_build_tree(const u32 frequencies[SYMBOL_COUNT],
				CodeLength code_lengths[SYMBOL_COUNT],
				HuffmanMinHeap *heap,
				HuffmanNode nodes[SYMBOL_COUNT * 2 + 1]) {
	i32 i;
	u16 node_counter = 0;

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
		code_lengths[node->symbol].length = 1;
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
				   CodeLength code_lengths[SYMBOL_COUNT],
				   u8 max_length) {
	i32 i;
	u32 excess = 0;
	u32 needed = 0;

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length > max_length) {
			excess += (code_lengths[i].length - max_length) *
				  frequencies[i];
			code_lengths[i].length = max_length;
			needed += frequencies[i];
		}
	}

	while (excess > 0 && needed > 0) {
		for (i = 0; i < SYMBOL_COUNT && excess > 0; i++) {
			if (code_lengths[i].length > 0 &&
			    code_lengths[i].length < max_length &&
			    frequencies[i] > 0) {
				u32 delta = (excess < frequencies[i])
						? excess
						: frequencies[i];
				code_lengths[i].length++;
				excess -= delta;
				needed -= delta;
			}
		}
	}

	u64 sum = 0;
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length > 0) {
			sum += 1ULL << (max_length - code_lengths[i].length);
		}
	}

	while (sum > (1ULL << max_length)) {
		for (i = SYMBOL_COUNT - 1; i >= 0; i--)
			if (code_lengths[i].length > 1 &&
			    code_lengths[i].length < max_length) {
				code_lengths[i].length++;
				break;
			}
		sum = 0;
		for (i = 0; i < SYMBOL_COUNT; i++) {
			if (code_lengths[i].length > 0) {
				sum += 1ULL
				       << (max_length - code_lengths[i].length);
			}
		}
	}
}

STATIC void compress_calculate_lengths(const u32 frequencies[SYMBOL_COUNT],
				       CodeLength code_lengths[SYMBOL_COUNT],
				       u8 max_length) {
	HuffmanMinHeap heap;
	HuffmanNode nodes[SYMBOL_COUNT * 2 + 1];
	HuffmanNode *root;
	compress_build_tree(frequencies, code_lengths, &heap, nodes);
	if ((root = compress_extract_min(&heap)) != NULL) {
		compress_compute_lengths(root, 0, code_lengths);
		compress_limit_lengths(frequencies, code_lengths, max_length);
	}
}

STATIC void compress_calculate_codes(CodeLength code_lengths[SYMBOL_COUNT]) {
	u32 i, j, code = 0;
	u32 length_count[MAX_CODE_LENGTH + 1] = {0};
	u32 length_start[MAX_CODE_LENGTH + 1] = {0};
	u32 length_pos[MAX_CODE_LENGTH + 1] = {0};

	for (i = 0; i < SYMBOL_COUNT; i++)
		length_count[code_lengths[i].length]++;

	for (i = 1; i <= MAX_CODE_LENGTH; i++) {
		code <<= 1;
		length_start[i] = code;
		code += length_count[i];
	}

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length != 0) {
			u8 len = code_lengths[i].length;
			code_lengths[i].code =
			    length_start[len] + length_pos[len]++;
			code_lengths[i].code &= (1U << len) - 1;

			u16 reversed = 0;
			u16 temp = code_lengths[i].code;
			for (j = 0; j < len; j++) {
				reversed = (reversed << 1) | (temp & 1);
				temp >>= 1;
			}
			code_lengths[i].code = reversed;
		}
	}
}

STATIC i32 compress_build_code_book(const CodeLength code_lengths[SYMBOL_COUNT],
				    CodeLength book[MAX_BOOK_CODES],
				    u32 frequencies[MAX_BOOK_CODES]) {
	u8 last_length = 0;
INIT:
	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			if (last_length == code_lengths[i].length && i > 0) {
				u16 repeat = 1;
				while (i + repeat < SYMBOL_COUNT &&
				       code_lengths[i + repeat].length ==
					   last_length &&
				       repeat < 6) {
					repeat++;
				}
				if (repeat >= 3) {
					frequencies[10]++;
					i += repeat - 1;
					last_length = 0;
					continue;
				}
			}
			last_length = code_lengths[i].length;
			frequencies[code_lengths[i].length]++;
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT &&
			       code_lengths[run].length == 0)
				run++;
			run -= i;

			if (run >= 11) {
				run = run > 138 ? 127 : run - 11;
				i += run + 10;
				frequencies[11]++;
			} else if (run >= 3) {
				run = run - 3;
				i += run + 2;
				frequencies[12]++;
			} else
				frequencies[0]++;
			last_length = 0;
		}
	}

	compress_calculate_lengths(frequencies, book, 7);
	compress_calculate_codes(book);

CLEANUP:
	RETURN;
}

STATIC i32 compress_write_lengths(BitStreamWriter *strm,
				  const CodeLength code_lengths[SYMBOL_COUNT],
				  const CodeLength book[MAX_BOOK_CODES]) {
	i32 i;
	u8 last_length = 0;
INIT:
	for (i = 0; i < 13; i++) WRITE(strm, book[i].length, 3);
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			if (last_length == code_lengths[i].length) {
				u16 repeat = 1;
				while (i + repeat < SYMBOL_COUNT &&
				       code_lengths[i + repeat].length ==
					   last_length &&
				       repeat < 6) {
					repeat++;
				}
				if (repeat >= 3) {
					WRITE(strm, book[10].code,
					      book[10].length);
					WRITE(strm, repeat - 3, 2);
					i += repeat - 1;
					last_length = 0;
					continue;
				}
			}

			WRITE(strm, book[code_lengths[i].length].code,
			      book[code_lengths[i].length].length);
			last_length = code_lengths[i].length;
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT &&
			       code_lengths[run].length == 0)
				run++;
			run -= i;
			if (run >= 11) {
				run = run > 138 ? 127 : run - 11;
				WRITE(strm, book[11].code, book[11].length);
				WRITE(strm, run, 7);
				i += run + 10;
			} else if (run >= 3) {
				run = run - 3;
				WRITE(strm, book[12].code, book[12].length);
				WRITE(strm, run, 3);
				i += run + 2;
			} else
				WRITE(strm, book[0].code, book[0].length);

			last_length = 0;
		}
	}

CLEANUP:
	RETURN;
}

STATIC i32 compress_write(const CodeLength code_lengths[SYMBOL_COUNT],
			  const CodeLength book[SYMBOL_COUNT],
			  const u8 match_array[2 * MAX_COMPRESS_LEN + 1],
			  u8 *out) {
	u32 i = 0;
	BitStreamWriter strm = {out};
	WRITE(&strm, 0, 8); /* Block type */
	compress_write_lengths(&strm, code_lengths, book);
	i = 0;
	while (true) {
		if (strm.bits_in_buffer >= 32) {
			bitstream_writer_flush(&strm);
			PROC_MATCH_ARRAY();
		}
		PROC_MATCH_ARRAY();
	}

	WRITE(&strm, code_lengths[SYMBOL_TERM].code,
	      code_lengths[SYMBOL_TERM].length);
	WRITE(&strm, 0, 64);
	bitstream_writer_flush(&strm);
	return (strm.bit_offset + 7) / 8;
}

STATIC void compress_build_lookup_table(
    const CodeLength code_lengths[SYMBOL_COUNT],
    HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)]) {
	i32 i, j;
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			i32 index = code_lengths[i].code &
				    ((1U << code_lengths[i].length) - 1);
			i32 fill_depth =
			    1U << (MAX_CODE_LENGTH - code_lengths[i].length);
			for (j = 0; j < fill_depth; j++) {
				lookup_table[index |
					     (j << code_lengths[i].length)]
				    .length = code_lengths[i].length;
				lookup_table[index |
					     (j << code_lengths[i].length)]
				    .symbol = i;
				if (i >= MATCH_OFFSET) {
					u8 mc = i - MATCH_OFFSET;
					lookup_table[index |
						     (j << code_lengths[i]
							       .length)]
					    .dist_extra_bits =
					    distance_extra_bits(mc);
					lookup_table[index |
						     (j << code_lengths[i]
							       .length)]
					    .len_extra_bits =
					    length_extra_bits(mc);
					lookup_table[index |
						     (j << code_lengths[i]
							       .length)]
					    .base_dist = distance_base(mc);
					lookup_table[index |
						     (j << code_lengths[i]
							       .length)]
					    .base_len = length_base(mc) + 4;
				}
			}
		}
	}
}

STATIC i32 compress_read_lengths(BitStreamReader *strm,
				 CodeLength code_lengths[SYMBOL_COUNT]) {
	i32 i = 0, j;
	u16 last_length = 0;
	CodeLength book_code_lengths[SYMBOL_COUNT] = {0};
	HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
INIT:
	TRY_READ(strm, 8); /* Skip over block type */
	for (i = 0; i < 13; i++)
		book_code_lengths[i].length = TRY_READ(strm, 3);

	compress_calculate_codes(book_code_lengths);
	compress_build_lookup_table(book_code_lengths, lookup_table);

	i = 0;

	while (i < SYMBOL_COUNT) {
		if (strm->bits_in_buffer < 7)
			if (bitstream_reader_load(strm) < 0) ERROR(EOVERFLOW);
		u8 bits = bitstream_reader_read(strm, 7);
		HuffmanLookup entry = lookup_table[bits];
		u16 code = entry.symbol;
		bitstream_reader_clear(strm, entry.length);
		if (code < 10) {
			code_lengths[i++].length = code;
			last_length = code;
		} else if (code == 10) {
			if (i == 0 || last_length == 0) ERROR(EPROTO);
			u8 repeat = TRY_READ(strm, 2) + 3;
			if (i + repeat > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < repeat; j++) {
				code_lengths[i++].length = last_length;
			}
		} else if (code == 11) {
			u8 zeros = TRY_READ(strm, 7) + 11;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		} else if (code == 12) {
			u8 zeros = TRY_READ(strm, 3) + 3;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		} else if (code == 12) {
			u8 zeros = TRY_READ(strm, 3) + 3;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		}
	}

CLEANUP:
	RETURN;
}

#ifdef __AVX2__
INLINE STATIC void copy_with_avx2(u8 *out_dest, const u8 *out_src,
				  u64 actual_length) {
	if (out_src + 32 <= out_dest) {
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
#endif /* __AVX2__ */

INLINE static i32 compress_proc_match(BitStreamReader *strm, u8 *out,
				      u32 capacity, HuffmanLookup *entry,
				      u32 *itt) {
	u8 len_extra;
	u16 base_length, actual_length, base_dist, dist_extra, actual_distance;
	u8 len_extra_bits = entry->len_extra_bits;
	u8 dist_extra_bits = entry->dist_extra_bits;
	base_length = entry->base_len;
	base_dist = entry->base_dist;

	len_extra = bitstream_reader_read(strm, len_extra_bits);
	bitstream_reader_clear(strm, len_extra_bits);
	dist_extra = bitstream_reader_read(strm, dist_extra_bits);
	bitstream_reader_clear(strm, dist_extra_bits);

	actual_length = base_length + len_extra;
	actual_distance = base_dist + dist_extra;
	if (__builtin_expect(actual_length + 32 + *itt > capacity, 0)) {
		errno = EOVERFLOW;
		return -1;
	}

	u8 *out_dest = out + *itt;
	u8 *out_src = out + *itt - actual_distance;
	*itt += actual_length;

#ifdef __AVX2__
	copy_with_avx2(out_dest, out_src, actual_length);
#else
	while (actual_length--) *out_dest++ = *out_src++;
#endif /* !__AVX2__ */
	return 0;
}

STATIC i32 compress_read_symbols(BitStreamReader *strm,
				 const CodeLength code_lengths[SYMBOL_COUNT],
				 u8 *out, u32 capacity, u64 *bytes_consumed) {
	HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
	u32 itt = 0;
	u16 symbol = 0;
	u8 load_threshold = MAX_CODE_LENGTH + 7 + 15;

	compress_build_lookup_table(code_lengths, lookup_table);

	while (true) {
		if (__builtin_expect(strm->bits_in_buffer < load_threshold, 0))
			bitstream_reader_load(strm);

		u16 bits = bitstream_reader_read(strm, MAX_CODE_LENGTH);
		HuffmanLookup entry = lookup_table[bits];
		u8 length = entry.length;
		symbol = entry.symbol;

		bitstream_reader_clear(strm, length);
		if (symbol < SYMBOL_TERM) {
			if (__builtin_expect(itt >= capacity, 0)) {
				errno = EOVERFLOW;
				return -1;
			}
			out[itt++] = symbol;
		} else if (symbol == SYMBOL_TERM) {
			break;
		} else if (compress_proc_match(strm, out, capacity, &entry,
					       &itt) < 0)
			return -1;
	}
	*bytes_consumed =
	    (strm->bit_offset - strm->bits_in_buffer + 64 + 7) / 8;
	return itt;
}

STATIC i32
compress_calculate_block_type(const u32 frequencies[SYMBOL_COUNT],
			      const u32 book_frequencies[MAX_BOOK_CODES],
			      const CodeLength code_lengths[SYMBOL_COUNT],
			      const CodeLength book[MAX_BOOK_CODES], u32 len) {
	u32 sum = 0;
	for (u32 i = 0; i < SYMBOL_COUNT; i++) {
		sum += frequencies[i] * code_lengths[i].length;
		if (i >= MATCH_OFFSET)
			sum += frequencies[i] *
			       (distance_extra_bits(i - MATCH_OFFSET) +
				length_extra_bits(i - MATCH_OFFSET));
	}
	sum += 13 * 3;
	for (u32 i = 0; i < MAX_BOOK_CODES; i++) {
		sum += book_frequencies[i] * book[i].length;
		if (i == 10) sum += book_frequencies[i] * 2;
		if (i == 11) sum += book_frequencies[i] * 7;
		if (i == 12) sum += book_frequencies[i] * 3;
	}
	sum += 7 + 64;
	sum >>= 3;
	return sum > len;
}

STATIC i32 compress_write_raw(const u8 *in, u32 len, u8 *out) {
	u32 value;
	if (!len) {
		out[0] = 0x80;
		return 3;
	}
	value = (len << 1) | 0x00000080;
	memcpy(out, &value, 3);
	memcpy(out + 3, in, len);
	return len + 3;
}

STATIC i32 compress_read_raw(const u8 *in, u32 len, u8 *out, u32 capacity,
			     u64 *bytes_consumed) {
	u32 block_len;
	u8 bytes[4];
INIT:
	if (len < 3) ERROR(EOVERFLOW);
	if (len == 3) {
		if (in[0] != 0x80 || in[1] != 0 || in[2] != 0) ERROR(EOVERFLOW);
		return 0;
	}
	bytes[0] = in[0] & ~0x80;
	bytes[1] = in[1];
	bytes[2] = in[2];
	bytes[3] = 0;
	block_len = (*(u32 *)bytes) >> 1;
	if (block_len > capacity) ERROR(EOVERFLOW);
	if (len < block_len + 3) ERROR(EOVERFLOW);

	memcpy(out, in + 3, block_len);
	*bytes_consumed = block_len + 3;
	OK(block_len);
CLEANUP:
	RETURN;
}

PUBLIC i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u32 frequencies[SYMBOL_COUNT] = {0};
	u32 book_frequencies[MAX_BOOK_CODES] = {0};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	CodeLength book[MAX_BOOK_CODES] = {0};
	u8 match_array[2 * MAX_COMPRESS_LEN + 1] = {0};

	if (capacity < compress_bound(len) || len > MAX_COMPRESS_LEN) {
		errno = EINVAL;
		return -1;
	}

	compress_find_matches(in, len, match_array, frequencies);
	compress_calculate_lengths(frequencies, code_lengths, MAX_CODE_LENGTH);
	compress_calculate_codes(code_lengths);
	compress_build_code_book(code_lengths, book, book_frequencies);
	i32 bt = compress_calculate_block_type(frequencies, book_frequencies,
					       code_lengths, book, len);
	if (bt != 0)
		return compress_write_raw(in, len, out);
	else
		return compress_write(code_lengths, book, match_array, out);
}

PUBLIC i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity,
			    u64 *bytes_consumed) {
	BitStreamReader strm = {in, len};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	if (len == 0) {
		errno = EINVAL;
		return -1;
	}
	if (in[0]) {
		return compress_read_raw(in, len, out, capacity,
					 bytes_consumed);
	} else {
		compress_read_lengths(&strm, code_lengths);
		compress_calculate_codes(code_lengths);
		return compress_read_symbols(&strm, code_lengths, out, capacity,
					     bytes_consumed);
	}
}

PUBLIC u64 compress_bound(u64 len) { return len + 3; }

