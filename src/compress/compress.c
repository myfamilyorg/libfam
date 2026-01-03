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
#include <libfam/compress.h>
#include <libfam/compress_impl.h>
#include <libfam/format.h>
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

		len += (mask != 0xFFFFFFFF) * ctz_u32(~mask) +
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

STATIC void compress_find_matches(BitStreamWriter *strm, const u8 *in, u32 len,
				  u16 match_array[MAX_COMPRESS_LEN + 2],
				  u32 frequencies[SYMBOL_COUNT]) {
	u32 i = 0, max, out_itt = 0;
	LzHash hash = {0};
	max = len >= 32 + MAX_MATCH_LEN ? len - (32 + MAX_MATCH_LEN) : 0;

	// Add space for the length of extrabits.
	bitstream_writer_push(strm, 0, 32);
	bitstream_writer_flush(strm);

	while (i < max) {
		MatchInfo mi = lz_hash_get(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			u8 mc = get_match_code(mi.len, mi.dist);
			u8 len_extra = length_extra_bits_value(mc, mi.len);
			u16 dist_extra = distance_extra_bits_value(mc, mi.dist);
			u8 len_extra_bits_count = length_extra_bits(mc);
			u8 dist_extra_bits_count = distance_extra_bits(mc);
			u8 extra_sum =
			    len_extra_bits_count + dist_extra_bits_count;
			u64 combined_extra =
			    ((u32)dist_extra << len_extra_bits_count) |
			    len_extra;

			if (__builtin_expect(
				strm->bits_in_buffer + extra_sum > 64, 0)) {
				u64 bit_offset = strm->bit_offset & 0x7;
				u64 byte_pos = strm->bit_offset >> 3;
				__builtin_prefetch(strm->data + byte_pos, 1, 3);
				strm->bit_offset += strm->bits_in_buffer;

				u64 bits_to_write = 8 - bit_offset;
				bits_to_write =
				    min(bits_to_write, strm->bits_in_buffer);
				u8 new_bits =
				    (u8)(strm->buffer &
					 bitstream_masks[bits_to_write]);
				new_bits <<= bit_offset;
				u8 mask =
				    bitstream_partial_masks[bit_offset]
							   [bits_to_write];
				u8 current_byte = strm->data[byte_pos];
				strm->data[byte_pos] =
				    (current_byte & mask) | new_bits;
				strm->buffer >>= bits_to_write;
				strm->bits_in_buffer -= bits_to_write;
				byte_pos++;

				u64 bits_mask =
				    bitstream_masks[strm->bits_in_buffer];
				u64 *data64 = (u64 *)(strm->data + byte_pos);
				u64 existing = *data64;
				*data64 = (existing & ~bits_mask) |
					  (strm->buffer & bits_mask);
				strm->buffer = strm->bits_in_buffer = 0;
			}
			strm->buffer |= combined_extra << strm->bits_in_buffer;
			strm->bits_in_buffer += extra_sum;

			u16 match_symbol = mc + MATCH_OFFSET;
			frequencies[match_symbol]++;
			match_array[out_itt] = match_symbol;
			out_itt += 1;

			lz_hash_set(&hash, in, i + 1);
			lz_hash_set(&hash, in, i + 2);
			lz_hash_set(&hash, in, i + 3);
			i += mi.len;
		} else {
			frequencies[in[i]]++;
			match_array[out_itt] = in[i];
			i++;
			out_itt += 1;
		}
	}
	while (i < len) {
		frequencies[in[i]]++;
		match_array[out_itt] = in[i];
		out_itt += 1;
		i++;
	}

	bitstream_writer_flush(strm);

	u32 offset = strm->bit_offset;
	fastmemcpy(strm->data, &offset, sizeof(u32));

	match_array[out_itt++] = SYMBOL_TERM;
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
				     CodeLength *code_lengths) {
	if (!node) return;
	if (!node->left && !node->right)
		code_lengths[node->symbol].length = length;
	compress_compute_lengths(node->left, length + 1, code_lengths);
	compress_compute_lengths(node->right, length + 1, code_lengths);
}

STATIC void compress_build_tree(const u32 *frequencies,
				CodeLength *code_lengths, u16 count,
				HuffmanMinHeap *heap, HuffmanNode *nodes) {
	i32 i;
	u16 node_counter = 0;

	heap->size = 0;

	for (i = 0; i < count; i++) {
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

STATIC void compress_limit_lengths(const u32 *frequencies,
				   CodeLength *code_lengths, u16 count,
				   u8 max_length) {
	i32 i;
	u32 excess = 0;
	u32 needed = 0;

	for (i = 0; i < count; i++) {
		if (code_lengths[i].length > max_length) {
			excess += (code_lengths[i].length - max_length) *
				  frequencies[i];
			code_lengths[i].length = max_length;
			needed += frequencies[i];
		}
	}

	while (excess > 0 && needed > 0) {
		for (i = 0; i < count && excess > 0; i++) {
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
	for (i = 0; i < count; i++)
		if (code_lengths[i].length > 0)
			sum += 1ULL << (max_length - code_lengths[i].length);

	while (sum > (1ULL << max_length)) {
		u16 best = 0;
		u32 min_freq = U32_MAX;
		for (u16 i = 0; i < count; ++i) {
			if (code_lengths[i].length > 1 &&
			    code_lengths[i].length < max_length &&
			    frequencies[i] < min_freq) {
				min_freq = frequencies[i];
				best = i;
			}
		}
		if (min_freq == U32_MAX) break;

		u8 old_len = code_lengths[best].length;
		code_lengths[best].length++;

		sum -= (1ULL << (max_length - old_len));
		sum += (1ULL << (max_length - code_lengths[best].length));
	}
}

STATIC void compress_calculate_lengths(const u32 *frequencies,
				       CodeLength *code_lengths, u16 count,
				       u8 max_length) {
	HuffmanMinHeap heap;
	HuffmanNode nodes[count * 2 + 1];
	HuffmanNode *root;
	compress_build_tree(frequencies, code_lengths, count, &heap, nodes);
	if ((root = compress_extract_min(&heap)) != NULL) {
		compress_compute_lengths(root, 0, code_lengths);
		compress_limit_lengths(frequencies, code_lengths, count,
				       max_length);
	}
}

STATIC void compress_calculate_codes(CodeLength *code_lengths, u16 count) {
	u32 i, j, code = 0;
	u32 length_count[MAX_CODE_LENGTH + 1] = {0};
	u32 length_start[MAX_CODE_LENGTH + 1] = {0};
	u32 length_pos[MAX_CODE_LENGTH + 1] = {0};

	for (i = 0; i < count; i++) {
		length_count[code_lengths[i].length]++;
	}

	for (i = 1; i <= MAX_CODE_LENGTH; i++) {
		code <<= 1;
		length_start[i] = code;
		code += length_count[i];
	}

	for (i = 0; i < count; i++) {
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
					frequencies[REPEAT_VALUE_INDEX]++;
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
				frequencies[REPEAT_ZERO_LONG_INDEX]++;
			} else if (run >= 3) {
				run = run - 3;
				i += run + 2;
				frequencies[REPEAT_ZERO_SHORT_INDEX]++;
			} else
				frequencies[0]++;
			last_length = 0;
		}
	}
	compress_calculate_lengths(frequencies, book, MAX_BOOK_CODES,
				   MAX_BOOK_CODE_LENGTH);
	compress_calculate_codes(book, MAX_BOOK_CODES);

CLEANUP:
	RETURN;
}

STATIC i32 compress_write_lengths(BitStreamWriter *strm,
				  const CodeLength code_lengths[SYMBOL_COUNT],
				  const CodeLength book[MAX_BOOK_CODES]) {
	i32 i;
	u8 last_length = 0;
INIT:
	for (i = 0; i < MAX_BOOK_CODES; i++) WRITE(strm, book[i].length, 3);
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
					WRITE(strm,
					      book[REPEAT_VALUE_INDEX].code,
					      book[REPEAT_VALUE_INDEX].length);
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
				WRITE(strm, book[REPEAT_ZERO_LONG_INDEX].code,
				      book[REPEAT_ZERO_LONG_INDEX].length);
				WRITE(strm, run, 7);
				i += run + 10;
			} else if (run >= 3) {
				run = run - 3;
				WRITE(strm, book[REPEAT_ZERO_SHORT_INDEX].code,
				      book[REPEAT_ZERO_SHORT_INDEX].length);
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

STATIC i32 compress_write(BitStreamWriter *strm,
			  const CodeLength code_lengths[SYMBOL_COUNT],
			  const CodeLength book[MAX_BOOK_CODES],
			  const u16 match_array[MAX_COMPRESS_LEN + 2],
			  u8 *out) {
	u32 i = 0;
	WRITE(strm, 0, 8); /* Block type */
	compress_write_lengths(strm, code_lengths, book);
	i = 0;
	while (match_array[i] != SYMBOL_TERM) {
		u16 symbol = match_array[i];
		u16 code = code_lengths[symbol].code;
		u8 length = code_lengths[symbol].length;
		if (length + strm->bits_in_buffer > 64)
			bitstream_writer_flush(strm);
		bitstream_writer_push(strm, code, length);
		i++;
	}

	WRITE(strm, code_lengths[SYMBOL_TERM].code,
	      code_lengths[SYMBOL_TERM].length);
	WRITE(strm, 0, 64);
	bitstream_writer_flush(strm);
	return (strm->bit_offset + 7) / 8;
}

STATIC void compress_build_lookup_table(const CodeLength *code_lengths,
					u16 count, HuffmanLookup *lookup_table,
					u8 max_length) {
	i32 i, j;
	for (i = 0; i < count; i++) {
		if (code_lengths[i].length) {
			i32 index = code_lengths[i].code &
				    ((1U << code_lengths[i].length) - 1);
			i32 fill_depth =
			    1U << (max_length - code_lengths[i].length);
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
	HuffmanLookup lookup_table[(1U << MAX_BOOK_CODE_LENGTH)] = {0};
INIT:
	TRY_READ(strm, 8); /* Skip over block type */
	for (i = 0; i < MAX_BOOK_CODES; i++) {
		book_code_lengths[i].length = TRY_READ(strm, 3);
	}

	compress_calculate_codes(book_code_lengths, MAX_BOOK_CODES);
	compress_build_lookup_table(book_code_lengths, MAX_BOOK_CODES,
				    lookup_table, MAX_BOOK_CODE_LENGTH);

	i = 0;

	while (i < SYMBOL_COUNT) {
		if (strm->bits_in_buffer < 7)
			if (bitstream_reader_load(strm) < 0) ERROR(EOVERFLOW);
		u8 bits = bitstream_reader_read(strm, MAX_BOOK_CODE_LENGTH);
		HuffmanLookup entry = lookup_table[bits];
		u16 code = entry.symbol;
		bitstream_reader_clear(strm, entry.length);
		if (code < REPEAT_VALUE_INDEX) {
			code_lengths[i++].length = code;
			last_length = code;
		} else if (code == REPEAT_VALUE_INDEX) {
			if (i == 0 || last_length == 0) ERROR(EPROTO);
			u8 repeat = TRY_READ(strm, 2) + 3;
			if (i + repeat > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < repeat; j++) {
				code_lengths[i++].length = last_length;
			}
		} else if (code == REPEAT_ZERO_LONG_INDEX) {
			u8 zeros = TRY_READ(strm, 7) + 11;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		} else if (code == REPEAT_ZERO_SHORT_INDEX) {
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

	if (strm->bits_in_buffer < 32) bitstream_reader_load(strm);

	len_extra = bitstream_reader_read(strm, len_extra_bits);
	bitstream_reader_clear(strm, len_extra_bits);

	dist_extra = bitstream_reader_read(strm, dist_extra_bits);
	bitstream_reader_clear(strm, dist_extra_bits);

	actual_length = base_length + len_extra;
	actual_distance = base_dist + dist_extra;
	if (__builtin_expect(
		actual_length + 32 + *itt > capacity || actual_distance > *itt,
		0)) {
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
				 u8 *out, u32 capacity) {
	BitStreamReader extras = {strm->data, strm->max_size, 8 * sizeof(u32)};
	HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
	u32 itt = 0;
	u16 symbol = 0;
	u8 load_threshold = MAX_CODE_LENGTH + 7 + 15;

	compress_build_lookup_table(code_lengths, SYMBOL_COUNT, lookup_table,
				    MAX_CODE_LENGTH);

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
		} else if (compress_proc_match(&extras, out, capacity, &entry,
					       &itt) < 0)
			return -1;
	}
	return itt;
}

PUBLIC u64 compress_bound(u64 source_len) { return source_len + 3; }

PUBLIC i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	BitStreamWriter strm = {out};
	u32 frequencies[SYMBOL_COUNT] = {0};
	u32 book_frequencies[MAX_BOOK_CODES] = {0};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	CodeLength book[MAX_BOOK_CODES] = {0};
	u16 match_array[MAX_COMPRESS_LEN + 2] = {0};

	if (in == NULL || out == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (capacity < compress_bound(len) || len > MAX_COMPRESS_LEN) {
		errno = EINVAL;
		return -1;
	}

	compress_find_matches(&strm, in, len, match_array, frequencies);
	compress_calculate_lengths(frequencies, code_lengths, SYMBOL_COUNT,
				   MAX_CODE_LENGTH);
	compress_calculate_codes(code_lengths, SYMBOL_COUNT);
	compress_build_code_book(code_lengths, book, book_frequencies);
	i32 res = compress_write(&strm, code_lengths, book, match_array, out);
	return res;
}

PUBLIC i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u32 bit_offset;
	BitStreamReader strm = {in, len};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	if (len <= sizeof(u32)) {
		errno = EINVAL;
		return -1;
	}
	fastmemcpy(&bit_offset, in, sizeof(u32));
	strm.bit_offset = bit_offset;
	compress_read_lengths(&strm, code_lengths);
	compress_calculate_codes(code_lengths, SYMBOL_COUNT);
	return compress_read_symbols(&strm, code_lengths, out, capacity);
}

