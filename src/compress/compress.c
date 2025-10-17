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
#include <libfam/compress_impl.h>
#include <libfam/format.h>

STATIC MatchInfo lz_hash_get(const LzHash *hash, const u8 *text, u32 cpos) {
	u16 pos, dist, len = 0;
	u32 mpos, key = *(u32 *)(text + cpos);
	pos = hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT];
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

STATIC void lz_hash_set(LzHash *hash, const u8 *text, u32 cpos) {
	u32 key = *(u32 *)(text + cpos);
	hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = (u16)cpos;
}

STATIC void compress_find_matches(const u8 *in, u32 len,
				  u8 match_array[4 * MAX_COMPRESS_LEN + 33],
				  u32 frequencies[SYMBOL_COUNT],
				  u32 *term_index) {
	u32 i = 0, max, out_itt = 0;
	LzHash hash = {0};
	max = len >= MAX_MATCH_LEN ? len - MAX_MATCH_LEN : 0;

	while (i < max) {
		MatchInfo mi = lz_hash_get(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			u8 mc = get_match_code(mi.len, mi.dist);
			frequencies[mc + MATCH_OFFSET]++;
			u8 len_extra = length_extra_bits_value(mc, mi.len);
			u16 dist_extra = distance_extra_bits_value(mc, mi.dist);
			u8 len_extra_bits_count = length_extra_bits(mc);
			u32 combined_extra =
			    ((u32)dist_extra << len_extra_bits_count) |
			    len_extra;

			match_array[out_itt] = mc + 2;
			((u32 *)(match_array + out_itt + 1))[0] =
			    combined_extra;
			out_itt += 4;

			lz_hash_set(&hash, in, i);
			lz_hash_set(&hash, in, i + 1);
			lz_hash_set(&hash, in, i + 2);
			lz_hash_set(&hash, in, i + 3);
			i += mi.len;
		} else {
			lz_hash_set(&hash, in, i);
			u8 ch = in[i++];
			frequencies[ch]++;
			((u16 *)match_array)[out_itt >> 1] = ch << 8;
			out_itt += 4;
		}
	}
	while (i < len) {
		frequencies[in[i]]++;
		((u16 *)match_array)[(out_itt) >> 1] = in[i] << 8;
		out_itt += 4;
		i++;
	}
	*term_index = out_itt;
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
				   CodeLength code_lengths[SYMBOL_COUNT]) {
	i32 i;
	u32 excess = 0;
	u32 needed = 0;

	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length > MAX_CODE_LENGTH) {
			excess += (code_lengths[i].length - MAX_CODE_LENGTH) *
				  frequencies[i];
			code_lengths[i].length = MAX_CODE_LENGTH;
			needed += frequencies[i];
		}
	}

	while (excess > 0 && needed > 0) {
		for (i = 0; i < SYMBOL_COUNT && excess > 0; i++) {
			if (code_lengths[i].length > 0 &&
			    code_lengths[i].length < MAX_CODE_LENGTH &&
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
			sum += 1ULL
			       << (MAX_CODE_LENGTH - code_lengths[i].length);
		}
	}

	while (sum > (1ULL << MAX_CODE_LENGTH)) {
		for (i = SYMBOL_COUNT - 1; i >= 0; i--)
			if (code_lengths[i].length > 1 &&
			    code_lengths[i].length < MAX_CODE_LENGTH) {
				code_lengths[i].length++;
				break;
			}
		sum = 0;
		for (i = 0; i < SYMBOL_COUNT; i++) {
			if (code_lengths[i].length > 0) {
				sum += 1ULL << (MAX_CODE_LENGTH -
						code_lengths[i].length);
			}
		}
	}
}

STATIC void compress_calculate_lengths(const u32 frequencies[SYMBOL_COUNT],
				       CodeLength code_lengths[SYMBOL_COUNT]) {
	HuffmanMinHeap heap;
	HuffmanNode nodes[SYMBOL_COUNT * 2 + 1];
	HuffmanNode *root;
	compress_build_tree(frequencies, code_lengths, &heap, nodes);
	if ((root = compress_extract_min(&heap)) != NULL) {
		compress_compute_lengths(root, 0, code_lengths);
		compress_limit_lengths(frequencies, code_lengths);
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

STATIC i32 compress_write_lengths(BitStreamWriter *strm,
				  const CodeLength code_lengths[SYMBOL_COUNT]) {
	i32 i;
INIT:
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			WRITE(strm, code_lengths[i].length, 4);
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT &&
			       code_lengths[run].length == 0)
				run++;
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

#ifdef __AVX2__
STATIC i32 compress_write(CodeLength code_lengths[SYMBOL_COUNT],
			  const u8 match_array[4 * MAX_COMPRESS_LEN + 33],
			  u8 *out, u32 term_index) {
	u32 i = 0;
	BitStreamWriter strm = {out};
	compress_write_lengths(&strm, code_lengths);
	bitstream_writer_flush(&strm);

	__m256i one = _mm256_set1_epi32(1);
	__m256i two = _mm256_set1_epi32(2);
	__m256i match_offset_vec = _mm256_set1_epi32(MATCH_OFFSET);
	u32 max = term_index >= 32 ? term_index - 32 : 0;

	while (i < max) {
		__m256i mreg = _mm256_load_si256((__m256i *)(match_array + i));
		__m256i types =
		    _mm256_and_si256(mreg, _mm256_set1_epi32(0x000000FF));
		__m256i sym =
		    _mm256_and_si256(mreg, _mm256_set1_epi32(0x0000FF00));
		sym = _mm256_srli_epi32(sym, 8);
		__m256i mask = _mm256_cmpgt_epi32(types, one);
		__m256i mcs = _mm256_sub_epi32(types, two);
		__m256i true_val = _mm256_add_epi32(mcs, match_offset_vec);
		sym = _mm256_blendv_epi8(sym, true_val, mask);
		__m256i cl_vec =
		    _mm256_i32gather_epi32((const i32 *)code_lengths, sym, 4);
		__m256i code_vec =
		    _mm256_and_si256(cl_vec, _mm256_set1_epi32(0xFFFF));
		__m256i length_vec = _mm256_srli_epi32(cl_vec, 16);

		__m256i combined_extra_vec =
		    _mm256_and_si256(mreg, _mm256_set1_epi32(0xFFFFFF00));
		combined_extra_vec = _mm256_srli_epi32(combined_extra_vec, 8);

		__m256i len_extra_vec = _mm256_srli_epi32(mcs, 4);
		__m256i dist_extra_vec =
		    _mm256_and_si256(mcs, _mm256_set1_epi32(0xF));
		__m256i total_extra_vec =
		    _mm256_add_epi8(len_extra_vec, dist_extra_vec);

		__m256i bits_vec = _mm256_or_si256(
		    code_vec,
		    _mm256_sllv_epi32(combined_extra_vec, length_vec));
		__m256i bits_length_vec =
		    _mm256_add_epi8(total_extra_vec, length_vec);

		__m256i literal_mask =
		    _mm256_cmpeq_epi32(mask, _mm256_set1_epi32(0));
		__m256i final_bits_vec =
		    _mm256_blendv_epi8(bits_vec, code_vec, literal_mask);
		__m256i final_bits_length_vec = _mm256_blendv_epi8(
		    bits_length_vec, length_vec, literal_mask);
		const u32 *codes = (const u32 *)&final_bits_vec;
		const u32 *lengths = (const u32 *)&final_bits_length_vec;
		u8 j;
		for (j = 0; j < 7; j++) {
			if (strm.bits_in_buffer + lengths[j] > 64) {
				bitstream_writer_flush(&strm);
				bitstream_writer_push(&strm, codes[j],
						      lengths[j]);
				j++;
			}
			bitstream_writer_push(&strm, codes[j], lengths[j]);
		}
		if (j < 8) {
			if (strm.bits_in_buffer + lengths[j] > 64)
				bitstream_writer_flush(&strm);
			bitstream_writer_push(&strm, codes[j], lengths[j]);
		}
		i += 32;
	}

	while (i < term_index && match_array[i] != 1) {
		bitstream_writer_flush(&strm);
		if (match_array[i] == 0) {
			u8 symbol = match_array[i + 1];
			CodeLength cl = code_lengths[symbol];
			u16 code = cl.code;
			u8 length = cl.length;
			bitstream_writer_push(&strm, code, length);
			i += 4;
		} else {
			u8 match_code = match_array[i] - 2;
			u16 symbol = (u16)match_code + MATCH_OFFSET;
			CodeLength cl = code_lengths[symbol];
			u16 code = cl.code;
			u8 length = cl.length;
			u32 combined_extra =
			    ((u32 *)(match_array + i + 1))[0] & 0xFFFFFF;
			u8 len_extra_bits = length_extra_bits(match_code);
			u8 dist_extra_bits = distance_extra_bits(match_code);
			u8 total_extra_bits = len_extra_bits + dist_extra_bits;

			bitstream_writer_push(&strm, code, length);
			bitstream_writer_push(&strm, combined_extra,
					      total_extra_bits);
			i += 4;
		}
	}

	WRITE(&strm, code_lengths[SYMBOL_TERM].code,
	      code_lengths[SYMBOL_TERM].length);
	WRITE(&strm, 0, 64);
	bitstream_writer_flush(&strm);
	return (strm.bit_offset + 7) / 8;
}
#else
STATIC i32 compress_write(CodeLength code_lengths[SYMBOL_COUNT],
			  const u8 match_array[4 * MAX_COMPRESS_LEN + 33],
			  u8 *out, u64 term_index) {
	u32 i = 0;
	BitStreamWriter strm = {out};
	compress_write_lengths(&strm, code_lengths);

	i = 0;
	while (match_array[i] != 1) {
		if (strm.bits_in_buffer >= 32) bitstream_writer_flush(&strm);
		if (match_array[i] == 0) {
			u8 symbol = match_array[i + 1];
			CodeLength cl = code_lengths[symbol];
			u16 code = cl.code;
			u8 length = cl.length;
			bitstream_writer_push(&strm, code, length);
		} else {
			u8 match_code = match_array[i] - 2;
			u16 symbol = (u16)match_code + MATCH_OFFSET;
			CodeLength cl = code_lengths[symbol];
			u16 code = cl.code;
			u8 length = cl.length;
			u32 combined_extra =
			    ((u32 *)(match_array + i + 1))[0] & 0xFFFFFF;
			u8 len_extra_bits = length_extra_bits(match_code);
			u8 dist_extra_bits = distance_extra_bits(match_code);
			u8 total_extra_bits = len_extra_bits + dist_extra_bits;

			bitstream_writer_push(&strm, code, length);
			bitstream_writer_push(&strm, combined_extra,
					      total_extra_bits);
		}
		i += 4;
	}

	WRITE(&strm, code_lengths[SYMBOL_TERM].code,
	      code_lengths[SYMBOL_TERM].length);
	WRITE(&strm, 0, 64);
	bitstream_writer_flush(&strm);
	return (strm.bit_offset + 7) / 8;
}
#endif /* !__AVX2__ */

STATIC i32 compress_read_lengths(BitStreamReader *strm,
				 CodeLength code_lengths[SYMBOL_COUNT]) {
	i32 i = 0, j;
INIT:
	while (i < SYMBOL_COUNT) {
		u8 code = TRY_READ(strm, 4);
		if (code < 14) {
			code_lengths[i++].length = code;
		} else if (code == 14) {
			u8 zeros = TRY_READ(strm, 7) + 11;
			if (i + zeros > SYMBOL_COUNT) ERROR(EPROTO);
			for (j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		} else if (code == 15) {
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
	if (actual_length + *itt > capacity) {
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
			if (itt >= capacity) {
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

PUBLIC u64 compress_bound(u64 len) { return len + (len >> 5) + 1024; }

PUBLIC i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u32 term_index;
	u32 frequencies[SYMBOL_COUNT] = {0};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	u8 __attribute__((
	    aligned(32))) match_array[4 * MAX_COMPRESS_LEN + 33] = {0};

	if (capacity < compress_bound(len) || len > MAX_COMPRESS_LEN) {
		errno = EINVAL;
		return -1;
	}

	compress_find_matches(in, len, match_array, frequencies, &term_index);
	compress_calculate_lengths(frequencies, code_lengths);
	compress_calculate_codes(code_lengths);
	return compress_write(code_lengths, match_array, out, term_index);
}

PUBLIC i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity,
			    u64 *bytes_consumed) {
	BitStreamReader strm = {in, len};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	compress_read_lengths(&strm, code_lengths);
	compress_calculate_codes(code_lengths);
	return compress_read_symbols(&strm, code_lengths, out, capacity,
				     bytes_consumed);
}
