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
#include <libfam/atomic.h>
#include <libfam/bitstream.h>
#include <libfam/builtin.h>
#include <libfam/compress.h>
#include <libfam/compress_impl.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/linux_time.h>
#include <libfam/memory.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

STATIC MatchInfo lz_hash_get(const LzHash *hash, const u8 *text, u32 cpos) {
	u16 pos, dist, len = 0;
	u32 mask, mpos, key = *(u32 *)(text + cpos);
	pos = hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT];
	dist = (u16)cpos - pos;
	if (!dist) return (MatchInfo){.len = 0, .dist = 0};
	mpos = cpos - dist;

#ifdef __AVX2__
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

STATIC void lz_hash_set(LzHash *hash, const u8 *text, u32 cpos) {
	u32 key = *(u32 *)(text + cpos);
	hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = (u16)cpos;
}

void compress_find_matches(const u8 *in, u32 len,
			   u8 match_array[2 * MAX_COMPRESS_LEN + 1],
			   u32 frequencies[SYMBOL_COUNT]) {
	u32 i = 0, max, out_itt = 0;
	LzHash hash = {0};
	max = len >= MAX_MATCH_LEN ? len - MAX_MATCH_LEN : 0;

	while (i < max) {
		MatchInfo mi = lz_hash_get(&hash, in, i);
		if (mi.len >= MIN_MATCH_LEN) {
			u8 mc = get_match_code(mi.len, mi.dist);
			frequencies[mc + MATCH_OFFSET]++;
			u8 len_extra = length_extra_bits_value(mc, mi.len);
			((u16 *)match_array)[out_itt >> 1] =
			    (len_extra << 8) | (mc + 2);
			u16 dist_extra = distance_extra_bits_value(mc, mi.dist);
			((u16 *)match_array)[(out_itt + 2) >> 1] = dist_extra;
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
			out_itt += 2;
		}
	}
	while (i < len) {
		frequencies[in[i]]++;
		((u16 *)match_array)[(out_itt) >> 1] = in[i] << 8;
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
				     u8 lengths[SYMBOL_COUNT]) {
	if (!node) return;
	if (!node->left && !node->right) lengths[node->symbol] = length;
	compress_compute_lengths(node->left, length + 1, lengths);
	compress_compute_lengths(node->right, length + 1, lengths);
}

STATIC void compress_build_tree(const u32 frequencies[SYMBOL_COUNT],
				u8 lengths[SYMBOL_COUNT], HuffmanMinHeap *heap,
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
	HuffmanNode nodes[SYMBOL_COUNT * 2 + 1];
	HuffmanNode *root;
	compress_build_tree(frequencies, lengths, &heap, nodes);
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
		if (lengths[i] != 0) {
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

STATIC i32 compress_write(const u16 codes[SYMBOL_COUNT],
			  const u8 lengths[SYMBOL_COUNT],
			  const u8 match_array[2 * MAX_COMPRESS_LEN + 1],
			  u8 *out) {
	u32 i = 0;
	BitStreamWriter strm = {out};
	compress_write_lengths(&strm, lengths);
	while (match_array[i] != 1) {
		if (match_array[i] == 0) {
			u8 symbol = match_array[i + 1];
			u16 code = codes[symbol];
			u8 length = lengths[symbol];
			WRITE(&strm, code, length);
			i += 2;
		} else {
			u8 match_code = match_array[i] - 2;
			u16 symbol = (u16)match_code + MATCH_OFFSET;
			u16 code = codes[symbol];
			u8 length = lengths[symbol];
			u16 len_extra_bits_value = match_array[i + 1];
			u8 len_extra_bits = length_extra_bits(match_code);
			u8 dist_extra_bits = distance_extra_bits(match_code);
			u16 distance_extra_bits_value =
			    match_array[i + 2] | match_array[i + 3] << 8;

			if (strm.bits_in_buffer + length + len_extra_bits +
				dist_extra_bits >
			    64)
				bitstream_writer_flush(&strm);

			bitstream_writer_push(&strm, code, length);
			bitstream_writer_push(&strm, len_extra_bits_value,
					      len_extra_bits);
			bitstream_writer_push(&strm, distance_extra_bits_value,
					      dist_extra_bits);
			i += 4;
		}
	}

	WRITE(&strm, codes[SYMBOL_TERM], lengths[SYMBOL_TERM]);
	WRITE(&strm, 0, 64);
	bitstream_writer_flush(&strm);
	return (strm.bit_offset + 7) / 8;
}

STATIC i32 compress_read_lengths(BitStreamReader *strm,
				 u8 lengths[SYMBOL_COUNT]) {
	i32 i = 0, j;
INIT:
	while (i < SYMBOL_COUNT) {
		u8 code = TRY_READ(strm, 4);
		if (code < 14) {
			lengths[i++] = code;
		} else if (code == 14) {
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
    const u8 lengths[SYMBOL_COUNT], const u16 codes[SYMBOL_COUNT],
    HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)]) {
	i32 i, j;
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i]) {
			i32 index = codes[i] & ((1U << lengths[i]) - 1);
			i32 fill_depth = 1U << (MAX_CODE_LENGTH - lengths[i]);
			for (j = 0; j < fill_depth; j++) {
				lookup_table[index | (j << lengths[i])].length =
				    lengths[i];
				lookup_table[index | (j << lengths[i])].symbol =
				    i;
				if (i >= MATCH_OFFSET) {
					u8 mc = i - MATCH_OFFSET;
					lookup_table[index | (j << lengths[i])]
					    .dist_extra_bits =
					    distance_extra_bits(mc);
					lookup_table[index | (j << lengths[i])]
					    .len_extra_bits =
					    length_extra_bits(mc);
					lookup_table[index | (j << lengths[i])]
					    .base_dist = distance_base(mc);
					lookup_table[index | (j << lengths[i])]
					    .base_len = length_base(mc) + 4;
				}
			}
		}
	}
}

STATIC i32 compress_read_symbols(BitStreamReader *strm,
				 const u8 lengths[SYMBOL_COUNT],
				 const u16 codes[SYMBOL_COUNT], u8 *out,
				 u32 capacity, u64 *bytes_consumed) {
	HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
	u32 itt = 0;
	u16 symbol = 0;
	u8 load_threshold = MAX_CODE_LENGTH + 7 + 15;

	compress_build_lookup_table(lengths, codes, lookup_table);

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

PUBLIC i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u32 frequencies[SYMBOL_COUNT] = {0};
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT] = {0};
	u8 match_array[2 * MAX_COMPRESS_LEN + 1] = {0};

	if (capacity < compress_bound(len) || len > MAX_COMPRESS_LEN) {
		errno = EINVAL;
		return -1;
	}

	compress_find_matches(in, len, match_array, frequencies);
	compress_calculate_lengths(frequencies, lengths);
	compress_calculate_codes(lengths, codes);
	return compress_write(codes, lengths, match_array, out);
}

PUBLIC i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity,
			    u64 *bytes_consumed) {
	BitStreamReader strm = {in, len};
	u8 lengths[SYMBOL_COUNT] = {0};
	u16 codes[SYMBOL_COUNT] = {0};
	compress_read_lengths(&strm, lengths);
	compress_calculate_codes(lengths, codes);
	return compress_read_symbols(&strm, lengths, codes, out, capacity,
				     bytes_consumed);
}

PUBLIC u64 compress_bound(u64 len) { return len + (len >> 5) + 1024; }

PUBLIC i32 decompress_stream(i32 in_fd, i32 out_fd) {
	CompressHeader header = {0};
	u64 in_offset = sizeof(CompressHeader);
	u64 out_offset = 0;
	u8 in_chunk[MAX_COMPRESS_BOUND_LEN] = {0},
	   out_chunk[4][MAX_COMPRESS_LEN + MAX_AVX_OVERWRITE] = {0};
	u64 in_chunk_size = 0, out_chunk_size = 0, id;
	IoUring *iou = NULL;
	u64 in_file_size = fsize(in_fd);
	u64 next_write = U32_MAX, next_read = 0;
	struct timevalfam ts[2] = {0};
INIT:
	if (iouring_init(&iou, 4) < 0) ERROR();

	in_chunk_size = compress_bound(MAX_COMPRESS_LEN);
	out_chunk_size = MAX_COMPRESS_LEN;

	if (iouring_init_read(iou, in_fd, &header, sizeof(CompressHeader), 0,
			      next_read) < 0)
		ERROR();
	next_read++;

	if (iouring_submit(iou, 1) < 0) ERROR();
	iouring_spin(iou, &id);

	while (out_offset < header.file_size) {
		in_chunk_size = min(compress_bound(MAX_COMPRESS_LEN),
				    in_file_size - in_offset);
		if (iouring_init_read(iou, in_fd, in_chunk, in_chunk_size,
				      in_offset, next_read) < 0)
			ERROR();

		if (iouring_submit(iou, 1) < 0) ERROR();
		while (true) {
			iouring_spin(iou, &id);
			if (id == next_read) break;
		}
		next_read++;

		u64 bytes_consumed;
		i32 result = decompress_block(in_chunk, in_chunk_size,
					      out_chunk[next_write % 4],
					      out_chunk_size, &bytes_consumed);
		if (result < 0) ERROR(EINVAL);

		if (iouring_init_write(iou, out_fd, out_chunk[next_write % 4],
				       result, out_offset, next_write) < 0)
			ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();

		if (next_write != U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					iouring_spin(iou, &id);
					if (id == next_write + 1) break;
				}
			}
		}

		in_offset += bytes_consumed;
		out_offset += result;
		next_write--;
	}

	while (iouring_pending_all(iou)) iouring_spin(iou, &id);
	if (out_fd != STDOUT_FD) {
		if (fresize(out_fd, out_offset) < 0) ERROR();
		if (fchmod(out_fd, header.permissions & 07777) < 0) ERROR();

		ts[0].tv_sec = header.atime;
		ts[1].tv_sec = header.mtime;
		if (utimesat(out_fd, NULL, ts, 0) < 0) ERROR();
	}
CLEANUP:
	if (iou) iouring_destroy(iou);
	RETURN;
}

PUBLIC i32 compress_stream(i32 in_fd, i32 out_fd) {
	CompressHeader header;
	u64 in_offset = 0;
	u64 out_offset = sizeof(CompressHeader);
	u8 in_chunk[2][MAX_COMPRESS_LEN], out_chunk[2][MAX_COMPRESS_BOUND_LEN];
	u64 in_chunk_size = MAX_COMPRESS_LEN,
	    out_chunk_size = compress_bound(MAX_COMPRESS_LEN);
	IoUring *iou = NULL;
	u64 next_read = 0, next_write = U64_MAX, id;
	struct stat st;
INIT:
	if (fstat(in_fd, &st) < 0) ERROR();
	if (!S_ISREG(st.st_mode)) ERROR(EINVAL);

	header.file_size = fsize(in_fd);
	header.version = 0;
	header.permissions = st.st_mode & 07777;
	header.mtime = st.st_mtime;
	header.atime = st.st_atime;

	if (iouring_init(&iou, 4) < 0) ERROR();

	if (header.file_size == 0) ERROR(EINVAL);

	if (iouring_init_write(iou, out_fd, (u8 *)&header,
			       sizeof(CompressHeader), 0, 0) < 0)
		ERROR();
	if (iouring_submit(iou, 1) < 0) ERROR();
	i32 res = iouring_spin(iou, &id);
	if (res < 0) ERROR();
	if (res != sizeof(CompressHeader)) ERROR(EIO);

	in_chunk_size = min(header.file_size, MAX_COMPRESS_LEN);
	if (iouring_init_read(iou, in_fd, in_chunk[0], in_chunk_size, in_offset,
			      next_read) < 0)
		ERROR();
	iouring_submit(iou, 1);

	while (in_offset < header.file_size) {
		if (iouring_pending(iou, next_read)) {
			while (true) {
				iouring_spin(iou, &id);
				if (id == next_read) break;
			}
		}
		next_read++;

		if (in_offset + MAX_COMPRESS_LEN <= header.file_size) {
			in_chunk_size = min(
			    header.file_size - (in_offset + MAX_COMPRESS_LEN),
			    MAX_COMPRESS_LEN);
			if (iouring_init_read(
				iou, in_fd, in_chunk[next_read % 2],
				in_chunk_size, in_offset + MAX_COMPRESS_LEN,
				next_read) < 0)
				ERROR();
			iouring_submit(iou, 1);
		}

		in_chunk_size =
		    min(header.file_size - in_offset, MAX_COMPRESS_LEN);

		i32 result =
		    compress_block(in_chunk[(next_read - 1) % 2], in_chunk_size,
				   out_chunk[next_write % 2], out_chunk_size);
		if (result < 0) ERROR(EINVAL);

		if (iouring_init_write(iou, out_fd, out_chunk[next_write % 2],
				       result, out_offset, next_write) < 0)
			ERROR();
		if (iouring_submit(iou, 1) < 0) ERROR();

		if (next_write != U64_MAX) {
			if (iouring_pending(iou, next_write + 1)) {
				while (true) {
					iouring_spin(iou, &id);
					if (id == next_write + 1) break;
				}
			}
		}

		next_write--;
		in_offset += in_chunk_size;
		out_offset += result;
	}
	while (iouring_pending_all(iou)) iouring_spin(iou, &id);
	if (out_fd != STDOUT_FD) {
		if (fresize(out_fd, out_offset) < 0) ERROR();
		if (fchmod(out_fd, header.permissions & 07777) < 0) ERROR();
	}
CLEANUP:
	if (iou) iouring_destroy(iou);
	RETURN;
}
