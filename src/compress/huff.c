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

#include <libfam/format.h>
#include <libfam/huff.h>
#include <libfam/utils.h>

STATIC_ASSERT(sizeof(HuffSymbols) == 8, huffman_symbols_size);

STATIC void huff_fill(HuffSymbols lookup_table[LOOKUP_SIZE],
		      const u8 lengths[SYMBOL_COUNT],
		      const u16 codes[SYMBOL_COUNT], u32 index,
		      HuffSymbols huff, u8 eb, u16 symbol) {
	u8 bit_depth = huff.bits_consumed - eb;
	u32 fill_depth = 1U << (LOOKUP_BITS - bit_depth);
	for (u32 i = 0; i < fill_depth; i++) {
		u32 idx = index | (i << bit_depth);
		lookup_table[idx] = huff;
	}

	if (huff.out_bytes == 3 || symbol == SYMBOL_TERM) return;

	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (!lengths[i]) continue;
		if (i >= SYMBOL_TERM && huff.match_flags) break;
		if (huff.bits_consumed + lengths[i] <= LOOKUP_BITS) {
			u8 eb = i >= MATCH_OFFSET ? extra_bits(i - MATCH_OFFSET)
						  : 0;
			u32 new_index =
			    (index | ((u64)codes[i] << huff.bits_consumed)) &
			    (LOOKUP_SIZE - 1);

			HuffSymbols new_huff = {
			    .out_bytes = huff.out_bytes + 1,
			    .bits_consumed =
				huff.bits_consumed + lengths[i] + eb,
			    .output.output = huff.output.output,
			    .match_flags = huff.match_flags,
			    .eb_offset = huff.eb_offset};
			if (i >= SYMBOL_TERM) {
				new_huff.match_flags = 1U << new_huff.out_bytes;
				new_huff.output
				    .output_bytes[new_huff.out_bytes] =
				    i - SYMBOL_TERM;
				new_huff.eb_offset =
				    new_huff.bits_consumed - eb;
			} else
				new_huff.output
				    .output_bytes[new_huff.out_bytes] = i;
			huff_fill(lookup_table, lengths, codes, new_index,
				  new_huff, eb, i);
		}
	}
}

void huff_lookup(HuffSymbols lookup_table[LOOKUP_SIZE],
		 const u8 lengths[SYMBOL_COUNT],
		 const u16 codes[SYMBOL_COUNT]) {
	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i]) {
			i32 index = codes[i];
			u8 eb = i >= MATCH_OFFSET ? extra_bits(i - MATCH_OFFSET)
						  : 0;
			HuffSymbols huff = {.match_flags = i >= SYMBOL_TERM};
			huff.output.output_bytes[0] =
			    i >= SYMBOL_TERM ? i - SYMBOL_TERM : i;
			huff.bits_consumed = lengths[i] + eb;
			huff.eb_offset = lengths[i];
			huff_fill(lookup_table, lengths, codes, index, huff, eb,
				  i);
		}
	}
}

