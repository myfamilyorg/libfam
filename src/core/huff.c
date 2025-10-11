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
		      const u16 codes[SYMBOL_COUNT], u16 symbol, u32 index,
		      HuffSymbols huff) {
	u8 extra_bits =
	    symbol >= MATCH_OFFSET
		? compress_length_extra_bits(symbol - MATCH_OFFSET) +
		      compress_distance_extra_bits(symbol - MATCH_OFFSET)
		: 0;

	u8 bits_consumed = huff.bits_consumed + lengths[symbol] + extra_bits;
	u8 output_byte = symbol >= MATCH_OFFSET	 ? symbol - MATCH_OFFSET
			 : symbol == SYMBOL_TERM ? 0xFF
						 : symbol;
	u8 match_flags =
	    huff.match_flags | ((symbol >= SYMBOL_TERM) << huff.out_incr);
	u8 out_incr = huff.out_incr + 1;
	u8 oindex = huff.out_incr;

	if (oindex >= 4 || bits_consumed > 18) return;

	huff.bits_consumed = bits_consumed;
	huff.match_flags = match_flags;
	huff.out_incr = out_incr;
	huff.output.output_bytes[oindex] = output_byte;

	u32 fill_depth = 1U << ((MAX_CODE_LENGTH << 1) - bits_consumed);
	for (u32 i = 0; i < fill_depth; i++) {
		u32 idx = index | (i << bits_consumed);
		lookup_table[idx] = huff;
	}

	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (!lengths[i]) continue;
		u32 new_index = (index | ((u64)codes[i] << bits_consumed)) &
				(LOOKUP_SIZE - 1);
		huff_fill(lookup_table, lengths, codes, i, new_index, huff);
	}
}

void huff_lookup(HuffSymbols lookup_table[LOOKUP_SIZE],
		 const u8 lengths[SYMBOL_COUNT],
		 const u16 codes[SYMBOL_COUNT]) {
	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (lengths[i]) {
			i32 index = codes[i] & ((1U << lengths[i]) - 1);
			HuffSymbols huff = {0};
			huff_fill(lookup_table, lengths, codes, i, index, huff);
		}
	}
}
