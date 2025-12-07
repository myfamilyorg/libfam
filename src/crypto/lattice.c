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

#include <libfam/lattice.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/utils.h>

PUBLIC void lattice_keygen(const u8 seed[32], LatticeSK *sk) {
	fastmemcpy(sk, seed, 32);
}

PUBLIC void lattice_pubkey(const LatticeSK *sec_key, LatticePK *pk) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 buffer[32];
	fastmemcpy(buffer, sec_key, 32);
	storm_init(&ctx, buffer);
	storm_xcrypt_buffer(&ctx, buffer);
	fastmemcpy(pk, buffer, 32);
	fastmemset(buffer, 0, 32);
}

PUBLIC i32 lattice_sign(const LatticeSK *sk, const u8 *message, u64 message_len,
			LatticeSig *sig) {
	return 0;
}

PUBLIC i32 lattice_verify(LatticePK *pub_key, const u8 *message,
			  u64 message_len, const LatticeSig *sig) {
	return 0;
}

