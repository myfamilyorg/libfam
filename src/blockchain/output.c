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

#include <libfam/errno.h>
#include <libfam/memory.h>
#include <libfam/output.h>
#include <libfam/string.h>
#include <libfam/types.h>
#include <libfam/verihash.h>

struct Output {
	OutputType t;
	u64 amount;
	u8 extra[];
};

const Output *output_create_plain(LamportPubKey *pk, u64 amount) {
	Output *ret;
	ret = alloc(sizeof(Output) + LAMPORT_PUBKEY_SIZE);
	if (!ret) return NULL;
	ret->t = OutputTypePlain;
	ret->amount = amount;
	fastmemcpy(ret->extra, pk->data, LAMPORT_PUBKEY_SIZE);
	return ret;
}

const Output *output_create_commitment(u8 commitment[32]) {
	Output *ret;
	ret = alloc(sizeof(Output) + 32);
	if (!ret) return NULL;
	ret->t = OutputTypeCommitment;
	ret->amount = 0;
	fastmemcpy(ret->extra, commitment, 32);
	return ret;
}

void output_destroy(const Output *o) { release((void *)o); }

void output_hash(const Output *o, u8 hash_out[32]) {
	if (o->t == OutputTypePlain)
		verihash256((void *)o, sizeof(Output) + LAMPORT_PUBKEY_SIZE,
			    hash_out);
	else
		verihash256((void *)o, sizeof(Output) + 32, hash_out);
}
