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

#ifndef _BPTREE_H
#define _BPTREE_H

#include <libfam/types.h>

#define MAX_LEVELS 128

typedef struct BpTree BpTree;
typedef struct BpTxn BpTxn;
typedef struct BpTreeNode BpTreeNode;

typedef struct {
	u64 node_id;
	u16 parent_index[MAX_LEVELS];
	u8 levels;
	u16 key_index;
	bool found;
} BpTreeSearchResult;

typedef void (*BpTreeSearch)(const BpTxn *txn, const void *key, u16 key_len,
			     const BpTreeNode *node,
			     BpTreeSearchResult *retval);

/* BpTree Handle management */
i32 bptree_open(BpTree **tree, const u8 *path);
i32 bptree_destroy(BpTree *tree);

/* BpTxn management */
i32 bptxn_start(BpTxn **txn, const BpTree *tree);
i32 bptxn_commit(BpTxn *txn);
void bptxn_abort(BpTxn *txn);

/* Modification functions */
i32 bptree_put(BpTxn *txn, const void *key, u16 key_len, const void *value,
	       u32 value_len, const BpTreeSearch search);
i32 bptree_remove(BpTxn *txn, const void *key, u16 key_len, const void *value,
		  u32 value_len, const BpTreeSearch search);

/* Search helpers */
const BpTreeNode *bptxn_get_node(const BpTxn *txn, u64 node_id);
i32 bptree_node_is_root(const BpTxn *txn, const BpTreeNode *node);
u64 bptree_node_id(const BpTxn *txn, const BpTreeNode *node);
const void *bptree_read_key(const BpTxn *txn, const BpTreeNode *node,
			    u16 index);
const void *bptree_read_value(const BpTxn *txn, const BpTreeNode *node,
			      u16 index);
const BpTreeNode *bptree_next_leaf(const BpTxn *txn, const BpTreeNode *node);
const BpTreeNode *bptree_prev_leaf(const BpTxn *txn, const BpTreeNode *node);

#endif /* _BPTREE_H */
