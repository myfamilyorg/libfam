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

#ifndef _BPTREE_NODE_H
#define _BPTREE_NODE_H

#include <libfam/types.H>

#ifndef NODE_SIZE
#ifndef PAGE_SIZE
#define PAGE_SIZE (4 * 4096)
#endif /* PAGE_SIZE */
#define NODE_SIZE ((u64)PAGE_SIZE)
#endif /* NODE_SIZE */

#define MAX_LEAF_ENTRIES ((u64)(NODE_SIZE / 32))
#define MAX_INTERNAL_ENTRIES (NODE_SIZE / 32)
#define INTERNAL_ARRAY_SIZE ((u64)((30 * NODE_SIZE - 1280) / 32))
/*#define INTERNAL_ARRAY_SIZE ((28 * NODE_SIZE - 1024) / 32)*/
#define LEAF_ARRAY_SIZE ((u64)((30 * NODE_SIZE - 1280) / 32) - 8)

/* BpTree Node */
typedef struct {
	u8 data[NODE_SIZE];
} BpTreeNode;

typedef struct {
	const void *value;
	u32 value_len;
} BpKeyValue;

typedef struct {
	u64 overflow_start;
	u64 overflow_end;
	u32 value_len;
} BpOverflow;

typedef struct {
	u64 node_id;
} BpInternal;

typedef enum {
	BPTREE_ITEM_TYPE_LEAF,
	BPTREE_ITEM_TYPE_OVERFLOW,
	BPTREE_ITEM_TYPE_INTERNAL
} BpTreeItemType;

typedef struct {
	u16 key_len;
	const void *key;
	BpTreeItemType item_type;
	union {
		BpKeyValue kv;
		BpOverflow overflow;
		BpInternal internal;
	} vardata;
} BpTreeItem;

/* Create/Modify node */
i32 bptree_node_init_node(BpTreeNode *node, u64 parent_id, bool is_internal);
i32 bptree_node_set_aux(BpTreeNode *node, u64 aux);
i32 bptree_node_set_copy(BpTreeNode *node);
i32 bptree_node_unset_copy(BpTreeNode *node);
void bptree_node_copy(BpTreeNode *dst, BpTreeNode *src);
i32 bptree_node_set_next_leaf(BpTreeNode *node, u64 next_leaf);
i32 bptree_node_set_parent(BpTreeNode *node, u64 parent_id);

/* Insert */
i32 bptree_node_insert_entry(BpTreeNode *node, u16 index, BpTreeItem *item);
/* Update */
i32 bptree_node_set_entry(BpTreeNode *node, u16 index, BpTreeItem *item);
/* Delete */
i32 bptree_node_delete_entry(BpTreeNode *node, u16 index);
/* Move */
i32 bptree_node_move_entries(BpTreeNode *dst, u16 dst_start_index,
			     BpTreeNode *src, u16 src_start_index,
			     u16 num_entries);
/* Accessors/Helpers */
i32 bptree_node_calculate_needed(BpTreeNode *node, BpTreeItem *item);
u64 bptree_node_parent_id(const BpTreeNode *node);
u16 bptree_node_num_entries(const BpTreeNode *node);
u16 bptree_node_used_bytes(const BpTreeNode *node);
bool bptree_node_is_copy(const BpTreeNode *node);
bool bptree_node_is_internal(const BpTreeNode *node);
u64 bptree_node_aux(const BpTreeNode *node);

i32 bptree_node_is_overflow(const BpTreeNode *node, u16 index);
u16 bptree_node_key_len(const BpTreeNode *node, u16 index);
u16 bptree_node_offset(const BpTreeNode *node, u16 index);
u32 bptree_node_value_len(const BpTreeNode *node, u16 index);
u64 bptree_node_overflow_start(const BpTreeNode *node, u16 index);
u64 bptree_node_overflow_end(const BpTreeNode *node, u16 index);
const void *bptree_node_key(const BpTreeNode *node, u16 index);
const void *bptree_node_value(const BpTreeNode *node, u16 index);
u64 bptree_node_next_leaf(const BpTreeNode *node);
u64 bptree_node_node_id(const BpTreeNode *node, u16 index);

#endif /* _BPTREE_NODE_H */
