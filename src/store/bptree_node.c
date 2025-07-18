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

#include <libfam/bptree_node.H>
#include <libfam/error.H>
#include <libfam/format.H>
#include <libfam/misc.H>

/* Data specific to an internal node */
typedef struct {
	u16 entry_offsets[MAX_INTERNAL_ENTRIES];
	u8 entries[INTERNAL_ARRAY_SIZE];
} BpTreeInternalNode;

/* Data specific to a leaf node */
typedef struct {
	u64 next_leaf;
	u16 entry_offsets[MAX_LEAF_ENTRIES];
	u8 entries[LEAF_ARRAY_SIZE];
} BpTreeLeafNode;

typedef struct {
	u64 aux;
	u64 parent_id;
	u64 reserved1;
	u64 reserved2;
	u16 num_entries;
	u16 used_bytes;
	bool is_internal;
	bool is_copy;
	union {
		BpTreeInternalNode internal;
		BpTreeLeafNode leaf;
	} data;
} BpTreeNodeImpl;

/* BpTree entry */
typedef struct {
	u32 value_len;
	u16 key_len;
	bool overflow;
} BpTreeLeafEntry;

/* BpTree Internal entry */
typedef struct {
	u64 node_id;
	u16 key_len;
} BpTreeInternalEntry;

#define STATIC_ASSERT(condition, message) \
	typedef u8 static_assert_##message[(condition) ? 1 : -1]

STATIC_ASSERT(sizeof(BpTreeNode) == NODE_SIZE, bptree_node_size);
STATIC_ASSERT(sizeof(BpTreeNodeImpl) == NODE_SIZE, bptreeimpl_node_size);
STATIC_ASSERT(sizeof(BpTreeLeafNode) == sizeof(BpTreeInternalNode),
	      bptree_nodes_equal);

STATIC void shift_by_offset(BpTreeNodeImpl *node, u16 key_index, i32 shift) {
	i32 i;
	u16 pos, bytes_to_move;
	void *dst, *src;

	if (node->is_internal)
		pos = node->data.internal.entry_offsets[key_index];
	else
		pos = node->data.leaf.entry_offsets[key_index];
	bytes_to_move = node->used_bytes - pos;
	if (node->is_internal) {
		dst = node->data.internal.entries + pos + shift;
		src = node->data.internal.entries + pos;

	} else {
		dst = node->data.leaf.entries + pos + shift;
		src = node->data.leaf.entries + pos;
	}

	memorymove(dst, src, bytes_to_move);
	for (i = node->num_entries; i > key_index; i--) {
		if (node->is_internal) {
			node->data.internal.entry_offsets[i] =
			    node->data.internal.entry_offsets[i - 1] + shift;

		} else {
			node->data.leaf.entry_offsets[i] =
			    node->data.leaf.entry_offsets[i - 1] + shift;
		}
	}
}

STATIC void place_item(BpTreeNodeImpl *node, u16 key_index, BpTreeItem *item) {
	if (node->is_internal) {
		u16 pos = node->data.internal.entry_offsets[key_index];
		BpTreeInternalEntry entry = {0};
		entry.key_len = item->key_len;
		entry.node_id = item->vardata.internal.node_id;
		memcpy((u8 *)node->data.internal.entries + pos, &entry,
		       sizeof(BpTreeInternalEntry));
		memcpy((u8 *)node->data.internal.entries + pos +
			   sizeof(BpTreeInternalEntry),
		       item->key, entry.key_len);

	} else {
		u16 pos = node->data.leaf.entry_offsets[key_index];
		BpTreeLeafEntry entry = {0};
		if (item->item_type == BPTREE_ITEM_TYPE_LEAF)
			entry.value_len = item->vardata.kv.value_len;
		else if (item->item_type == BPTREE_ITEM_TYPE_OVERFLOW) {
			entry.value_len = item->vardata.overflow.value_len;
			entry.overflow = true;
		}
		entry.key_len = item->key_len;
		memcpy((u8 *)node->data.leaf.entries + pos, &entry,
		       sizeof(BpTreeLeafEntry));
		memcpy((u8 *)node->data.leaf.entries + pos +
			   sizeof(BpTreeLeafEntry),
		       item->key, entry.key_len);

		if (item->item_type == BPTREE_ITEM_TYPE_LEAF)
			memcpy((u8 *)node->data.leaf.entries + pos +
				   sizeof(BpTreeLeafEntry) + entry.key_len,
			       item->vardata.kv.value, entry.value_len);
		else if (item->item_type == BPTREE_ITEM_TYPE_OVERFLOW) {
			memcpy((u8 *)node->data.leaf.entries + pos +
				   sizeof(BpTreeLeafEntry) + entry.key_len,
			       &item->vardata.overflow.overflow_start,
			       sizeof(u64));
			memcpy((u8 *)node->data.leaf.entries + pos +
				   sizeof(BpTreeLeafEntry) + entry.key_len +
				   sizeof(u64),
			       &item->vardata.overflow.overflow_end,
			       sizeof(u64));
		}
	}
}

i32 bptree_node_calculate_needed(BpTreeNode *node, BpTreeItem *item) {
	BpTreeNodeImpl *impl;
	if (!node || !item) {
		err = EINVAL;
		return -1;
	}

	impl = (BpTreeNodeImpl *)node;
	if (impl->is_internal) {
		if (item->item_type != BPTREE_ITEM_TYPE_INTERNAL) return -1;
		return item->key_len + sizeof(BpTreeInternalEntry);
	} else if (item->item_type == BPTREE_ITEM_TYPE_OVERFLOW) {
		return item->key_len + sizeof(BpTreeLeafEntry) +
		       sizeof(u64) * 2;
	} else {
		if (item->item_type != BPTREE_ITEM_TYPE_LEAF) return -1;
		return item->key_len + item->vardata.kv.value_len +
		       sizeof(BpTreeLeafEntry);
	}
}

i32 bptree_node_init_node(BpTreeNode *node, u64 parent_id, bool is_internal) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl) {
		err = EINVAL;
		return -1;
	}

	impl->is_internal = is_internal;
	impl->parent_id = parent_id;
	impl->used_bytes = impl->num_entries = 0;
	impl->is_copy = true;
	impl->aux = 0;
	if (is_internal)
		impl->data.internal.entry_offsets[0] = 0;
	else {
		impl->data.leaf.entry_offsets[0] = 0;
		impl->data.leaf.next_leaf = 0;
	}

	return 0;
}

i32 bptree_node_set_aux(BpTreeNode *node, u64 aux) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl) {
		err = EINVAL;
		return -1;
	}

	impl->aux = aux;
	return 0;
}

i32 bptree_node_set_parent(BpTreeNode *node, u64 parent_id) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl) {
		err = EINVAL;
		return -1;
	}

	if (!impl->is_copy) {
		err = EACCES;
		return -1;
	}

	impl->parent_id = parent_id;
	return 0;
}

i32 bptree_node_set_copy(BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl || impl->is_copy) {
		err = EINVAL;
		return -1;
	}

	impl->is_copy = true;
	return 0;
}

i32 bptree_node_unset_copy(BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl || !impl->is_copy) {
		err = EINVAL;
		return -1;
	}

	impl->is_copy = false;
	return 0;
}

void bptree_node_copy(BpTreeNode *dst, BpTreeNode *src) {
	if (!dst || !src) {
		err = EINVAL;
		return;
	}
	BpTreeNodeImpl *dst_impl = (BpTreeNodeImpl *)dst;
	memcpy((u8 *)dst_impl, (u8 *)src, NODE_SIZE);
	dst_impl->is_copy = true;
}

i32 bptree_node_set_next_leaf(BpTreeNode *node, u64 next_leaf) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl || impl->is_internal) {
		err = EINVAL;
		return -1;
	}

	if (!impl->is_copy) {
		err = EACCES;
		return -1;
	}

	impl->data.leaf.next_leaf = next_leaf;
	return 0;
}

i32 bptree_node_set_entry(BpTreeNode *node, u16 index, BpTreeItem *item) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	i32 size_new, width, delta, max_size;
	u16 pos, i;
	u8 *entries;
	u16 *entry_offsets;

	if (!node || !item || index >= impl->num_entries) {
		err = EINVAL;
		return -1;
	}

	if (!impl->is_copy) {
		err = EACCES;
		return -1;
	}

	size_new = bptree_node_calculate_needed(node, item);
	if (size_new < 0) {
		err = EINVAL;
		return -1;
	}

	pos = bptree_node_offset(node, index);
	if (index < impl->num_entries - 1) {
		width = bptree_node_offset(node, index + 1) - pos;
	} else {
		width = impl->used_bytes - pos;
	}

	delta = size_new - width;
	max_size = impl->is_internal ? INTERNAL_ARRAY_SIZE : LEAF_ARRAY_SIZE;
	if (impl->used_bytes + delta > max_size) {
		err = EOVERFLOW;
		return -1;
	}

	if (impl->is_internal) {
		entries = impl->data.internal.entries;
		entry_offsets = impl->data.internal.entry_offsets;
	} else {
		entries = impl->data.leaf.entries;
		entry_offsets = impl->data.leaf.entry_offsets;
	}

	if (delta != 0) {
		u16 tail_bytes = impl->used_bytes - pos - width;
		memorymove(entries + pos + size_new, entries + pos + width,
			   tail_bytes);
		for (i = index + 1; i < impl->num_entries; i++) {
			entry_offsets[i] += delta;
		}
		impl->used_bytes += delta;
	}

	place_item(impl, index, item);
	return 0;
}

i32 bptree_node_move_entries(BpTreeNode *dst, u16 dst_start_index,
			     BpTreeNode *src, u16 src_start_index,
			     u16 num_entries) {
	BpTreeNodeImpl *src_impl = (BpTreeNodeImpl *)src;
	BpTreeNodeImpl *dst_impl = (BpTreeNodeImpl *)dst;
	u32 dst_start_pos, src_start_pos, bytes_to_copy, i;
	u16 compact_bytes;

	u8 *dst_entries, *src_entries;
	u16 *dst_entry_offsets, *src_entry_offsets;

	if (!dst || !src || num_entries == 0 ||
	    (u32)num_entries + (u32)src_start_index > src_impl->num_entries) {
		err = EINVAL;
		return -1;
	}

	if (!dst_impl->is_copy) {
		err = EACCES;
		return -1;
	}

	if (dst_impl->is_internal) {
		if (!src_impl->is_internal ||
		    (u32)num_entries + (u32)dst_start_index >=
			MAX_INTERNAL_ENTRIES) {
			err = EOVERFLOW;
			return -1;
		}
		dst_entries = dst_impl->data.internal.entries;
		src_entries = src_impl->data.internal.entries;
		dst_entry_offsets = dst_impl->data.internal.entry_offsets;
		src_entry_offsets = src_impl->data.internal.entry_offsets;
	} else {
		if (src_impl->is_internal ||
		    (u32)num_entries + (u32)dst_start_index >=
			MAX_LEAF_ENTRIES) {
			err = EOVERFLOW;
			return -1;
		}
		dst_entries = dst_impl->data.leaf.entries;
		src_entries = src_impl->data.leaf.entries;
		dst_entry_offsets = dst_impl->data.leaf.entry_offsets;
		src_entry_offsets = src_impl->data.leaf.entry_offsets;
	}

	dst_start_pos = dst_entry_offsets[dst_start_index];
	src_start_pos = src_entry_offsets[src_start_index];

	if (src_start_index + num_entries < src_impl->num_entries) {
		bytes_to_copy =
		    src_entry_offsets[src_start_index + num_entries] -
		    src_start_pos;
	} else
		bytes_to_copy = src_impl->used_bytes - src_start_pos;

	if (!dst_impl->is_internal &&
	    (u32)bytes_to_copy + (u32)dst_impl->used_bytes > LEAF_ARRAY_SIZE) {
		err = EOVERFLOW;
		return -1;
	}
	if (dst_impl->is_internal &&
	    (u32)bytes_to_copy + (u32)dst_impl->used_bytes >
		INTERNAL_ARRAY_SIZE) {
		err = EOVERFLOW;
		return -1;
	}

	if (dst_start_index < dst_impl->num_entries) {
		shift_by_offset(dst_impl, dst_start_index, bytes_to_copy);
	}

	memorymove((u8 *)dst_entries + dst_start_pos,
		   (u8 *)src_entries + src_start_pos, bytes_to_copy);

	compact_bytes = src_impl->used_bytes - (src_start_pos + bytes_to_copy);
	dst_impl->num_entries += num_entries;
	src_impl->num_entries -= num_entries;
	dst_impl->used_bytes += bytes_to_copy;
	src_impl->used_bytes -= bytes_to_copy;

	for (i = 0; i < num_entries; i++) {
		dst_entry_offsets[dst_start_index + i] =
		    src_entry_offsets[src_start_index + i] - src_start_pos +
		    dst_start_pos;
	}

	if (src_start_index < num_entries) {
		memorymove((u8 *)src_entries + src_start_pos,
			   (u8 *)src_entries + src_start_pos + bytes_to_copy,
			   compact_bytes);
	}

	return 0;
}

i32 bptree_node_insert_entry(BpTreeNode *node, u16 index, BpTreeItem *item) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	i32 needed;
	u16 *entry_offsets;

	if (!node || !item || index > impl->num_entries) {
		err = EINVAL;
		return -1;
	}

	if (!impl->is_internal && impl->num_entries == MAX_LEAF_ENTRIES) {
		err = EOVERFLOW;
		return -1;
	}

	if (impl->is_internal && impl->num_entries == MAX_INTERNAL_ENTRIES) {
		err = EOVERFLOW;
		return -1;
	}

	if (!impl->is_copy) {
		err = EACCES;
		return -1;
	}

	if (impl->is_internal)
		entry_offsets = impl->data.internal.entry_offsets;
	else
		entry_offsets = impl->data.leaf.entry_offsets;

	needed = bptree_node_calculate_needed(node, item);
	if (needed < 0) {
		err = EINVAL;
		return -1;
	}
	if (!impl->is_internal &&
	    (u32)needed + (u32)impl->used_bytes > LEAF_ARRAY_SIZE) {
		err = EOVERFLOW;
		return -1;
	}
	if (impl->is_internal &&
	    (u32)needed + (u32)impl->used_bytes > INTERNAL_ARRAY_SIZE) {
		err = EOVERFLOW;
		return -1;
	}

	if (impl->num_entries > index)
		shift_by_offset(impl, index, needed);
	else
		entry_offsets[impl->num_entries] = impl->used_bytes;

	place_item(impl, index, item);
	impl->used_bytes += needed;
	impl->num_entries++;

	return 0;
}

i32 bptree_node_delete_entry(BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	i32 width;
	u16 pos, i;
	u8 *entries;
	u16 *entry_offsets;

	if (!node || index >= impl->num_entries) {
		err = EINVAL;
		return -1;
	}

	if (!impl->is_copy) {
		err = EACCES;
		return -1;
	}

	if (impl->is_internal) {
		entry_offsets = impl->data.internal.entry_offsets;
		entries = impl->data.internal.entries;
	} else {
		entry_offsets = impl->data.leaf.entry_offsets;
		entries = impl->data.leaf.entries;
	}

	pos = entry_offsets[index];
	if (index < (impl->num_entries - 1)) {
		width = entry_offsets[index + 1] - entry_offsets[index];
	} else {
		width = impl->used_bytes - entry_offsets[index];
	}

	memorymove(entries + pos, entries + pos + width,
		   impl->used_bytes - (pos + width));

	for (i = index; i < impl->num_entries - 1; i++) {
		entry_offsets[i] = entry_offsets[i + 1] - width;
	}

	impl->num_entries--;
	impl->used_bytes -= width;
	return 0;
}

u64 bptree_node_parent_id(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return 0;
	return impl->parent_id;
}

u16 bptree_node_num_entries(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return 0;
	return impl->num_entries;
}

u16 bptree_node_used_bytes(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return 0;
	return impl->used_bytes;
}

bool bptree_node_is_copy(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return false;
	return impl->is_copy;
}

bool bptree_node_is_internal(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return false;
	return impl->is_internal;
}

u64 bptree_node_aux(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl) return 0;
	return impl->aux;
}

u64 bptree_node_next_leaf(const BpTreeNode *node) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl || impl->is_internal) return 0;
	return impl->data.leaf.next_leaf;
}

u16 bptree_node_key_len(const BpTreeNode *node, u16 index) {
	u16 pos;
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl || index >= impl->num_entries) {
		err = EINVAL;
		return 0;
	}

	if (impl->is_internal) {
		BpTreeInternalEntry *entry;
		pos = impl->data.internal.entry_offsets[index];
		entry =
		    (BpTreeInternalEntry *)((u8 *)impl->data.internal.entries +
					    pos);
		return entry->key_len;
	} else {
		BpTreeLeafEntry *entry;
		pos = impl->data.leaf.entry_offsets[index];
		entry =
		    (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);
		return entry->key_len;
	}
}

u32 bptree_node_value_len(const BpTreeNode *node, u16 index) {
	BpTreeLeafEntry *entry;
	u16 pos;
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	if (!impl || impl->is_internal || index >= impl->num_entries) return 0;
	pos = impl->data.leaf.entry_offsets[index];
	entry = (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);
	return entry->value_len;
}

const void *bptree_node_key(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u16 pos;

	if (!impl || index >= impl->num_entries) {
		err = EINVAL;
		return NULL;
	}

	if (impl->is_internal) {
		pos = impl->data.internal.entry_offsets[index];
		return (const void *)((u8 *)impl->data.internal.entries + pos +
				      sizeof(BpTreeInternalEntry));
	} else {
		pos = impl->data.leaf.entry_offsets[index];
		return (const void *)((u8 *)impl->data.leaf.entries + pos +
				      sizeof(BpTreeLeafEntry));
	}
}

const void *bptree_node_value(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u16 pos;
	BpTreeLeafEntry *entry;

	if (!impl || impl->is_internal || index >= impl->num_entries) {
		err = EINVAL;
		return NULL;
	}

	pos = impl->data.leaf.entry_offsets[index];
	entry = (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);

	if (entry->overflow) {
		err = EINVAL;
		return NULL;
	}

	return (const void *)((u8 *)impl->data.leaf.entries + pos +
			      sizeof(BpTreeLeafEntry) + entry->key_len);
}

u16 bptree_node_offset(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;

	if (!impl || index >= impl->num_entries) {
		err = EINVAL;
		return 0;
	}

	if (impl->is_internal) {
		if (index >= MAX_INTERNAL_ENTRIES) {
			err = EINVAL;
			return 0;
		}
		return impl->data.internal.entry_offsets[index];
	} else {
		if (index >= MAX_LEAF_ENTRIES) {
			err = EINVAL;
			return 0;
		}
		return impl->data.leaf.entry_offsets[index];
	}
}

i32 bptree_node_is_overflow(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u16 pos;
	BpTreeLeafEntry *entry;

	if (!impl || index >= impl->num_entries || impl->is_internal) {
		err = EINVAL;
		return -1;
	}

	pos = impl->data.leaf.entry_offsets[index];
	entry = (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);

	if (entry->overflow) return 1;
	return 0;
}

u64 bptree_node_overflow_start(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u64 ret;
	u16 pos;
	BpTreeLeafEntry *entry;

	if (!impl || index >= impl->num_entries || impl->is_internal) {
		err = EINVAL;
		return -1;
	}

	pos = impl->data.leaf.entry_offsets[index];
	entry = (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);

	if (!entry->overflow) {
		err = EINVAL;
		return 0;
	}

	memcpy(&ret,
	       (u8 *)impl->data.leaf.entries + pos + sizeof(BpTreeLeafEntry) +
		   entry->key_len,
	       sizeof(u64));
	return ret;
}

u64 bptree_node_overflow_end(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u16 pos;
	u64 ret;
	BpTreeLeafEntry *entry;

	if (!impl || index >= impl->num_entries || impl->is_internal) {
		err = EINVAL;
		return -1;
	}

	pos = impl->data.leaf.entry_offsets[index];
	entry = (BpTreeLeafEntry *)((u8 *)impl->data.leaf.entries + pos);

	if (!entry->overflow) {
		err = EINVAL;
		return 0;
	}

	memcpy(&ret,
	       (u8 *)impl->data.leaf.entries + pos + sizeof(BpTreeLeafEntry) +
		   entry->key_len + sizeof(u64),
	       sizeof(u64));
	return ret;
}

u64 bptree_node_node_id(const BpTreeNode *node, u16 index) {
	BpTreeNodeImpl *impl = (BpTreeNodeImpl *)node;
	u16 pos;
	BpTreeInternalEntry *entry;

	if (!impl || !impl->is_internal || index >= impl->num_entries) return 0;

	pos = impl->data.internal.entry_offsets[index];
	entry =
	    (BpTreeInternalEntry *)((u8 *)impl->data.internal.entries + pos);

	return entry->node_id;
}
