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

#ifndef _RBTREE_H
#define _RBTREE_H

#include <libfam/types.h>

/*
 * Type: RbTreeNode
 * Node structure for a red-black tree.
 * members:
 *         RbTreeNode *parent_color - pointer to parent; LSB encodes color
 * (0=red, 1=black). RbTreeNode *right        - pointer to right child.
 *         RbTreeNode *left         - pointer to left child.
 * notes:
 *         User data must be embedded at the start of a struct containing this.
 *         Example:
 *           typedef struct { RbTreeNode node; u64 key; u8 *value; } MyNode;
 *         Color is stored in the least significant bit of parent_color.
 *         NULL parent indicates root.
 */
typedef struct RbTreeNode {
	struct RbTreeNode *parent_color;
	struct RbTreeNode *right;
	struct RbTreeNode *left;
} RbTreeNode;

/*
 * Type: RbTreeNodePair
 * Result structure for search functions.
 * members:
 *         RbTreeNode *parent - pointer to parent of insertion point.
 *         RbTreeNode *self   - pointer to existing node if found, or insertion
 * point. bool is_right      - true if new node should be right child of parent.
 * notes:
 *         Used by RbTreeSearch callback to return search results.
 *         If node exists, self points to it; parent is its parent.
 *         If node missing, self == NULL, parent/is_right indicate insertion
 * point.
 */
typedef struct {
	RbTreeNode *parent;
	RbTreeNode *self;
	bool is_right;
} RbTreeNodePair;

/*
 * Type: RbTree
 * Red-black tree container.
 * members:
 *         RbTreeNode *root - pointer to root node, or NULL if empty.
 * notes:
 *         Initialize with RBTREE_INIT or {NULL}.
 *         Thread-safe only with external synchronization.
 */
typedef struct {
	RbTreeNode *root;
} RbTree;

/*
 * Constant: RBTREE_INIT
 * Initializer for an empty RbTree.
 * notes:
 *         Use as: RbTree tree = RBTREE_INIT;
 */
static const RbTree RBTREE_INIT = {NULL};

/*
 * Type: RbTreeSearch
 * Callback function to search/compare nodes during insert/remove.
 * inputs:
 *         RbTreeNode *base  - pointer to existing node in tree.
 *         const RbTreeNode *value - pointer to node being inserted/removed.
 *         RbTreeNodePair *retval - pointer to store search result.
 * return value: i32 - <0 if value < base, 0 if equal, >0 if value > base.
 * errors: None.
 * notes:
 *         Must return consistent ordering for correct tree behavior.
 *         On equality (return 0), retval->self must point to base.
 *         On inequality, retval->parent and retval->is_right must indicate
 *         where value would be inserted.
 *         Example for u64 key:
 * i32 test_rbsearch(RbTreeNode *cur, const RbTreeNode *value,
 *                 RbTreeNodePair *retval) {
 *        while (cur) {
 *               u64 v1 = ((TestRbTreeNode *)cur)->value;
 *               u64 v2 = ((TestRbTreeNode *)value)->value;
 *               if (v1 == v2) {
 *                       retval->self = cur;
 *                       break;
 *               } else if (v1 < v2) {
 *                       retval->parent = cur;
 *                       retval->is_right = 1;
 *                       cur = cur->right;
 *               } else {
 *                       retval->parent = cur;
 *                       retval->is_right = 0;
 *                       cur = cur->left;
 *               }
 *               retval->self = cur;
 *        }
 *        return 0;
 * }
 */
typedef i32 (*RbTreeSearch)(RbTreeNode *base, const RbTreeNode *value,
			    RbTreeNodePair *retval);

/*
 * Function: rbtree_put
 * Inserts a node into the red-black tree.
 * inputs:
 *         RbTree *tree         - pointer to initialized tree.
 *         RbTreeNode *value    - pointer to node to insert.
 *         const RbTreeSearch search - comparison callback.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if tree, value, or search is null.
 *         EDUPLICATE     - if node with same key already exists.
 * notes:
 *         value must be part of a user-defined struct with RbTreeNode as first
 * member. If duplicate found, returns -1 and does not insert. Tree maintains
 * red-black properties automatically. O(log n) time complexity.
 */
i32 rbtree_put(RbTree *tree, RbTreeNode *value, const RbTreeSearch search);

/*
 * Function: rbtree_remove
 * Removes a node from the red-black tree.
 * inputs:
 *         RbTree *tree         - pointer to initialized tree.
 *         RbTreeNode *value    - pointer to node to remove (or key template).
 *         const RbTreeSearch search - comparison callback.
 * return value: RbTreeNode * - pointer to removed node, or NULL if not found.
 * errors: None.
 * notes:
 *         value may be a template (only key fields filled) if node not known.
 *         If found, node is removed and returned; caller must free if needed.
 *         If not found, returns NULL.
 *         Tree maintains red-black properties.
 *         O(log n) time complexity.
 */
RbTreeNode *rbtree_remove(RbTree *tree, RbTreeNode *value,
			  const RbTreeSearch search);

#endif /* _RBTREE_H */
