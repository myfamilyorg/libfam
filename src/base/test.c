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

#include <libfam/builtin.h>
#include <libfam/debug.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/rbtree.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

typedef struct {
	RbTreeNode _reserved;
	u64 value;
} TestRbTreeNode;

i32 test_rbsearch(RbTreeNode *cur, const RbTreeNode *value,
		  RbTreeNodePair *retval) {
	while (cur) {
		u64 v1 = ((TestRbTreeNode *)cur)->value;
		u64 v2 = ((TestRbTreeNode *)value)->value;
		if (v1 == v2) {
			retval->self = cur;
			break;
		} else if (v1 < v2) {
			retval->parent = cur;
			retval->is_right = 1;
			cur = cur->right;
		} else {
			retval->parent = cur;
			retval->is_right = 0;
			cur = cur->left;
		}
		retval->self = cur;
	}
	return 0;
}

#define PARENT(node) ((RbTreeNode *)((u64)node->parent_color & ~0x1))
#define RIGHT(node) node->right
#define LEFT(node) node->left
#define ROOT(tree) (tree->root)
#define IS_RED(node) (node && ((u64)node->parent_color & 0x1))
#define IS_BLACK(node) !IS_RED(node)
#define ROOT(tree) (tree->root)

static bool check_root_black(RbTree *tree) {
	if (!ROOT(tree)) return true;
	return IS_BLACK(ROOT(tree));
}

static bool check_no_consecutive_red(RbTreeNode *node) {
	if (!node) return true;

	if (IS_RED(node)) {
		if (RIGHT(node) && IS_RED(RIGHT(node))) return false;
		if (LEFT(node) && IS_RED(LEFT(node))) return false;
	}

	return check_no_consecutive_red(LEFT(node)) &&
	       check_no_consecutive_red(RIGHT(node));
}

static i32 check_black_height(RbTreeNode *node) {
	i32 left_height, right_height;
	if (!node) return 1;
	left_height = check_black_height(LEFT(node));
	right_height = check_black_height(RIGHT(node));

	if (left_height == -1 || right_height == -1) return -1;

	if (left_height != right_height) return -1;

	return left_height + (IS_BLACK(node) ? 1 : 0);
}

static void validate_rbtree(RbTree *tree) {
	ASSERT(check_root_black(tree), "Root must be black");
	ASSERT(check_no_consecutive_red(ROOT(tree)),
	       "No consecutive red nodes");
	ASSERT(check_black_height(ROOT(tree)) != -1,
	       "Inconsistent black height");
}

Test(rbtree1) {
	RbTree tree = RBTREE_INIT;
	TestRbTreeNode v1 = {{0}, 1};
	TestRbTreeNode v2 = {{0}, 2};
	TestRbTreeNode v3 = {{0}, 3};
	TestRbTreeNode v4 = {{0}, 0};
	TestRbTreeNode vx = {{0}, 3};
	TestRbTreeNode vy = {{0}, 0};
	RbTreeNodePair retval = {0};

	rbtree_put(&tree, (RbTreeNode *)&v1, test_rbsearch);
	validate_rbtree(&tree);
	rbtree_put(&tree, (RbTreeNode *)&v2, test_rbsearch);
	validate_rbtree(&tree);

	test_rbsearch(tree.root, (RbTreeNode *)&v1, &retval);
	ASSERT_EQ(((TestRbTreeNode *)retval.self)->value, 1, "value=1");

	test_rbsearch(tree.root, (RbTreeNode *)&v2, &retval);
	ASSERT_EQ(((TestRbTreeNode *)retval.self)->value, 2, "value=2");
	test_rbsearch(tree.root, (RbTreeNode *)&v3, &retval);
	ASSERT_EQ(retval.self, NULL, "self=NULL");

	rbtree_remove(&tree, (RbTreeNode *)&v2, test_rbsearch);
	validate_rbtree(&tree);
	test_rbsearch(tree.root, (RbTreeNode *)&v2, &retval);
	ASSERT_EQ(retval.self, NULL, "retval=NULL2");
	rbtree_put(&tree, (RbTreeNode *)&v3, test_rbsearch);
	validate_rbtree(&tree);
	rbtree_put(&tree, (RbTreeNode *)&v4, test_rbsearch);
	validate_rbtree(&tree);

	ASSERT_EQ(rbtree_put(&tree, (RbTreeNode *)&vx, test_rbsearch), -1,
		  "duplicate");
	validate_rbtree(&tree);

	ASSERT_EQ(rbtree_put(&tree, (RbTreeNode *)&vy, test_rbsearch), -1,
		  "duplicate2");
	validate_rbtree(&tree);
}

#define SIZE 100

Test(rbtree2) {
	u64 size, i;
	u64 next = 101;

	for (size = 1; size < SIZE; size++) {
		RbTree tree = RBTREE_INIT;
		TestRbTreeNode values[SIZE];
		for (i = 0; i < size; i++) {
			values[i].value = (next++ * 37) % 1001;
			rbtree_put(&tree, (RbTreeNode *)&values[i],
				   test_rbsearch);
			validate_rbtree(&tree);
		}

		for (i = 0; i < size; i++) {
			RbTreeNodePair retval = {0};
			TestRbTreeNode v = {{0}, 0};
			v.value = values[i].value;

			test_rbsearch(tree.root, (RbTreeNode *)&v, &retval);
			ASSERT(retval.self != NULL, "retval=NULL");
			ASSERT_EQ(((TestRbTreeNode *)retval.self)->value,
				  values[i].value, "value=values[i].value");
		}

		for (i = 0; i < size; i++) {
			TestRbTreeNode v = {{0}, 0};
			v.value = values[i].value;
			rbtree_remove(&tree, (RbTreeNode *)&v, test_rbsearch);
			validate_rbtree(&tree);
		}
		ASSERT_EQ(tree.root, NULL, "root=NULL");
		validate_rbtree(&tree);
	}
}

Test(strcmp) {
	ASSERT(strcmp("abc", "def"), "abc!=def");
	ASSERT(!strcmp("abc", "abc"), "abc=abc");
}

Test(strncpy) {
	u8 x[1024] = {0};
	strncpy(x, "abcd", 3);
	ASSERT_EQ(x[0], 'a', "a");
	ASSERT_EQ(x[1], 'b', "b");
	ASSERT_EQ(x[2], 'c', "c");
	ASSERT_EQ(x[3], 0, "\0");
}

Test(f64_to_string) {
	u8 buf[64] = {0};
	u64 len;

	len = f64_to_string(buf, 0.3, 1, false);
	ASSERT_EQ(len, 3, "len=3");
	ASSERT(!strcmp(buf, "0.3"), "0.3");

	len = f64_to_string(buf, 0.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "nan"), "nan");
	ASSERT_EQ(len, 3, "nan_len");

	len = f64_to_string(buf, 1.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "inf"), "inf");
	ASSERT_EQ(len, 3, "inf_len");

	len = f64_to_string(buf, -1.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "-inf"), "neg_inf");
	ASSERT_EQ(len, 4, "neg_inf_len");

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Wliteral-range"
	len = f64_to_string(buf, 1.8e308, 6, false);
	ASSERT(!strcmp(buf, "inf"), "overflow_inf");
	ASSERT_EQ(len, 3, "overflow_inf_len");
#pragma GCC diagnostic pop

	len = f64_to_string(buf, 0.0, 6, false);
	ASSERT(!strcmp(buf, "0"), "zero");
	ASSERT_EQ(len, 1, "zero_len");
	len = f64_to_string(buf, -0.0, 6, false);
	ASSERT(!strcmp(buf, "0"), "neg_zero");
	ASSERT_EQ(len, 1, "neg_zero_len");

	len = f64_to_string(buf, 123.0, 0, false);
	ASSERT(!strcmp(buf, "123"), "int_pos");
	ASSERT_EQ(len, 3, "int_pos_len");

	len = f64_to_string(buf, -123.0, 0, false);
	ASSERT(!strcmp(buf, "-123"), "int_neg");

	ASSERT_EQ(len, 4, "int_neg_len");

	len = f64_to_string(buf, 123.456789, 6, false);
	ASSERT(!strcmp(buf, "123.456789"), "frac");
	ASSERT_EQ(len, 10, "frac_len");

	len = f64_to_string(buf, -123.456789, 6, false);
	ASSERT(!strcmp(buf, "-123.456789"), "neg_frac");
	ASSERT_EQ(len, 11, "neg_frac_len");

	len = f64_to_string(buf, 0.9999995, 6, false);
	ASSERT(!strcmp(buf, "1"), "round_up");
	ASSERT_EQ(len, 1, "round_up_len");

	len = f64_to_string(buf, 123.4000, 6, false);
	ASSERT(!strcmp(buf, "123.4"), "trim_zeros");
	ASSERT_EQ(len, 5, "trim_zeros_len");

	len = f64_to_string(buf, 123.0000001, 6, false);
	ASSERT(!strcmp(buf, "123"), "remove_decimal");
	ASSERT_EQ(len, 3, "remove_decimal_len");

	len = f64_to_string(buf, 123.456789123456789, 18, false);
	buf[len] = 0;
	ASSERT(!strcmp(buf, "123.45678912345678668"), "max_decimals");
	ASSERT_EQ(len, 21, "max_decimals_len");

	len = f64_to_string(buf, 123.456, -1, false);
	ASSERT(!strcmp(buf, "123"), "neg_decimals");
	ASSERT_EQ(len, 3, "neg_decimals_len");

	len = f64_to_string(buf, 9993234.334, 2, true);
	ASSERT(!strcmp(buf, "9,993,234.33"), "commas");
	ASSERT_EQ(strlen("9,993,234.33"), len, "commas len");
}

Test(limits) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Winteger-overflow"

	ASSERT(U8_MIN == 0, "U8_MIN should be 0");
	ASSERT(U16_MIN == 0, "U16_MIN should be 0");
	ASSERT(U32_MIN == 0, "U32_MIN should be 0");
	ASSERT(U64_MIN == 0, "U64_MIN should be 0");
	ASSERT(U128_MIN == 0, "U128_MIN should be 0");

	ASSERT(U8_MAX == 0xFF, "U8_MAX should be 255");
	ASSERT(U16_MAX == 0xFFFF, "U16_MAX should be 65535");
	ASSERT(U32_MAX == 0xFFFFFFFF, "U32_MAX should be 4294967295");
	ASSERT(U64_MAX == 0xFFFFFFFFFFFFFFFF,
	       "U64_MAX should be 18446744073709551615");
	u128 u128_max_expected =
	    ((u128)0xFFFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL;
	ASSERT(U128_MAX == u128_max_expected, "U128_MAX incorrect");

	ASSERT(I8_MAX == 0x7F, "I8_MAX should be 127");
	ASSERT(I16_MAX == 0x7FFF, "I16_MAX should be 32767");
	ASSERT(I32_MAX == 0x7FFFFFFF, "I32_MAX should be 2147483647");
	ASSERT(I64_MAX == 0x7FFFFFFFFFFFFFFF,
	       "I64_MAX should be 9223372036854775807");

	i128 i128_max_expected =
	    ((i128)(((i128)0x7FFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL));
	ASSERT(I128_MAX == i128_max_expected, "I128_MAX incorrect");

	ASSERT(I8_MIN == -128, "I8_MIN should be -128");
	ASSERT(I16_MIN == -32768, "I16_MIN should be -32768");
	ASSERT(I32_MIN == -2147483648, "I32_MIN should be -2147483648");
	ASSERT(I64_MIN == I64_MAX + 1,
	       "I64_MIN should be -9223372036854775808");

	i128 i128_min_expected =
	    ((i128)(((u128)0x8000000000000000UL << 64) | 0x0000000000000000UL));
	ASSERT(I128_MIN == i128_min_expected, "I128_MIN");

	ASSERT_EQ((u8)(U8_MAX + 1), U8_MIN, "overflow U8_MAX");
	ASSERT_EQ((u8)(U8_MIN - 1), U8_MAX, "underflow U8_MIN");
	ASSERT_EQ((u16)(U16_MAX + 1), U16_MIN, "overflow U16_MAX");
	ASSERT_EQ((u16)(U16_MIN - 1), U16_MAX, "underflow U16_MIN");
	ASSERT_EQ(U32_MAX + 1, U32_MIN, "overflow U32_MAX");
	ASSERT_EQ(U32_MIN - 1, U32_MAX, "underflow U32_MIN");
	ASSERT_EQ(U64_MAX + 1, U64_MIN, "overflow U64_MAX");
	ASSERT_EQ(U64_MIN - 1, U64_MAX, "underflow U64_MIN");
	ASSERT_EQ(U128_MAX + 1, U128_MIN, "overflow U128_MAX");
	ASSERT_EQ(U128_MIN - 1, U128_MAX, "underflow U128_MIN");
	ASSERT_EQ((i8)(I8_MAX + 1), I8_MIN, "overflow I8_MAX");
	ASSERT_EQ((i8)(I8_MIN - 1), I8_MAX, "underflow I8_MIN");
	ASSERT_EQ((i16)(I16_MAX + 1), I16_MIN, "overflow I16_MAX");
	ASSERT_EQ((i16)(I16_MIN - 1), I16_MAX, "underflow I16_MIN");
	ASSERT_EQ(I32_MAX + 1, I32_MIN, "overflow I32_MAX");
	ASSERT_EQ(I32_MIN - 1, I32_MAX, "underflow I32_MIN");
	ASSERT_EQ(I64_MAX + 1, I64_MIN, "overflow I64_MAX");
	ASSERT_EQ(I64_MIN - 1, I64_MAX, "underflow I64_MIN");
	ASSERT_EQ((i128)(I128_MAX + 1), I128_MIN, "overflow I128_MAX");
	ASSERT_EQ((i128)(I128_MIN - 1), I128_MAX, "underflow I128_MIN");
#pragma GCC diagnostic pop
}

Test(builtins) {
	ASSERT_EQ(clz_u64(0xFFUL), 64 - 8, "0xFFULL");
	ASSERT_EQ(clz_u64(0xFFFFUL), 64 - 16, "0xFFFFULL");
	ASSERT_EQ(clz_u32(0xFFFFFF), 32 - 24, "0xFFFFFF");
	ASSERT_EQ(clz_u32(0xFFFFFFFF), 0, "0xFFFFFFFF");
	ASSERT_EQ(ctz_u32(0xFFFF0), 4, "ctz 0xFFFF0");
	ASSERT_EQ(ctz_u64(0xFFFE0UL), 5, "ctz 0xFFFE0");
	ASSERT_EQ(clz_u128(0xFFFFFFFFFFUL), 128 - 40, "0xFFFFFFFFFFUL");
	ASSERT_EQ(clz_u128((u128)0x1 << 90), 128 - 90 - 1, "t1");
	ASSERT_EQ(clz_u128(0), 128, "clz_128(0)");
}

Test(string_chr_cat) {
	const char *in = "abcdefgh";
	ASSERT_EQ(strchr(in, 'c'), in + 2, "strchr");
	ASSERT_EQ(strchr(in, 'v'), NULL, "strchr miss");
	ASSERT_EQ(strchr(in, 0), in + strlen(in), "strchr strlen");
	u8 buf[1024] = {0};
	strcpy(buf, "abc");
	strcat(buf, "def");
	ASSERT(!strcmp(buf, "abcdef"), "buf");
}

Test(colors) {
	i32 __attribute__((unused)) _v;
	_debug_no_write = true;
	_v = write(STDERR_FD, RED, strlen(RED));
	_v = write(STDERR_FD, BRIGHT_RED, strlen(BRIGHT_RED));
	_v = write(STDERR_FD, MAGENTA, strlen(MAGENTA));
	_v = write(STDERR_FD, BLUE, strlen(BLUE));
	_debug_no_write = false;
}

i32 *__err_location(void);

Test(errors) {
	ASSERT(!strcmp("Success", strerror(0)), "success");
	ASSERT(!strcmp("Operation not permitted", strerror(EPERM)), "eperm");
	ASSERT(!strcmp("Interrupted system call", strerror(EINTR)), "eintr");
	ASSERT(!strcmp("Input/output error", strerror(EIO)), "eio");
	ASSERT(!strcmp("Bad file descriptor", strerror(EBADF)), "ebadf");
	ASSERT(!strcmp("Resource temporarily unavailable", strerror(EAGAIN)),
	       "eagain");
	ASSERT(!strcmp("Invalid argument", strerror(EINVAL)), "einval");
	ASSERT(!strcmp("Bad address", strerror(EFAULT)), "efault");
	ASSERT(!strcmp("Resource busy or locked", strerror(EBUSY)), "ebusy");
	ASSERT(!strcmp("No such file or directory", strerror(ENOENT)),
	       "enoent");
	ASSERT(!strcmp("No space left on device", strerror(ENOSPC)), "enospc");
	ASSERT(!strcmp("Broken pipe", strerror(EPIPE)), "epipe");
	ASSERT(!strcmp("Value too large for defined data type",
		       strerror(EOVERFLOW)),
	       "eoverflow");
	ASSERT(!strcmp("No child processes", strerror(ECHILD)), "echild");
	ASSERT(!strcmp("Duplicate entries", strerror(EDUPLICATE)),
	       "eduplicate");
	ASSERT(!strcmp("Out of memory", strerror(ENOMEM)), "enomem");
	ASSERT(!strcmp("Protocol error", strerror(EPROTO)), "eproto");
	ASSERT(!strcmp("todo/work in progress", strerror(ETODO)), "etodo");
	ASSERT(!strcmp("Unknown error", strerror(I32_MAX)), "unknown");
	ASSERT_EQ(*__err_location(), errno, "errno");
	_debug_no_write = true;
	perror("test");
	_debug_no_write = false;
}

Test(memmove) {
	const u8 *test = "test";
	const u8 *test2 = "aaaaa";
	u8 out[1024] = {0};

	ASSERT(memcmp(out, test, 4), "memcmp ne");
	memcpy(out, test, 4);
	ASSERT(!memcmp(out, test, 4), "memcmp eq");
	memmove(out, test2, 5);
	ASSERT(!memcmp(out, test2, 5), "memcmp eq");
	memcpy(out + 5, "bbbbbbbb", 8);
	memmove(out + 5, out, 8);
	ASSERT(!memcmp(out, "aaa", 3), "memmove cmp");
}

void __stack_chk_fail(void);
void __stack_chk_guard(void);

Test(stack_fails) {
	_debug_no_write = true;
	_debug_no_famexit = true;

	__stack_chk_fail();
	__stack_chk_guard();

	_debug_no_write = false;
	_debug_no_famexit = false;
}

Test(rand1) {
	u8 buf[128] = {0}, zero[128] = {0}, bigbuf[1024] = {0};
	ASSERT(!memcmp(buf, zero, sizeof(buf)), "equal");
	ASSERT_EQ(getrandom(buf, sizeof(buf), GRND_RANDOM), sizeof(buf),
		  "rand");
	ASSERT_EQ(getrandom(bigbuf, sizeof(bigbuf), GRND_RANDOM), -1, "rand");
	ASSERT(memcmp(buf, zero, sizeof(buf)), "not equal");
	ASSERT_EQ(gettimeofday(NULL, NULL), -1, "null gettimeofday");
}

