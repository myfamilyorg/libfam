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

#ifndef _TEST_BASE_H
#define _TEST_BASE_H

#include <libfam/colors.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#define MAX_TESTS 1024
#define MAX_TEST_NAME 128

void add_test_fn(void (*test_fn)(void), const u8 *name);
static __attribute__((unused)) const u8 *__assertion_msg =
    "\nassertion failed in test";

extern i32 exe_test;
typedef struct {
	void (*test_fn)(void);
	u8 name[MAX_TEST_NAME + 1];
} TestEntry;
extern TestEntry tests[];

#define Test(name)                                                         \
	void __test_##name(void);                                          \
	static void __attribute__((constructor)) __add_test_##name(void) { \
		add_test_fn(__test_##name, #name);                         \
	}                                                                  \
	void __test_##name(void)

#define ASSERT_EQ(x, y, msg)                                                 \
	do {                                                                 \
		if ((x) != (y)) {                                            \
			i32 __attribute((unused)) _v;                        \
			_v = pwrite(STDERR_FD, BRIGHT_RED,                   \
				    faststrlen(BRIGHT_RED), 0);              \
			_v = pwrite(STDERR_FD, __assertion_msg,              \
				    faststrlen(__assertion_msg), 0);         \
			_v = pwrite(STDERR_FD, RESET, faststrlen(RESET), 0); \
			_v = pwrite(STDERR_FD, ": [", 3, 0);                 \
			_v = pwrite(STDERR_FD, tests[exe_test].name,         \
				    faststrlen(tests[exe_test].name), 0);    \
			_v = pwrite(STDERR_FD, "]. '", 4, 0);                \
			_v = pwrite(STDERR_FD, msg, faststrlen(msg), 0);     \
			_v = pwrite(STDERR_FD, "'\n", 2, 0);                 \
			_exit(-1);                                           \
		}                                                            \
	} while (0);

#define ASSERT(x, msg)                                                       \
	do {                                                                 \
		if (!(x)) {                                                  \
			i32 __attribute((unused)) _v;                        \
			_v = pwrite(STDERR_FD, BRIGHT_RED,                   \
				    faststrlen(BRIGHT_RED), 0);              \
			_v = pwrite(STDERR_FD, __assertion_msg,              \
				    faststrlen(__assertion_msg), 0);         \
			_v = pwrite(STDERR_FD, RESET, faststrlen(RESET), 0); \
			_v = pwrite(STDERR_FD, ": [", 3, 0);                 \
			_v = pwrite(STDERR_FD, tests[exe_test].name,         \
				    faststrlen(tests[exe_test].name), 0);    \
			_v = pwrite(STDERR_FD, "]. '", 4, 0);                \
			_v = pwrite(STDERR_FD, msg, faststrlen(msg), 0);     \
			_v = pwrite(STDERR_FD, "'\n", 2, 0);                 \
			_exit(-1);                                           \
		}                                                            \
	} while (0);

#endif /* _TEST_BASE_H */
