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

#ifndef _TEST_H
#define _TEST_H

#include <libfam/colors.h>
#include <libfam/format.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#define MAX_TESTS 1024
#define MAX_TEST_NAME 128

void add_test_fn(void (*test_fn)(void), const u8 *name);
void add_bench_fn(void (*bench_fn)(void), const u8 *name);
i64 write_num(i32 fd, u64 num);
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

#define Bench(name)                                                         \
	void __bench_##name(void);                                          \
	static void __attribute__((constructor)) __add_bench_##name(void) { \
		add_bench_fn(__bench_##name, #name);                        \
	}                                                                   \
	void __bench_##name(void)

#define ASSERT_EQ(x, y, ...)                                                  \
	({                                                                    \
		if ((x) != (y)) {                                             \
			Formatter fmt = FORMATTER_INIT;                       \
			__VA_OPT__(FORMAT(&fmt, __VA_ARGS__);)                \
			println("{}{}{}: [{}]. '{}'", BRIGHT_RED,             \
				__assertion_msg, RESET, tests[exe_test].name, \
				format_to_string(&fmt));                      \
			_exit(-1);                                            \
		}                                                             \
	})

#define ASSERT(x, ...)                                                        \
	({                                                                    \
		if (!(x)) {                                                   \
			Formatter fmt = FORMATTER_INIT;                       \
			__VA_OPT__(FORMAT(&fmt, __VA_ARGS__);)                \
			println("{}{}{}: [{}]. '{}'", BRIGHT_RED,             \
				__assertion_msg, RESET, tests[exe_test].name, \
				format_to_string(&fmt));                      \
			_exit(-1);                                            \
		}                                                             \
	})

#ifdef COVERAGE
#define ASSERT_BYTES(v)
#define ASSERT_NOT_BYTES_0(v)
#else
#define ASSERT_BYTES(v)                                                       \
	({                                                                    \
		u64 _b__ = allocated_bytes();                                 \
		if (_b__ != (v)) print("expected b={}. found b={}", v, _b__); \
		ASSERT_EQ(_b__, (v), "ASSERT_BYTES");                         \
	})
#define ASSERT_NOT_BYTES_0()                                           \
	({                                                             \
		u64 _b__ = allocated_bytes();                          \
		if (!_b__) println("expected b!=0, found b={}", _b__); \
		ASSERT(_b__, "ASSERT_NOT_BYTES_0");                    \
	})
#endif /* !COVERAGE */

#endif /* _TEST_H */
