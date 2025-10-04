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

#include <libfam/env.h>
#include <libfam/errno.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>
#include <libfam/types.h>
#include <libfam/utils.h>

const u8 *SPACER =
    "------------------------------------------------------------------"
    "--------------------------\n";

i32 cur_tests = 0;
i32 exe_test = 0;

TestEntry tests[MAX_TESTS];

void add_test_fn(void (*test_fn)(void), const u8 *name) {
	if (strlen(name) > MAX_TEST_NAME) {
		const u8 *msg = "test name too long!\n";
		write(STDERR_FD, msg, strlen(msg));
		_exit(-1);
	}
	if (cur_tests >= MAX_TESTS) {
		const u8 *msg = "too many tests!";
		write(STDERR_FD, msg, strlen(msg));
		_exit(-1);
	}
	tests[cur_tests].test_fn = test_fn;
	memset(tests[cur_tests].name, 0, MAX_TEST_NAME);
	strcpy(tests[cur_tests].name, name);
	cur_tests++;
}

#ifndef COVERAGE
#ifdef __aarch64__
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    ldr x0, [sp]\n"
    "    add x1, sp, #8\n"
    "    add x3, x0, #1\n"
    "    lsl x3, x3, #3\n"
    "    add x2, x1, x3\n"
    "    sub sp, sp, x3\n"
    "    bl main\n"
    "    mov x8, #93\n"
    "    svc #0\n");
#elif defined(__x86_64__)
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    movq (%rsp), %rdi\n"
    "    lea 8(%rsp), %rsi\n"
    "    mov %rdi, %rcx\n"
    "    add $1, %rcx\n"
    "    shl $3, %rcx\n"
    "    lea (%rsi, %rcx), %rdx\n"
    "    mov %rsp, %rcx\n"
    "    and $-16, %rsp\n"
    "    call main\n"
    "    mov %rax, %rdi\n"
    "    mov $60, %rax\n"
    "    syscall\n");
#endif /* __x86_64__ */
#endif /* COVERAGE */

i32 main(i32 argc, u8 **argv, u8 **envp) {
	u8 *pattern;
	u64 total, len, test_count = 0;
	f64 ms;
	u8 buf[64];

	(void)argc;
	(void)argv;

	if (init_environ(envp) < 0) {
		perror("init_environ");
		const u8 *msg = "Too many environment variables!\n";
		write(STDERR_FD, msg, strlen(msg));
		_exit(-1);
	}

	pattern = getenv("TEST_PATTERN");

	write(STDERR_FD, CYAN, strlen(CYAN));
	if (!pattern || !strcmp(pattern, "*")) {
		write(STDERR_FD, "Running ", strlen("Running "));
		write_num(STDERR_FD, cur_tests);
		write(STDERR_FD, " tests", strlen(" tests"));
		write(STDERR_FD, RESET, strlen(RESET));
		write(STDERR_FD, "...\n", 4);
	} else {
		write(STDERR_FD, "Running test", strlen("Running test"));
		write(STDERR_FD, RESET, strlen(RESET));
		write(STDERR_FD, ": '", 3);
		write(STDERR_FD, pattern, strlen(pattern));
		write(STDERR_FD, "' ...\n", 6);
	}

	write(STDERR_FD, SPACER, strlen(SPACER));

	total = micros();

	for (exe_test = 0; exe_test < cur_tests; exe_test++) {
		if (!pattern || !strcmp(pattern, "*") ||
		    !strcmp(pattern, tests[exe_test].name)) {
			i64 start = micros();
			write(STDERR_FD, YELLOW, strlen(YELLOW));
			write(STDERR_FD, "Running test",
			      strlen("Running test"));
			write(STDERR_FD, RESET, strlen(RESET));
			write(STDERR_FD, " ", 1);
			write_num(STDERR_FD, ++test_count);
			write(STDERR_FD, " [", 2);
			write(STDERR_FD, DIMMED, strlen(DIMMED));
			write(STDERR_FD, tests[exe_test].name,
			      strlen(tests[exe_test].name));
			write(STDERR_FD, RESET, strlen(RESET));

			write(STDERR_FD, "] ", 2);

			tests[exe_test].test_fn();

			write(STDERR_FD, GREEN, strlen(GREEN));
			write(STDERR_FD, "[", 1);
			write_num(STDERR_FD, (i64)(micros() - start));
			write(STDERR_FD, "µs", strlen("µs"));
			write(STDERR_FD, "]\n", 2);
			write(STDERR_FD, RESET, strlen(RESET));
		}
	}

	ms = (f64)(micros() - total) / (f64)1000;
	len = f64_to_string(buf, ms, 3);
	buf[len] = 0;

	write(STDERR_FD, SPACER, strlen(SPACER));

	write(STDERR_FD, GREEN, strlen(GREEN));
	write(STDERR_FD, "Success", strlen("Success"));
	write(STDERR_FD, RESET, strlen(RESET));
	write(STDERR_FD, "! ", 2);
	write_num(STDERR_FD, test_count);
	write(STDERR_FD, " ", 1);
	write(STDERR_FD, CYAN, strlen(CYAN));
	write(STDERR_FD, "tests passed!", strlen("tests passed!"));
	write(STDERR_FD, RESET, strlen(RESET));
	write(STDERR_FD, GREEN, strlen(GREEN));
	write(STDERR_FD, " [", 2);
	write(STDERR_FD, buf, strlen(buf));
	write(STDERR_FD, " ms]\n", 5);
	write(STDERR_FD, RESET, strlen(RESET));

	_exit(0);
	return 0;
}
