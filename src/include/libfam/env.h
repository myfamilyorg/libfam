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

#ifndef _ENV_H
#define _ENV_H

#include <libfam/types.h>

/*
 * Function: getenv
 * Retrieves the value of an environment variable.
 * inputs:
 *         const char *name - null-terminated name of the environment variable.
 * return value: char * - pointer to null-terminated value string, or NULL if
 *         not found. errors: None.
 * notes: name must not be null. Returned pointer is valid until next call to
 * program exit. Do not free or modify the returned string.
 * init_environ must have been called successfully before use. Case-sensitive.
 */
char *getenv(const char *name);

/*
 * Function: init_environ
 * Initializes the internal environment from the process startup envp array.
 * inputs:
 *         u8 **envp - pointer to the third argument of main() (char *envp[]).
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if envp is NULL or malformed.
 *         ENOMEM         - if memory allocation fails during parsing.
 * notes:
 *         Must be called once at program startup before any getenv calls.
 *         envp is the standard C runtime environment array (null-terminated).
 *         Parses and copies all NAME=VALUE pairs into internal storage.
 *         Idempotent: safe to call multiple times (subsequent calls are
 *         no-ops). On failure, getenv will always return NULL.
 */
i32 init_environ(u8 **envp);

#endif /* _ENV_H */
