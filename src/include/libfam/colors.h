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

#ifndef _COLORS_H
#define _COLORS_H

#include <libfam/types.h>

/*
 * Function: get_dimmed
 * Returns ANSI escape sequence for dimmed (faint) text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[2m".
 * errors: None.
 * notes:
 *         Use with println or similar: println("{}Hello{}", DIMMED, RESET);
 *         Safe to use even if terminal does not support ANSI.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_dimmed(void);
#define DIMMED get_dimmed()

/*
 * Function: get_red
 * Returns ANSI escape sequence for red text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[31m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Combine with RESET to restore default.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_red(void);
#define RED get_red()

/*
 * Function: get_bright_red
 * Returns ANSI escape sequence for bright red text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[91m".
 * errors: None.
 * notes:
 *         High-intensity foreground color.
 *         Use for emphasis or errors.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_bright_red(void);
#define BRIGHT_RED get_bright_red()

/*
 * Function: get_green
 * Returns ANSI escape sequence for green text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[32m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Often used for success messages.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_green(void);
#define GREEN get_green()

/*
 * Function: get_yellow
 * Returns ANSI escape sequence for yellow text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[33m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Use for warnings or highlights.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_yellow(void);
#define YELLOW get_yellow()

/*
 * Function: get_cyan
 * Returns ANSI escape sequence for cyan text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[36m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Often used for information or metadata.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_cyan(void);
#define CYAN get_cyan()

/*
 * Function: get_magenta
 * Returns ANSI escape sequence for magenta text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[35m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Use for special highlighting.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_magenta(void);
#define MAGENTA get_magenta()

/*
 * Function: get_blue
 * Returns ANSI escape sequence for blue text.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[34m".
 * errors: None.
 * notes:
 *         Standard foreground color.
 *         Use for links or neutral emphasis.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_blue(void);
#define BLUE get_blue()

/*
 * Function: get_reset
 * Returns ANSI escape sequence to reset all text attributes.
 * inputs: None.
 * return value: const u8 * - null-terminated string "\x1b[0m".
 * errors: None.
 * notes:
 *         Always pair with color codes to avoid persistent styling.
 *         Safe to use multiple times.
 *         Returned pointer is static and must not be freed.
 */
const u8 *get_reset(void);
#define RESET get_reset()

#endif /* _COLORS_H */
