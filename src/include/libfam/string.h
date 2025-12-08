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

#ifndef _LFAM_STRING_H
#define _LFAM_STRING_H

#include <libfam/types.h>

/*
 * Constant: MAX_U128_STRING_LEN
 * Maximum buffer size for u128 string conversion (255 bytes).
 * notes:
 *         Covers maximum decimal digits for 2^128 - 1 (39 digits) + commas +
 * null.
 */
#define MAX_U128_STRING_LEN 255

/*
 * Constant: MAX_I128_STRING_LEN
 * Maximum buffer size for i128 string conversion (256 bytes).
 * notes:
 *         One extra byte for negative sign.
 */
#define MAX_I128_STRING_LEN (MAX_U128_STRING_LEN + 1)

/*
 * Constant: MAX_F64_STRING_LEN
 * Maximum buffer size for f64 string conversion (64 bytes).
 * notes:
 *         Covers full precision + commas + sign + null.
 */
#define MAX_F64_STRING_LEN 64

/*
 * Enum: Int128DisplayType
 * Formatting options for 128-bit integer conversion.
 * values:
 *         Int128DisplayTypeDecimal     - decimal (e.g., 123456789)
 *         Int128DisplayTypeHexUpper    - uppercase hex (e.g., 0x1A2B3C)
 *         Int128DisplayTypeHexLower    - lowercase hex (e.g., 0x1a2b3c)
 *         Int128DisplayTypeBinary      - binary (e.g., 0b1010)
 *         Int128DisplayTypeCommas      - decimal with comma separators
 * notes:
 *         Used by i128_to_string and u128_to_string.
 */
typedef enum {
	Int128DisplayTypeDecimal,
	Int128DisplayTypeHexUpper,
	Int128DisplayTypeHexLower,
	Int128DisplayTypeBinary,
	Int128DisplayTypeCommas,
} Int128DisplayType;

/*
 * Function: strlen
 * Returns the length of a null-terminated string.
 * inputs:
 *         const char *msg - pointer to string.
 * return value: u64 - number of bytes excluding null terminator.
 * errors: None.
 * notes:
 *         msg must not be null and must be null-terminated.
 *         Returns 0 if msg is null or empty.
 */
u64 strlen(const char *msg);

/*
 * Function: strncmp
 * Compares up to n bytes of two strings.
 * inputs:
 *         const char *x - first string.
 *         const char *y - second string.
 *         u64 n        - maximum bytes to compare.
 * return value: i32 - <0 if x < y, 0 if equal, >0 if x > y.
 * errors: None.
 * notes:
 *         x and y must not be null.
 *         Stops at null terminator or n bytes.
 */
i32 strncmp(const char *x, const char *y, u64 n);

/*
 * Function: strcpy
 * Copies a null-terminated string.
 * inputs:
 *         char *dest       - destination buffer.
 *         const char *src  - source string.
 * return value: char * - pointer to dest.
 * errors: None.
 * notes:
 *         dest must have space for strlen(src) + 1 bytes.
 *         src must be null-terminated.
 *         Overlapping buffers result in undefined behavior.
 */
char *strcpy(char *dest, const char *src);

/*
 * Function: strncpy
 * Copies up to n bytes of a string.
 * inputs:
 *         char *dst        - destination buffer.
 *         const char *src  - source string.
 *         u64 n            - maximum bytes to copy.
 * return value: char * - pointer to dst.
 * errors: None.
 * notes:
 *         dst must have space for n bytes.
 *         If src is shorter than n, pads with null bytes.
 *         If src is longer, truncates and does *not* null-terminate.
 *         Use with caution — prefer strlcpy if available.
 */
char *strncpy(char *dst, const char *src, u64 n);

/*
 * Function: strcmp
 * Compares two null-terminated strings.
 * inputs:
 *         const char *x - first string.
 *         const char *y - second string.
 * return value: i32 - <0 if x < y, 0 if equal, >0 if x > y.
 * errors: None.
 * notes:
 *         x and y must not be null and must be null-terminated.
 */
i32 strcmp(const char *x, const char *y);

/*
 * Function: strstr
 * Locates a substring.
 * inputs:
 *         const char *s   - haystack string.
 *         const char *sub - needle string.
 * return value: char * - pointer to first occurrence, or NULL if not found.
 * errors: None.
 * notes:
 *         s and sub must be null-terminated.
 *         Returns s if sub is empty.
 */
char *strstr(const char *s, const char *sub);

/*
 * Function: strcat
 * Concatenates two strings.
 * inputs:
 *         char *dest       - destination buffer (must be null-terminated).
 *         const char *src  - source string.
 * return value: char * - pointer to dest.
 * errors: None.
 * notes:
 *         dest must have space for strlen(dest) + strlen(src) + 1.
 *         Overwrites dest's null terminator.
 */
char *strcat(char *dest, const char *src);

/*
 * Function: strchr
 * Finds first occurrence of a character in a string.
 * inputs:
 *         const char *s - string to search.
 *         i32 c         - character to find (as int).
 * return value: char * - pointer to first occurrence, or NULL if not found.
 * errors: None.
 * notes:
 *         s must be null-terminated.
 *         c is masked to 8 bits.
 */
char *strchr(const char *s, i32 c);

/*
 * Function: memset
 * Fills memory with a byte value.
 * inputs:
 *         void *ptr  - destination memory.
 *         i32 x      - byte value to fill (as int).
 *         u64 n      - number of bytes to fill.
 * return value: void * - pointer to ptr.
 * errors: None.
 * notes:
 *         ptr must not be null if n > 0.
 *         x is masked to 8 bits.
 */
void *memset(void *ptr, i32 x, u64 n);

/*
 * Function: memcpy
 * Copies memory.
 * inputs:
 *         void *dst        - destination.
 *         const void *src  - source.
 *         u64 n            - number of bytes to copy.
 * return value: void * - pointer to dst.
 * errors: None.
 * notes:
 *         dst and src must not overlap.
 *         dst and src must be valid for n bytes.
 */
void *memcpy(void *dst, const void *src, u64 n);

/*
 * Function: memmove
 * Copies memory (handles overlap).
 * inputs:
 *         void *dst        - destination.
 *         const void *src  - source.
 *         u64 n            - number of bytes to copy.
 * return value: void * - pointer to dst.
 * errors: None.
 * notes:
 *         dst and src may overlap.
 *         dst and src must be valid for n bytes.
 */
void *memmove(void *dst, const void *src, u64 n);

/*
 * Function: memcmp
 * Compares memory.
 * inputs:
 *         const void *s1 - first buffer.
 *         const void *s2 - second buffer.
 *         u64 n          - number of bytes to compare.
 * return value: i32 - <0 if s1 < s2, 0 if equal, >0 if s1 > s2.
 * errors: None.
 * notes:
 *         s1 and s2 must be valid for n bytes.
 */
i32 memcmp(const void *s1, const void *s2, u64 n);

/*
 * Function: f64_to_string
 * Converts a double to a string.
 * inputs:
 *         u8 buf[MAX_F64_STRING_LEN] - output buffer.
 *         f64 v                      - value to convert.
 *         i32 max_decimals           - maximum decimal places (0–15).
 *         bool commas                - insert comma separators.
 * return value: u8 - number of bytes written (excluding null).
 * errors: None.
 * notes:
 *         buf must have at least MAX_F64_STRING_LEN bytes.
 *         Always null-terminates.
 *         max_decimals is clamped to [0, 15].
 *         Commas inserted every 3 digits in integer part.
 */
u8 f64_to_string(u8 buf[MAX_F64_STRING_LEN], f64 v, i32 max_decimals,
		 bool commas);

/*
 * Function: string_to_u128
 * Parses an unsigned 128-bit integer from a string.
 * inputs:
 *         const u8 *buf  - input string.
 *         u64 len        - length of string (excluding null).
 *         u128 *result   - pointer to store parsed value.
 * return value: i32 - 0 on success, -1 on error.
 * errors:
 *         EINVAL         - if overflow or invalid digit.
 * notes:
 *         buf must contain only digits (0–9).
 *         Leading zeros allowed.
 *         result is set on success.
 */
i32 string_to_u128(const u8 *buf, u64 len, u128 *result);

/*
 * Function: i128_to_string
 * Converts a signed 128-bit integer to a string.
 * inputs:
 *         u8 buf[MAX_I128_STRING_LEN] - output buffer.
 *         i128 value                  - value to convert.
 *         Int128DisplayType t         - display format.
 * return value: u8 - number of bytes written (excluding null).
 * errors: None.
 * notes:
 *         buf must have at least MAX_I128_STRING_LEN bytes.
 *         Always null-terminates.
 *         Negative sign added for Int128DisplayTypeDecimal.
 *         Prefix: 0x for hex, 0b for binary.
 */
u8 i128_to_string(u8 buf[MAX_I128_STRING_LEN], i128 value, Int128DisplayType t);

/*
 * Function: u128_to_string
 * Converts an unsigned 128-bit integer to a string.
 * inputs:
 *         u8 buf[MAX_U128_STRING_LEN] - output buffer.
 *         u128 value                  - value to convert.
 *         Int128DisplayType t         - display format.
 * return value: u8 - number of bytes written (excluding null).
 * errors: None.
 * notes:
 *         buf must have at least MAX_U128_STRING_LEN bytes.
 *         Always null-terminates.
 *         Prefix: 0x for hex, 0b for binary.
 *         Commas every 3 digits for Int128DisplayTypeCommas.
 */
u8 u128_to_string(u8 buf[MAX_U128_STRING_LEN], u128 value, Int128DisplayType t);

/*
 * Macro to call builtin memcpy/memmove
 */
#define fastmemcpy(dst, src, n) __builtin_memcpy((dst), (src), (n))
#define fastmemmove(dst, src, n) __builtin_memmove((dst), (src), (n))
#define fastmemset(dst, v, n) __builtin_memset((dst), (v), (n))
__attribute__((unused, noinline)) static void secure_zero(void *ptr, u64 len) {
	volatile u8 *p = (volatile u8 *)ptr;
	while (len--) {
		*p++ = 0;
	}
}

#endif /* _LFAM_STRING_H */
