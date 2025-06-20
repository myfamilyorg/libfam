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

#include <alloc.H>
#include <format.H>
#include <misc.H>
#include <syscall.H>

static void reverse(u8* str, u64 len) {
	u64 i;
	u64 j;
	u8 tmp;

	for (i = 0, j = len - 1; i < j; i++, j--) {
		tmp = str[i];
		str[i] = str[j];
		str[j] = tmp;
	}
}

static u64 uint_to_str(u64 num, u8* buf, i32 base, i32 upper) {
	const u8* digits;
	u64 i;
	u64 temp;

	digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	i = 0;
	temp = num;

	do {
		buf[i++] = digits[temp % base];
		temp /= base;
	} while (temp);

	reverse(buf, i);
	return i;
}

static u64 int_to_str(i64 num, u8* buf, i32 base, i32 upper) {
	u64 i;
	i64 temp;

	i = 0;
	temp = num;

	if (temp < 0) {
		buf[i++] = '-';
		temp = -temp;
	}

	return i + uint_to_str((u64)temp, buf + i, base, upper);
}
static i32 vsnprintf(u8* str, u64 size, const u8* format,
		     __builtin_va_list ap) {
	const u8* fmt;
	u64 pos;
	u64 len;
	u8 buf[1024];
	u64 i;
	u64 j;
	i32 val;
	u32 uval;
	double dval;
	const u8* s;
	u8 c;

	pos = 0;
	len = 0;

	for (fmt = format; *fmt; fmt++) {
		if (*fmt != '%') {
			len++;
			if (str && pos < size) {
				str[pos++] = *fmt;
			}
			continue;
		}
		fmt++; /* Skip '%' */
		if (!*fmt) {
			len++;
			if (str && pos < size) {
				str[pos++] = '%';
			}
			break; /* Handle trailing % */
		}

		switch (*fmt) {
			case 'd':
			case 'i':
				val = __builtin_va_arg(ap, i64);
				j = int_to_str(val, buf, 10, 0);
				len += j;
				for (i = 0; i < j && str && pos < size; i++) {
					str[pos++] = buf[i];
				}
				break;
			case 'f':
				dval = __builtin_va_arg(ap, double);
				j = double_to_string(buf, dval, 5);
				len += j;
				for (i = 0; i < j && str && pos < size; i++) {
					str[pos++] = buf[i];
				}
				break;
			case 'u':
				uval = __builtin_va_arg(ap, u64);
				j = uint_to_str(uval, buf, 10, 0);
				len += j;
				for (i = 0; i < j && str && pos < size; i++) {
					str[pos++] = buf[i];
				}
				break;

			case 'x':
				uval = __builtin_va_arg(ap, u64);
				j = uint_to_str(uval, buf, 16, 0);
				len += j;
				for (i = 0; i < j && str && pos < size; i++) {
					str[pos++] = buf[i];
				}
				break;

			case 'X':
				uval = __builtin_va_arg(ap, u64);
				j = uint_to_str(uval, buf, 16, 1);
				len += j;
				for (i = 0; i < j && str && pos < size; i++) {
					str[pos++] = buf[i];
				}
				break;

			case 's':
				s = __builtin_va_arg(ap, const u8*);
				if (!s) {
					s = "(null)";
				}
				for (i = 0; s[i]; i++) {
					len++;
					if (str && pos < size) {
						str[pos++] = s[i];
					}
				}
				break;

			case 'c':
				c = (u8) __builtin_va_arg(ap, i32);
				len++;
				if (str && pos < size) {
					str[pos++] = c;
				}
				break;

			case '%':
				len++;
				if (str && pos < size) {
					str[pos++] = '%';
				}
				break;

			default:
				len++;
				if (str && pos < size) {
					str[pos++] = *fmt;
				}
				break;
		}
	}

	if (size > 0 && str) {
		if (pos + 1 < size) {
			str[pos++] = '\0';
		} else {
			str[size - 1] = '\0';
		}
	}

	return (i32)len;
}

/* snprintf implementation that takes variable arguments */
i32 snprintf(u8* str, u64 size, const u8* format, ...) {
	__builtin_va_list ap;
	i32 len;

	__builtin_va_start(ap, format);
	len = vsnprintf(str, size, format, ap);
	__builtin_va_end(ap);
	return len;
}

/* printf implementation */
i32 printf(const u8* format, ...) {
	__builtin_va_list ap, ap_copy;
	i32 len;
	u8* buf;

	__builtin_va_start(ap, format);
	__builtin_va_copy(ap_copy, ap);

	len = vsnprintf(NULL, 0, format, ap);
	if (len > 0) {
		buf = alloc(len + 1);

		if (buf == NULL)
			len = -1;
		else {
			len = vsnprintf(buf, len + 1, format, ap_copy);
			if (len > 0) write(1, buf, len);
			release(buf);
		}
	}

	__builtin_va_end(ap_copy);
	__builtin_va_end(ap);
	return len;
}

void panic(const u8* format, ...) {
	__builtin_va_list ap, ap_copy;
	i32 len;
	u8* buf;

	__builtin_va_start(ap, format);
	__builtin_va_copy(ap_copy, ap);

	len = vsnprintf(NULL, 0, format, ap);
	if (len > 0) {
		buf = alloc(len + 1);

		if (buf == NULL)
			len = -1;
		else {
			len = vsnprintf(buf, len + 1, format, ap_copy);
			if (len > 0) {
				write(2, "panic: ", 7);
				write(2, buf, len);
				write(2, "\n", 1);
			}
			release(buf);
		}
	}

	__builtin_va_end(ap_copy);
	__builtin_va_end(ap);
	exit(-1);
}
