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
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/utils.h>

STATIC const u8 *find_next_placeholder(const u8 *p) {
	while (true) {
		while (*p != '{')
			if (!*p++) return NULL;
		if (p[1] == '}' || (p[1] &&
				    (p[1] == 'X' || p[1] == 'x' ||
				     p[1] == 'c' || p[1] == 'b') &&
				    p[2] == '}'))
			return p;
		p++;
	}
}

STATIC i32 format_try_resize(Formatter *f, u64 len) {
	u64 needed = len + f->pos;
INIT:
	if (needed > f->capacity) {
		u64 to_alloc =
		    needed <= 8 ? 8 : 1UL << (64 - __builtin_clzl(needed));
		void *tmp = resize(f->buf, to_alloc);
		if (!tmp) ERROR();
		f->buf = tmp;
		f->capacity = to_alloc;
	}
CLEANUP:
	RETURN;
}

PUBLIC i32 format_append(Formatter *f, const u8 *fmt, ...) {
	u8 buf[MAX_I128_STRING_LEN];
	const u8 *p = fmt;
	__builtin_va_list args;
	u64 len;
	Printable next;
INIT:
	__builtin_va_start(args, fmt);
	while (*p != '\0') {
		const u8 *np = find_next_placeholder(p);
		if (np) {
			Int128DisplayType idt;
			bool is_char = false;
			if (np[1] == '}')
				idt = Int128DisplayTypeDecimal;
			else if (np[1] == 'b' && np[2] == '}')
				idt = Int128DisplayTypeBinary;
			else if (np[1] == 'X' && np[2] == '}')
				idt = Int128DisplayTypeHexUpper;
			else if (np[1] == 'c' && np[2] == '}')
				is_char = true;
			else if (np[1] == 'x' && np[2] == '}')
				idt = Int128DisplayTypeHexLower;

			len = np - p;
			if (format_try_resize(f, len) < 0) ERROR();
			memcpy(f->buf + f->pos, p, len);
			f->pos += len;

			next = __builtin_va_arg(args, Printable);
			if (is_char &&
			    (next.t == UIntType || next.t == IntType)) {
				if (format_try_resize(f, 1) < 0) ERROR();
				f->buf[f->pos++] = next.data.uvalue <= I8_MAX
						       ? next.data.uvalue
						       : '?';
			} else if (next.t == UIntType) {
				len =
				    u128_to_string(buf, next.data.uvalue, idt);
				if (format_try_resize(f, len) < 0) ERROR();
				memcpy(f->buf + f->pos, buf, len);
				f->pos += len;
			} else if (next.t == IntType) {
				len =
				    i128_to_string(buf, next.data.ivalue, idt);
				if (format_try_resize(f, len) < 0) ERROR();
				memcpy(f->buf + f->pos, buf, len);
				f->pos += len;
			} else if (next.t == StringType) {
				len = strlen(next.data.svalue);
				if (format_try_resize(f, len) < 0) ERROR();
				memcpy(f->buf + f->pos, next.data.svalue, len);
				f->pos += len;
			} else if (next.t == FloatType) {
				len = f64_to_string(buf, next.data.fvalue, 5);
				if (format_try_resize(f, len) < 0) ERROR();
				memcpy(f->buf + f->pos, buf, len);
				f->pos += len;
			}
			p = np + 2 + (np[1] != '}');
		} else {
			len = strlen(p);
			if (format_try_resize(f, len) < 0) ERROR();
			memcpy(f->buf + f->pos, p, len);
			f->pos += len;
			break;
		}
	}
CLEANUP:
	__builtin_va_end(args);
	RETURN;
}

PUBLIC void format_clear(Formatter *f) {
	release(f->buf);
	f->capacity = f->pos = 0;
	f->buf = NULL;
}

PUBLIC const u8 *format_to_string(Formatter *f) {
	if (format_try_resize(f, 1) < 0) return NULL;
	f->buf[f->pos++] = '\0';
	return f->buf;
}

