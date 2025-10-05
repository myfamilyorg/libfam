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

typedef enum {
	FormatAlignLeft,
	FormatAlignRight,
} FormatAlignment;
typedef enum {
	FormatSpecTypeNone,
	FormatSpecTypeBinary,
	FormatSpecTypeHexUpper,
	FormatSpecTypeHexLower,
	FormatSpecTypeCommas,
	FormatSpecTypeChar,
	FormatSpecTypeEscapeBracketRight,
	FormatSpecTypeEscapeBracketLeft,
} FormatSpecType;

typedef struct {
	bool has_precision;
	u32 precision;
	bool has_width;
	u32 width;
	FormatAlignment align;
	FormatSpecType t;
	u32 total_bytes;
} FormatSpec;

STATIC i32 format_parse_spec(const u8 *p, FormatSpec *spec) {
	FormatSpec ret = {.t = FormatSpecTypeNone, .total_bytes = 2};
INIT:
	p++;
	while (*p) {
		if (*p == '.') {
			if (ret.has_precision) ERROR(EPROTO);
			ret.has_precision = true;
			p++;
			if (*p > '9' || *p < '0') ERROR(EPROTO);
			ret.precision = *p - '0';
			ret.total_bytes += 2;
			p++;
		} else if (*p == '{') {
			if (ret.has_precision || ret.has_width ||
			    ret.t != FormatSpecTypeNone)
				ERROR(EPROTO);
			ret.t = FormatSpecTypeEscapeBracketLeft;
			break;
		} else if (*p == ':') {
			if (ret.has_width) ERROR(EPROTO);
			ret.has_width = true;
			p++;
			ret.align = FormatAlignRight;
			if (*p == '<') {
				ret.align = FormatAlignLeft;
				p++;
				ret.total_bytes++;
			} else if (*p == '>') {
				ret.align = FormatAlignRight;
				p++;
				ret.total_bytes++;
			}

			ret.width = 0;

			while (*p >= '0' && *p <= '9') {
				ret.width = ret.width * 10 + (*p - '0');
				if (ret.width > 999) ERROR(EPROTO);
				p++;
				ret.total_bytes++;
			}
			ret.total_bytes++;
		} else if (*p == 'c') {
			if (ret.t != FormatSpecTypeNone) ERROR(EPROTO);
			ret.t = FormatSpecTypeChar;
			ret.total_bytes++;
			p++;
		} else if (*p == 'b') {
			if (ret.t != FormatSpecTypeNone) ERROR(EPROTO);
			ret.t = FormatSpecTypeBinary;
			ret.total_bytes++;
			p++;
		} else if (*p == 'X') {
			if (ret.t != FormatSpecTypeNone) ERROR(EPROTO);
			ret.t = FormatSpecTypeHexUpper;
			ret.total_bytes++;
			p++;
		} else if (*p == 'x') {
			if (ret.t != FormatSpecTypeNone) ERROR(EPROTO);
			ret.t = FormatSpecTypeHexLower;
			ret.total_bytes++;
			p++;
		} else if (*p == 'n') {
			if (ret.t != FormatSpecTypeNone) ERROR(EPROTO);
			ret.t = FormatSpecTypeCommas;
			ret.total_bytes++;
			p++;
		} else if (*p == '}') {
			break;
		} else
			ERROR(EPROTO);
	}
	*spec = ret;
CLEANUP:
	RETURN;
}

STATIC const u8 *find_next_placeholder(const u8 *p, FormatSpec *spec) {
	while (*p) {
		if (*p == '{') {
			if (format_parse_spec(p, spec) < 0) return NULL;
			return p;
		} else if (*p == '}' && p[1] == '}') {
			*spec =
			    (FormatSpec){.t = FormatSpecTypeEscapeBracketRight,
					 .total_bytes = 2};
			return p;
		}
		p++;
	}
	return NULL;
}

STATIC i32 format_try_resize(Formatter *f, u64 len) {
	u64 needed = len + f->pos;
INIT:
	if (needed > f->capacity) {
		u64 to_alloc = needed <= 8 ? 8 : 1UL << (64 - clz_u64(needed));
		void *tmp = resize(f->buf, to_alloc);
		if (!tmp) ERROR();
		f->buf = tmp;
		f->capacity = to_alloc;
	}
CLEANUP:
	RETURN;
}

STATIC Int128DisplayType format_get_displayType(const FormatSpec *spec) {
	if (spec->t == FormatSpecTypeNone)
		return Int128DisplayTypeDecimal;
	else if (spec->t == FormatSpecTypeBinary)
		return Int128DisplayTypeBinary;
	else if (spec->t == FormatSpecTypeHexUpper)
		return Int128DisplayTypeHexUpper;
	else if (spec->t == FormatSpecTypeCommas)
		return Int128DisplayTypeCommas;
	else
		return Int128DisplayTypeHexLower;
}

STATIC i32 format_proc_padding(Formatter *f, const FormatSpec *spec,
			       const u8 *value, u64 raw_bytes) {
	u64 aligned_bytes, i;
INIT:
	aligned_bytes = !spec->has_width	  ? raw_bytes
			: spec->width > raw_bytes ? spec->width
						  : raw_bytes;
	if (format_try_resize(f, aligned_bytes) < 0) ERROR();
	if (spec->align == FormatAlignRight)
		for (i = raw_bytes; i < aligned_bytes; i++)
			f->buf[f->pos++] = ' ';
	memcpy(f->buf + f->pos, value, raw_bytes);
	f->pos += raw_bytes;
	if (spec->align == FormatAlignLeft)
		for (i = raw_bytes; i < aligned_bytes; i++)
			f->buf[f->pos++] = ' ';

CLEANUP:
	RETURN;
}

STATIC i32 format_proc_uint(Formatter *f, const FormatSpec *spec, u128 value) {
	u8 buf[MAX_U128_STRING_LEN];
	Int128DisplayType idt = format_get_displayType(spec);
	u64 raw_bytes;
INIT:
	if (spec->t == FormatSpecTypeChar) {
		buf[0] = value <= I8_MAX ? value : '?';
		raw_bytes = 1;
	} else
		raw_bytes = u128_to_string(buf, value, idt);
	if (format_proc_padding(f, spec, buf, raw_bytes) < 0) ERROR();
CLEANUP:
	RETURN;
}

STATIC i32 format_proc_int(Formatter *f, const FormatSpec *spec, i128 value) {
	u8 buf[MAX_I128_STRING_LEN];
	Int128DisplayType idt = format_get_displayType(spec);
	u64 raw_bytes;
INIT:
	if (spec->t == FormatSpecTypeChar) {
		buf[0] = value <= I8_MAX ? value : '?';
		raw_bytes = 1;
	} else
		raw_bytes = i128_to_string(buf, value, idt);
	if (format_proc_padding(f, spec, buf, raw_bytes) < 0) ERROR();
CLEANUP:
	RETURN;
}

STATIC i32 format_proc_string(Formatter *f, const FormatSpec *spec,
			      const u8 *value) {
	return format_proc_padding(f, spec, value, strlen(value));
}

STATIC i32 format_proc_float(Formatter *f, const FormatSpec *spec, f64 value) {
	u8 buf[MAX_F64_STRING_LEN];
	u64 raw_bytes;
INIT:
	raw_bytes = f64_to_string(buf, value,
				  spec->has_precision ? spec->precision : 5);
	if (format_proc_padding(f, spec, buf, raw_bytes) < 0) ERROR();
CLEANUP:
	RETURN;
}
STATIC i32 format_proc_invalid(Formatter *f, const FormatSpec *spec) {
	return 0;
}

PUBLIC i32 format_append(Formatter *f, const u8 *p, ...) {
	__builtin_va_list args;
	FormatSpec spec;
	u64 len;
	Printable next;
INIT:
	__builtin_va_start(args, p);
	while (*p != '\0') {
		const u8 *np = find_next_placeholder(p, &spec);
		if (np) {
			len = np - p;
			if (format_try_resize(f, len) < 0) ERROR();
			memcpy(f->buf + f->pos, p, len);
			f->pos += len;
			if (spec.t == FormatSpecTypeEscapeBracketRight) {
				if (format_proc_string(f, &spec, "}") < 0)
					ERROR();

				p = np + spec.total_bytes;
				continue;
			} else if (spec.t == FormatSpecTypeEscapeBracketLeft) {
				if (format_proc_string(f, &spec, "{") < 0)
					ERROR();
				p = np + spec.total_bytes;
				continue;
			}
			next = __builtin_va_arg(args, Printable);
			if (next.t == UIntType) {
				u128 v = next.data.uvalue;
				if (format_proc_uint(f, &spec, v) < 0) ERROR();
			} else if (next.t == IntType) {
				i128 v = next.data.ivalue;
				if (format_proc_int(f, &spec, v) < 0) ERROR();
			} else if (next.t == StringType) {
				const u8 *s = next.data.svalue;
				if (format_proc_string(f, &spec, s) < 0)
					ERROR();
			} else if (next.t == FloatType) {
				f64 v = next.data.fvalue;
				if (format_proc_float(f, &spec, v) < 0) ERROR();
			} else {
				if (format_proc_invalid(f, &spec) < 0) ERROR();
			}
			p = np + spec.total_bytes;
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

