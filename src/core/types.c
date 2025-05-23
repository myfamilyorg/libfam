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

#include <error.h>
#include <misc.h>
#include <sys.h>
#include <types.h>

static int write_u64(int fd, uint64_t value) {
	char buffer[20];
	int len = 0;
	int i, j;

	if (value == 0) {
		buffer[0] = '0';
		len = 1;
	} else {
		while (value > 0) {
			if (len >= 20) {
				err = EOVERFLOW;
				return -1;
			}
			buffer[len++] = '0' + (value % 10);
			value /= 10;
		}
	}

	for (i = 0, j = len - 1; i < j; i++, j--) {
		char temp = buffer[i];
		buffer[i] = buffer[j];
		buffer[j] = temp;
	}

	ssize_t bytes_written = write(fd, buffer, len);
	if (bytes_written == -1) return -1;
	if (bytes_written != len) {
		err = EIO;
		return -1;
	}

	return 0;
}

#define CheckType(t, exp)                             \
	if (sizeof(t) != exp) {                       \
		const char *msg = "expected sizeof("; \
		write(2, msg, strlen(msg));           \
		write(2, #t, strlen(#t));             \
		write(2, ") == ", 5);                 \
		write_u64(2, exp);                    \
		write(2, ", Found ", 8);              \
		write_u64(2, sizeof(t));              \
		write(2, "\n", 1);                    \
		exit(-1);                             \
	}

#define CheckEndian()                                                          \
	uint16_t test = 0x1234;                                                \
	uint8_t *bytes = (uint8_t *)&test;                                     \
	if (bytes[0] != 0x34) {                                                \
		const char *msg = "Error: Big-endian systems not supported\n"; \
		write(2, msg, strlen(msg));                                    \
		exit(-1);                                                      \
	}

static __attribute__((constructor)) void check_sizes(void) {
	CheckEndian();
	CheckType(uint8_t, 1);
	CheckType(int8_t, 1);
	CheckType(uint16_t, 2);
	CheckType(int16_t, 2);
	CheckType(uint32_t, 4);
	CheckType(int32_t, 4);
	CheckType(uint64_t, 8);
	CheckType(int64_t, 8);
	CheckType(uint128_t, 16);
	CheckType(int128_t, 16);
	CheckType(byte, 1);
	CheckType(unsigned long, 8);
	CheckType(size_t, 8);
	CheckType(ssize_t, 8);

	const char *bool_err = "expected true to be true\n";
	if (!true) {
		write(2, bool_err, strlen(bool_err));
		exit(-1);
	}
	if (false) {
		write(2, bool_err, strlen(bool_err));
		exit(-1);
	}
	if (!true) {
		write(2, bool_err, strlen(bool_err));
		exit(-1);
	}
}

