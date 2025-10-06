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

#include <libfam/compress.h>
#include <libfam/format.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/sysext.h>
#include <libfam/version.h>

i32 decompress_file(const u8 *f, bool console) {
	u8 *in, *out;
	u8 uncompressed[2048];
	u64 len = strlen(f), decomp_size;
	const u8 *index = f + len - 3;
	i32 fd, fd_out;
	i64 file_size, result;

	if (!f) {
		println("File '' not found!");
		return -1;
	}
	if (!exists(f)) {
		println("File '{}' not found!", f);
		return -1;
	}
	if (len < 3) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}
	if (strcmp(index, ".cz") != 0) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}

	if (len >= sizeof(uncompressed)) {
		println("Path '{}' is too long!", f);
		return -1;
	}

	memcpy(uncompressed, f, len - 3);
	uncompressed[len - 3] = 0;

	fd = file(f);
	file_size = fsize(fd);

	if (file_size < sizeof(i64)) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}

	in = fmap(fd, file_size, 0);
	if (!in) {
		println("Could not memory map file '{}'!", f);
		return -1;
	}

	memcpy(&decomp_size, in, sizeof(i64));
	if (console) {
		fd_out = 1;
		out = map(decomp_size);
		if (!out) {
			println("Could not create memory map!");
			return -1;
		}
		result = decompress(in + sizeof(i64), file_size - sizeof(i64),
				    out, decomp_size);

		if (result < 0) {
			println("Decompression failed: {}", strerror(errno));
			return -1;
		}

		u64 bytes_written = 0;
		while (bytes_written < decomp_size) {
			u64 written = write(fd_out, (u8 *)out + bytes_written,
					    decomp_size - bytes_written);
			if (written == -1) {
				println("Write failed: {}", strerror(errno));
				munmap(out, decomp_size);
				munmap(in, file_size);
				close(fd);
				return -1;
			}
			bytes_written += written;
		}

		close(fd);
		close(fd_out);
		munmap(in, file_size);
		munmap(out, decomp_size);

	} else {
		if (exists(uncompressed)) {
			println("File '{}', already exists!", uncompressed);
			return -1;
		}

		fd_out = file(uncompressed);
		if (fd_out < 0) {
			println("Could not open file '{}'!", uncompressed);
			return -1;
		}
		if (fresize(fd_out, decomp_size) < 0) {
			println("Could not resize file '{}'!", uncompressed);
			return -1;
		}
		out = fmap(fd_out, decomp_size, 0);
		if (!out) {
			println("Could not memory map file '{}'!",
				uncompressed);
			return -1;
		}

		result = decompress(in + sizeof(i64), file_size - sizeof(i64),
				    out, decomp_size);

		if (result < 0) {
			println("Decompression failed: {}", strerror(errno));
			return -1;
		}

		close(fd);
		close(fd_out);
		munmap(in, file_size);
		munmap(out, decomp_size);
		unlink(f);
	}

	return 0;
}

i32 compress_file(const u8 *f, bool console) {
	u8 compressed[2048] = {0};
	i32 fd, fd_out;
	i64 file_size, result;
	u8 *in, *out;
	u64 bound;

	if (!exists(f)) {
		println("File '{}' not found!", f);
		return -1;
	}
	fd = file(f);
	if (fd < 0) {
		println("Could not open file '{}'!", f);
		return -1;
	}
	file_size = fsize(fd);
	if (file_size < 0) {
		println("Could not change the size of file '{}'!", f);
		return -1;
	}

	in = fmap(fd, file_size, 0);
	if (!in) {
		println("Could not memory map file '{}'! ({})", f, file_size);
		return -1;
	}

	bound = compress_bound(file_size);

	if (console) {
		fd_out = 1;
		out = map(bound + sizeof(u64));
		if (!out) {
			println("Could not create memory map!");
			return -1;
		}
		result = compress(in, file_size, out + sizeof(i64), bound);
		if (result < 0) {
			println("Compression failed: {}", strerror(errno));
			return -1;
		}
		write(fd_out, &file_size, sizeof(i64));

		u64 bytes_written = 0;
		while (bytes_written < result) {
			u64 written = write(
			    fd_out, (u8 *)out + sizeof(i64) + bytes_written,
			    result - bytes_written);
			if (written == -1) {
				println("Write failed: {}", strerror(errno));
				munmap(out, bound + sizeof(i64));
				munmap(in, file_size);
				close(fd);
				return -1;
			}
			bytes_written += written;
		}

		close(fd);
		munmap(out, bound + sizeof(i64));
		munmap(in, file_size);

	} else {
		if (strlen(f) > sizeof(compressed) - strlen(".cz") - 1) {
			println("Path is too long '{}'", f);
			return -1;
		}
		strcpy(compressed, f);
		strcat(compressed, ".cz");

		if (exists(compressed)) {
			println("File '{}' already exists!", compressed);
			return -1;
		}

		fd_out = file(compressed);
		if (fresize(fd_out, bound + sizeof(i64)) < 0) {
			println("File resize failed: {}", strerror(errno));
			return -1;
		}
		out = fmap(fd_out, bound + sizeof(i64), 0);
		if (!out) {
			println("Could not memory map file '{}'!", compressed);
			return -1;
		}
		memcpy(out, &file_size, sizeof(i64));
		result = compress(in, file_size, out + sizeof(i64), bound);
		if (result < 0) {
			println("Compression failed: {}", strerror(errno));
			return -1;
		}
		munmap(out, bound + sizeof(i64));
		munmap(in, file_size);
		fresize(fd_out, result + sizeof(u64));
		close(fd_out);
		unlink(f);
	}

	return 0;
}

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

int main(int argc, u8 **argv, u8 **envp) {
	i32 i;
	bool decompress = false;
	bool console = false;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-V")) {
			println("czip {}", LIBFAM_VERSION);
			return 0;
		} else if (!strcmp(argv[i], "-d")) {
			decompress = true;
		} else if (!strcmp(argv[i], "-c")) {
			console = true;
		} else if (!strcmp(argv[i], "-dc") || !strcmp(argv[i], "-cd")) {
			console = true;
			decompress = true;
		}
	}
	if (argc < 2 || argc > 4) {
		println("Usage: czip [-dc] <file>");
		return -1;
	}

	if (!decompress)
		return compress_file(argv[argc - 1], console);
	else
		return decompress_file(argv[argc - 1], console);
}
