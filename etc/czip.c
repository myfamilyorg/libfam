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
#include <libfam/errno.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/main.h>
#include <libfam/string.h>
#include <libfam/sysext.h>
#include <libfam/version.h>

#define CZIP_VERSION 0
#define CHUNK_SIZE 61440
#define PAGE_SIZE 4096
#define MAX_PATH 1024

typedef struct {
	bool decompress;
	bool console;
	bool version;
	bool help;
	bool stack_only;
	const u8 *file;
	i32 return_value;
} CzipConfig;

typedef struct {
	u64 file_size;
	u64 mtime;
	u64 atime;
	u16 permissions;
	u16 czip_version;
} CzipFileHeader;

CzipConfig parse_argv(i32 argc, u8 **argv) {
	CzipConfig ret = {0};
	i32 i;
	for (i = 1; i < argc; i++) {
		u8 *arg = argv[i];
		if (*arg == '-') {
			arg++;
			if (*arg == '-') {
				arg++;
				if (!strcmp(arg, "decompress")) {
					ret.decompress = true;
				} else if (!strcmp(arg, "console")) {
					ret.console = true;
				} else if (!strcmp(arg, "stack_only")) {
					ret.stack_only = true;
				} else if (!strcmp(arg, "version")) {
					ret.version = true;
					return ret;
				} else if (!strcmp(arg, "help")) {
					ret.help = true;
					return ret;
				} else {
					println("Illegal option: {}", argv[i]);
					ret.help = true;
					ret.file = "";
					ret.return_value = -1;
					return ret;
				}
			} else if (*arg == '\0') {
				ret.file = "";
			} else {
				u8 ch;
				while ((ch = *arg++)) {
					if (ch == 'd')
						ret.decompress = true;
					else if (ch == 'c')
						ret.console = true;
					else if (ch == 'h')
						ret.help = true;
					else if (ch == 'v')
						ret.version = true;
					else if (ch == 's')
						ret.stack_only = true;
					else {
						println("Illegal option: {c}",
							ch);
						ret.help = true;
						ret.return_value = -1;
						ret.file = "";
						return ret;
					}
				}
			}
		} else {
			if (ret.file) {
				println("Error: Multiple files specified!");
				ret.help = true;
				ret.return_value = -1;
				return ret;
			}
			ret.file = arg;
		}
	}
	return ret;
}

void run_compressor(CzipConfig *config) {
	i32 infd, outfd;
	u64 offset = 0;
	i64 file_size, out_size;
	u8 output_file[MAX_PATH];
	u64 strlen_in_file = strlen(config->file);
	struct stat st;
	CzipFileHeader *header;

	if (strlen_in_file + 4 > MAX_PATH) {
		println("Specified filename '{}' is too long.", config->file);
		_exit(-1);
	}

	strncpy(output_file, config->file, strlen_in_file);
	output_file[strlen_in_file] = '.';
	output_file[strlen_in_file + 1] = 'c';
	output_file[strlen_in_file + 2] = 'z';
	output_file[strlen_in_file + 3] = 0;

	if (!exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_exit(-1);
	}

	if (exists(output_file)) {
		println("Output file '{}' already exists.", output_file);
		_exit(-1);
	}

	infd = file(config->file);
	if (infd < 0) {
		println("Could not open file '{}'.", config->file);
		_exit(-1);
	}

	file_size = fsize(infd);
	if (file_size < 0) {
		println("Could not obtain file size for file '{}'.",
			config->file);
		_exit(-1);
	}

	if (fstatat(AT_FDCWD, config->file, &st, 0) < 0) {
		println("Could not stat file '{}'.");
		_exit(-1);
	}

	outfd = file(output_file);
	if (outfd < 0) {
		println("Could not open file '{}'.", output_file);
		_exit(-1);
	}
	out_size = sizeof(CzipFileHeader);

	if (fresize(outfd, sizeof(CzipFileHeader)) < 0) {
		println("Could not resize output file due to: {}",
			strerror(errno));
		_exit(-1);
	}
	header = fmap(outfd, sizeof(CzipFileHeader), 0);
	if (!header) {
		println("fmap failed: {}", strerror(errno));
		_exit(-1);
	}
	header->file_size = file_size;
	header->mtime = st.st_mtime;
	header->atime = st.st_atime;
	header->permissions = st.st_mode & 0xFFF;
	header->czip_version = 0;
	munmap(header, sizeof(CzipFileHeader));

	while (offset < file_size) {
		u64 len = min(file_size - offset, CHUNK_SIZE);
		u64 bound = compress_bound(len);
		u8 *chunk = fmap(infd, len, offset);
		if (!chunk) {
			println("fmap failed: {}", strerror(errno));
			_exit(-1);
		}
		if (fresize(outfd, out_size + bound) < 0) {
			println(
			    "Could not resize output file due to: "
			    "{}.",
			    strerror(errno));
			_exit(-1);
		}
		u64 out_offset_aligned = PAGE_SIZE * (out_size / PAGE_SIZE);

		u8 *out =
		    fmap(outfd, sizeof(u32) + bound + out_size % PAGE_SIZE,
			 out_offset_aligned);
		out += sizeof(u32) + out_size % PAGE_SIZE;

		if (!out) {
			println("fmap failed: {}", strerror(errno));
			_exit(-1);
		}
		i32 res = compress16(chunk, len, out, bound);
		if (res < 0) {
			println("Compression error: {}.", strerror(errno));
			_exit(-1);
		}
		out -= sizeof(u32);
		memcpy(out, &res, sizeof(u32));
		out_size += res;
		munmap(chunk, len);
		munmap(out, bound);
		offset += len;
	}
	if (fresize(outfd, out_size) < 0) {
		println("Could not resize output file due to: {}",
			strerror(errno));
		_exit(-1);
	}
	close(infd);
	close(outfd);
}

void run_decompressor(CzipConfig *config) {
	CzipFileHeader *header;
	i64 file_size, offset;
	i32 infd, outfd;
	u8 output_file[MAX_PATH];
	u64 strlen_config_file;

	if (!exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_exit(-1);
	}

	strlen_config_file = strlen(config->file);

	if (strlen_config_file < 3) {
		println("Specified filename '{}' is too short.", config->file);
		_exit(-1);
	}
	if (strncmp(config->file + strlen_config_file - 3, ".cz", 3) != 0) {
		println("Specified filename '{}' is not a .cz file.",
			config->file);
		_exit(-1);
	}
	if (strlen_config_file > MAX_PATH - 4) {
		println("Specified filename '{}' is too long.", config->file);
		_exit(-1);
	}

	strncpy(output_file, config->file, strlen_config_file - 3);
	output_file[strlen_config_file - 3] = 0;
	if (exists(output_file)) {
		println("Specified filename '{}' already exists.", output_file);
		_exit(-1);
	}

	infd = file(config->file);
	if (infd < 0) {
		println("Could not open file '{}'.", config->file);
		_exit(-1);
	}

	file_size = fsize(infd);
	if (file_size < 0) {
		println("Could not obtain file size for file '{}'.",
			config->file);
		_exit(-1);
	}

	header = fmap(infd, PAGE_SIZE, 0);
	if (!header) {
		println("Could not fmap file '{}'.", config->file);
		_exit(-1);
	}
	println("ver={},size={},out={}", header->czip_version,
		header->file_size, output_file);
	offset = sizeof(CzipFileHeader);

	outfd = file(output_file);
	if (outfd < 0) {
		println("Could not open filename '{}'.", output_file);
		_exit(-1);
	}

	u64 out_size = 0;

	while (offset < file_size) {
		u64 offset_aligned = PAGE_SIZE * (offset / PAGE_SIZE);
		u8 *chunk = fmap(infd,
				 sizeof(u32) + compress_bound(CHUNK_SIZE) +
				     offset % PAGE_SIZE,
				 offset_aligned);
		if (!chunk) {
			println("fmap failed due to '{}'.", strerror(errno));
			_exit(-1);
		}

		chunk += (offset % PAGE_SIZE);
		u32 actual_size;
		memcpy(&actual_size, chunk, sizeof(u32));
		println("actual_size={}", actual_size);
		chunk += sizeof(u32);

		if (fresize(outfd, out_size + actual_size) < 0) {
			println(
			    "Could not resize output file due to: "
			    "{}.",
			    strerror(errno));
			_exit(-1);
		}

		u64 out_offset_aligned = PAGE_SIZE * (out_size / PAGE_SIZE);
		u8 *out = fmap(outfd, actual_size + out_size % PAGE_SIZE,
			       out_offset_aligned);
		if (!out) {
			println("fmap failed due to: {}.", strerror(errno));
			_exit(-1);
		}
		out += out_size % PAGE_SIZE;

		i64 advance = decompress16(chunk, actual_size, out, CHUNK_SIZE);

		munmap(chunk, actual_size + offset % PAGE_SIZE);

		println("offset={},offset_aligned={},map_len={},cs={},adv={}",
			offset, offset_aligned,
			compress_bound(CHUNK_SIZE) + offset % PAGE_SIZE,
			CHUNK_SIZE, advance);

		offset += actual_size;
		out_size += advance;
	}

	if (fresize(outfd, out_size) < 0) {
		println("Could not resize file '{}'.", output_file);
		_exit(-1);
	}

	close(infd);
	close(outfd);
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	CzipConfig config = parse_argv(argc, argv);

	if (config.version) {
		println("czip {}", LIBFAM_VERSION);
	} else if (config.help || !config.file) {
		if (!config.file) println("Error: No file was specified!");
		println("Usage: czip [OPTION]... [FILE]...");
		println(
		    "-c, --console       write to standard output, "
		    "keep files "
		    "unchanged");
		println("-d, --decompress    decompress");
		println("-h, --help          print this message");
		println("-v, --version       print version");
		println(
		    "-s, --stack_only    use only the stack (no heap "
		    "allocations)");
		println(
		    "\nNote: if '-' is specified stdin will be used as "
		    "the "
		    "input file.");
		return config.return_value;
	} else if (config.decompress) {
		run_decompressor(&config);
	} else {
		run_compressor(&config);
	}

	return 0;
}
