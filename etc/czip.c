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
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/sysext.h>
#include <libfam/version.h>

#define CZIP_VERSION 0
#define CHUNK_SIZE (1 << 18)
#define PAGE_SIZE 4096
#define MAX_PATH 1024

typedef struct {
	bool decompress;
	bool console;
	bool version;
	bool help;
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

void do_compress(const CzipFileHeader *header, i32 in_fd, i32 out_fd) {
	if (compress_file(in_fd, out_fd, NULL) < 0) {
		println("Could not compress stream!");
		_famexit(-1);
	}
}

void do_decompress(const CzipFileHeader *header, i32 in_fd, i32 out_fd,
		   u64 in_file_size) {
	if (decompress_file(in_fd, out_fd) < 0) {
		println("Could not decompress stream!");
		_famexit(-1);
	}
}

void run_compressor(CzipConfig *config) {
	i32 infd, outfd;
	u8 output_file[MAX_PATH];
	u64 file_size;
	u64 strlen_in_file;
	struct stat st;
	CzipFileHeader header;

	strlen_in_file = config->file ? strlen(config->file) : 0;

	if (strlen_in_file + 4 > MAX_PATH) {
		println("Specified filename '{}' is too long.", config->file);
		_famexit(-1);
	}

	if (strlen_in_file && !exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_famexit(-1);
	}

	if (exists(output_file)) {
		println("Output file '{}' already exists.", output_file);
		_famexit(-1);
	}

	if (!strlen_in_file) {
		infd = 0;
	} else
		infd = file(config->file);
	if (infd < 0) {
		println("Could not open file '{}'.", config->file);
		_famexit(-1);
	}

	if (strlen_in_file) {
		file_size = fsize(infd);
		if (file_size < 0) {
			println("Could not obtain file size for file '{}'.",
				config->file);
			_famexit(-1);
		}

		if (fstatat(AT_FDCWD, config->file, &st, 0) < 0) {
			println("Could not stat file '{}'.");
			_famexit(-1);
		}
	}

	if (config->console) {
		outfd = STDOUT_FD;
	} else {
		strncpy(output_file, config->file, strlen_in_file);
		output_file[strlen_in_file] = '.';
		output_file[strlen_in_file + 1] = 'c';
		output_file[strlen_in_file + 2] = 'z';
		output_file[strlen_in_file + 3] = 0;

		outfd = file(output_file);
		if (outfd < 0) {
			println("Could not open file '{}'.", output_file);
			_famexit(-1);
		}
	}

	if (strlen_in_file) {
		header.file_size = file_size;
		header.mtime = st.st_mtime;
		header.atime = st.st_atime;
		header.permissions = st.st_mode & 0xFFF;
		header.czip_version = 0;
	} else {
		header.mtime = 0;
		header.atime = 0;
		header.permissions = 0644;
	}

	do_compress(&header, infd, outfd);

	close(infd);
	if (!config->console) {
		close(outfd);
		unlink(config->file);
	}
}

void run_decompressor(CzipConfig *config) {
	CzipFileHeader *header;
	i64 file_size;
	i32 infd, outfd;
	u8 output_file[MAX_PATH];
	u64 strlen_config_file;

	if (!exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_famexit(-1);
	}

	strlen_config_file = strlen(config->file);

	if (strlen_config_file < 3) {
		println("Specified filename '{}' is too short.", config->file);
		_famexit(-1);
	}
	if (strncmp(config->file + strlen_config_file - 3, ".cz", 3) != 0) {
		println("Specified filename '{}' is not a .cz file.",
			config->file);
		_famexit(-1);
	}
	if (strlen_config_file > MAX_PATH - 4) {
		println("Specified filename '{}' is too long.", config->file);
		_famexit(-1);
	}

	infd = file(config->file);
	if (infd < 0) {
		println("Could not open file '{}'.", config->file);
		_famexit(-1);
	}

	file_size = fsize(infd);
	if (file_size < 0) {
		println("Could not obtain file size for file '{}'.",
			config->file);
		_famexit(-1);
	}

	header = fmap(infd, sizeof(CzipFileHeader), 0);
	if (!header) {
		println("Could not fmap file '{}'.", config->file);
		_famexit(-1);
	}

	if (config->console) {
		outfd = STDOUT_FD;
		do_decompress(header, infd, outfd, file_size);
	} else {
		strncpy(output_file, config->file, strlen_config_file - 3);
		output_file[strlen_config_file - 3] = 0;
		if (exists(output_file)) {
			println("Specified filename '{}' already exists.",
				output_file);
			_famexit(-1);
		}

		outfd = file(output_file);
		if (outfd < 0) {
			println("Could not open filename '{}'.", output_file);
			_famexit(-1);
		}

		do_decompress(header, infd, outfd, file_size);
		close(outfd);
	}
	munmap(header, sizeof(CzipFileHeader));
	close(infd);
	if (!config->console) unlink(config->file);
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	init_global_allocator(64);
	CzipConfig config = parse_argv(argc, argv);

	if (config.version) {
		println("czip {}", LIBFAM_VERSION);
	} else if (config.help) {
		println("Usage: czip [OPTION]... [FILE]...");
		println(
		    "-c, --console       write to standard output, "
		    "keep files "
		    "unchanged");
		println("-d, --decompress    decompress");
		println("-h, --help          print this message");
		println("-v, --version       print version");
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
