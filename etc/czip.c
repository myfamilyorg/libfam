/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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
#include <libfam/main.h>
#include <libfam/version.h>

#define CZIP_VERSION 0
#define CZIP_MAGIC 0xCC337711
#define MAX_PATH 1024

typedef struct {
	bool decompress;
	bool console;
	bool version;
	bool help;
	bool keep;
	const u8 *file;
	i32 return_value;
} CzipConfig;

typedef struct {
	u64 file_size;
	u64 mtime;
	u64 atime;
	u16 permissions;
	u16 czip_version;
	const u8 *file;
} CzipFileHeader;

static CzipConfig parse_argv(i32 argc, u8 **argv) {
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
				} else if (!strcmp(arg, "keep")) {
					ret.keep = true;
					return ret;
				} else {
					println("Illegal option: '{}'",
						argv[i]);
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
					else if (ch == 'k')
						ret.keep = true;
					else {
						println("Illegal option: '{c}'",
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

static void decompress(CzipConfig *config) {
	i32 infd, outfd;
	u8 outpath[MAX_PATH] = {0};

	if (!config->file) {
		println("File name must be specified.");
		_exit(-1);
	}

	if (!exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_exit(-1);
	}

	infd = file(config->file);
	if (infd < 0) {
		println("Could not open specified file '{}'", config->file);
		_exit(-1);
	}

	strcpy(outpath, config->file);
	outpath[strlen(outpath) - 3] = 0;

	outfd = config->console ? 1 : file(outpath);

	u32 magic;
	u8 version;
	/*
	pread(infd, &magic, sizeof(u32), 0);
	pread(infd, &version, sizeof(u8), 4);

	if (magic != CZIP_MAGIC || version != CZIP_VERSION) {
		println("Magic error! {}/{} (expected {}/{}", magic, version,
			CZIP_MAGIC, CZIP_VERSION);
		_exit(-1);
	}
	*/

	if (config->console)
		decompress_stream(infd, 5, outfd, 0);
	else
		decompress_file(infd, 5, outfd, 0);

	close(infd);
	if (!config->console) close(outfd);

	if (!config->keep && !config->console) unlink(config->file);
}

static void compress(CzipConfig *config) {
	i32 infd, outfd;
	u8 outpath[MAX_PATH] = {0};

	if (strlen(config->file) >= MAX_PATH - 4) {
		println("File name too long!");
		_exit(-1);
	}

	if (!exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		_exit(-1);
	}

	infd = file(config->file);

	if (infd < 0) {
		println("Could not open specified file '{}'", config->file);
		_exit(-1);
	}

	strcpy(outpath, config->file);
	strcat(outpath, ".cz");

	outfd = file(outpath);

	if (outfd < 0) {
		println("Could not open output file '{}'", outpath);
		_exit(-1);
	}

	u32 wval = CZIP_MAGIC;

	pwrite(outfd, &wval, sizeof(u32), 0);
	pwrite(outfd, CZIP_VERSION, sizeof(u8), 4);

	compress_file(infd, 0, outfd, 5);

	close(infd);
	close(outfd);

	if (!config->keep) unlink(config->file);
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
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
		println("-k, --keep          keep original file");
		println(
		    "\nNote: if no file is specified stdin will be "
		    "used as "
		    "the "
		    "input file.");
		return config.return_value;
	} else if (config.decompress) {
		decompress(&config);
	} else {
		compress(&config);
	}

	return 0;
}
