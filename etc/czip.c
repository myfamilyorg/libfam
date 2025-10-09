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
#define CHUNK_SIZE (1 << 17)
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

void do_compress(const CzipFileHeader *header, i32 in_fd, i32 out_fd) {
	u64 out_offset = 0;
	u64 in_offset = 0;

	if (fresize(out_fd, sizeof(CzipFileHeader)) < 0) {
		println("Failed to resize file!");
		perror("fresize");
		_exit(-1);
	}

	CzipFileHeader *out_header = fmap(out_fd, sizeof(CzipFileHeader), 0);
	if (!out_header) {
		println("mmap failed to map output file!");
		perror("mmap");
		_exit(-1);
	}
	*out_header = *header;
	out_offset += sizeof(CzipFileHeader);
	munmap(out_header, sizeof(CzipFileHeader));

	while (in_offset < header->file_size) {
		u64 chunk_size = min(header->file_size - in_offset, CHUNK_SIZE);

		u8 *in_chunk = fmap(in_fd, chunk_size, in_offset);
		if (!in_chunk) {
			println("mmap failed to read next chunk!");
			perror("mmap");
			_exit(-1);
		}
		u64 out_offset_aligned = (out_offset / PAGE_SIZE) * PAGE_SIZE;
		u64 out_offset_diff = out_offset - out_offset_aligned;
		u64 out_max = compress_bound(CHUNK_SIZE) + out_offset_diff;
		if (fresize(out_fd, out_offset + out_max) < 0) {
			println("Failed to resize file!");
			perror("fresize");
			_exit(-1);
		}
		u8 *out_chunk = fmap(out_fd, out_max, out_offset_aligned);
		if (!out_chunk) {
			println("mmap failed to map write chunk!");
			perror("mmap");
			_exit(-1);
		}
		u8 *compress_chunk = out_chunk + out_offset_diff;
		i32 result = compress32(in_chunk, chunk_size, compress_chunk,
					compress_bound(CHUNK_SIZE));
		if (result < 0) {
			println("Failed to compress block due to {}.",
				strerror(errno));
			_exit(-1);
		}

		/*
		println(
		    "chunk_size={},in_offset={},out_offset={},result={},out_"
		    "offset_diff={}",
		    chunk_size, in_offset, out_offset, result, out_offset_diff);
		    */

		munmap(out_chunk, out_max);
		munmap(in_chunk, chunk_size);
		in_offset += chunk_size;
		out_offset += result;
	}

	if (fresize(out_fd, out_offset) < 0) {
		println("failed to resize output file");
		_exit(-1);
	}
}

void do_decompress(const CzipFileHeader *header, i32 in_fd, i32 out_fd,
		   u64 in_file_size) {
	u8 output[1024 * 1024];
	u64 in_offset = sizeof(CzipFileHeader);
	u64 out_offset = 0;
	println("do_decompress");
	while (in_offset < in_file_size) {
		u64 bytes_consumed;
		u64 in_offset_aligned = (in_offset / PAGE_SIZE) * PAGE_SIZE;
		u64 in_offset_diff = in_offset - in_offset_aligned;
		u64 chunk_size =
		    min(in_offset_diff + compress_bound(CHUNK_SIZE),
			in_file_size - in_offset);

		println("pre fmap {}, {}", chunk_size, in_offset_aligned);
		u8 *in_chunk = fmap(in_fd, chunk_size, in_offset_aligned);
		println("post fmap");
		if (!in_chunk) {
			println("mmap failed: {}", strerror(errno));
			_exit(-1);
		}
		u8 *in_block = in_chunk + in_offset_diff;

		u64 out_offset_aligned = (out_offset / PAGE_SIZE) * PAGE_SIZE;
		u64 out_offset_diff = out_offset - out_offset_aligned;

		fresize(out_fd, out_offset + CHUNK_SIZE);

		u8 *out_chunk = fmap(out_fd, CHUNK_SIZE + out_offset_diff,
				     out_offset_aligned);
		u8 *out_block = out_chunk + out_offset_diff;

		println("pre decomp {}, in file offset = {}/{}", in_offset_diff,
			in_offset_aligned + in_offset_diff, in_file_size);
		i32 result = decompress32(in_block, chunk_size, out_block,
					  CHUNK_SIZE, &bytes_consumed);
		println("post decomp");
		if (result < 0) {
			println("decompress32 failed: {}", strerror(errno));
			_exit(-1);
		}

		println("in_offset={},result={},bytes_consumed={}", in_offset,
			result, bytes_consumed);

		munmap(out_chunk, CHUNK_SIZE + out_offset_diff);
		munmap(in_chunk, chunk_size);
		in_offset += bytes_consumed;
		out_offset += result;
	}

	fresize(out_fd, out_offset);
}

void run_compressor(CzipConfig *config) {
	i32 infd, outfd;
	u8 output_file[MAX_PATH];
	u64 file_size;
	u64 strlen_in_file = strlen(config->file);
	struct stat st;
	CzipFileHeader header;

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

	header.file_size = file_size;
	header.mtime = st.st_mtime;
	header.atime = st.st_atime;
	header.permissions = st.st_mode & 0xFFF;
	header.czip_version = 0;

	do_compress(&header, infd, outfd);

	close(infd);
	close(outfd);
}

void run_decompressor(CzipConfig *config) {
	CzipFileHeader *header;
	i64 file_size;
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

	header = fmap(infd, sizeof(CzipFileHeader), 0);
	if (!header) {
		println("Could not fmap file '{}'.", config->file);
		_exit(-1);
	}
	println("ver={},size={},out={}", header->czip_version,
		header->file_size, output_file);

	outfd = file(output_file);
	if (outfd < 0) {
		println("Could not open filename '{}'.", output_file);
		_exit(-1);
	}

	do_decompress(header, infd, outfd, file_size);

	munmap(header, sizeof(CzipFileHeader));
	close(infd);
	close(outfd);

	/*

	while (out_size < header->file_size) {
		i64 offset_aligned = (offset / PAGE_SIZE) * PAGE_SIZE;
		u32 offset_aligned_diff = offset - offset_aligned;
		u32 in_map_len = min(header->file_size - offset,
				     compress_bound(CHUNK_SIZE) +
					 offset_aligned_diff + sizeof(u32));
		println("in map len={},offset_diff={},offset_aligned={}",
			in_map_len, offset_aligned_diff, offset_aligned);
		u8 *chunk = fmap(infd, in_map_len, offset_aligned);
		u32 *chunk_size = (void *)chunk;
		println("chunk_size={}", *chunk_size);
		u32 out_max = *chunk_size;

		fresize(outfd, out_size + *chunk_size);
		u8 *outfmap = fmap(outfd, *chunk_size, out_size);
		out_size += decompress32(
		    chunk + offset_aligned_diff + sizeof(u32),
		    in_map_len - (offset_aligned_diff + sizeof(u32)), outfmap,
		    out_max);
		offset += CHUNK_SIZE;
		munmap(outfmap, *chunk_size);
		munmap(chunk, in_map_len);
	}
	*/

	/*
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
		u8 *out = fmap(outfd, CHUNK_SIZE + out_size % PAGE_SIZE,
			       out_offset_aligned);
		if (!out) {
			println("fmap failed due to: {}.", strerror(errno));
			_exit(-1);
		}
		out += out_size % PAGE_SIZE;

		i64 advance = decompress32(chunk, actual_size, out, CHUNK_SIZE);

		munmap(chunk, actual_size + offset % PAGE_SIZE);

		println("offset={},offset_aligned={},map_len={},cs={},adv={}",
			offset, offset_aligned,
			compress_bound(CHUNK_SIZE) + offset % PAGE_SIZE,
			CHUNK_SIZE, advance);

		offset += actual_size;
		out_size += advance;
	}
	*/

	/*
	println("freqize to {}", out_size);
	if (fresize(outfd, out_size) < 0) {
		println("Could not resize file '{}'.", output_file);
		_exit(-1);
	}
	*/

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
