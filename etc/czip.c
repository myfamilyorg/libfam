#include <libfam/compress.h>
#include <libfam/format.h>
#include <libfam/memory.h>
#include <libfam/string.h>
#include <libfam/sysext.h>

i32 decompress_file(const u8 *f) {
	if (!f) {
		println("File '' not found!");
		return -1;
	}
	if (!exists(f)) {
		println("File '{}' not found!", f);
		return -1;
	}

	u64 len = strlen(f);
	if (len < 5) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}
	const u8 *index = f + len - 3;
	if (strcmp(index, ".cz") != 0) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}

	u8 *uncompressed = alloc(index - f + 1);
	if (!uncompressed) {
		println("Could not allocate memory!");
		return -1;
	}
	memcpy(uncompressed, f, strlen(f) - 3);

	if (exists(uncompressed)) {
		println("File '{}', already exists!", uncompressed);
		return -1;
	}

	i32 fd = file(f);
	i64 file_size = fsize(fd);

	if (file_size < sizeof(i64)) {
		println("File '{}' is not a czip file!", f);
		return -1;
	}

	u8 *in = fmap(fd, file_size, 0);
	if (!in) {
		println("Could not memory map file '{}'!", f);
		return -1;
	}

	u64 decomp_size;
	memcpy(&decomp_size, in, sizeof(i64));
	i32 fd_out = file(uncompressed);
	if (fd_out < 0) {
		println("Could not open file '{}'!", uncompressed);
		return -1;
	}
	if (fresize(fd_out, decomp_size) < 0) {
		println("Could not resize file '{}'!", uncompressed);
		return -1;
	}
	u8 *out = fmap(fd_out, decomp_size, 0);
	if (!out) {
		println("Could not memory map file '{}'!", uncompressed);
		return -1;
	}

	i64 result = decompress(in + sizeof(i64), file_size - sizeof(i64), out,
				decomp_size);
	if (result < 0) {
		println("Decompression failed: {}", strerror(errno));
		return -1;
	}
	unlink(f);

	return 0;
}

i32 compress_file(const u8 *f) {
	if (!exists(f)) {
		println("File '{}' not found!", f);
		return -1;
	}
	i32 fd = file(f);
	if (fd < 0) {
		println("Could not open file '{}'!", f);
		return -1;
	}
	i64 file_size = fsize(fd);
	if (file_size < 0) {
		println("Could not change the size of file '{}'!", f);
		return -1;
	}

	u8 *in = fmap(fd, file_size, 0);
	if (!in) {
		println("Could not memory map file '{}'! ({})", f, file_size);
		return -1;
	}

	u64 bound = compress_bound(file_size);
	u64 nfile_len = strlen(f) + strlen(".cz") + 1;
	u8 *nfile = alloc(nfile_len);
	if (!nfile) {
		println("Could not allocate memory!");
		return -1;
	}
	memset(nfile, 0, nfile_len);
	strcpy(nfile, f);
	strcpy(nfile + strlen(f), ".cz");
	if (exists(nfile)) {
		println("File '{}' already exists!", nfile);
		return -1;
	}

	i32 fd_out = file(nfile);
	if (fresize(fd_out, bound + sizeof(i64)) < 0) {
		println("File resize failed: {}", strerror(errno));
		return -1;
	}
	u8 *out = fmap(fd_out, bound, 0);
	i64 result = compress(in, file_size, out + sizeof(i64), bound);
	if (result < 0) {
		println("Compression failed: {}", strerror(errno));
		return -1;
	}
	memcpy(out, &file_size, sizeof(i64));
	munmap(out, bound);
	fresize(fd_out, result + sizeof(u64));
	close(fd_out);
	unlink(f);

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2 && argc != 3) {
		println("Usage: czip [-d] <file>");
		return -1;
	}
	if (argc == 3 && strcmp(argv[1], "-d")) {
		println("Usage: czip [-d] <file>");
		return -1;
	}

	if (argc == 2)
		return compress_file(argv[1]);
	else
		return decompress_file(argv[2]);
}
