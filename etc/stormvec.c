#include <libfam/format.h>
#include <libfam/main.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/types.h>

#define VECTOR_FILE_PATH "/tmp/storm_vectors.h"

int main(i32 argc, u8 **argv, u8 **envp) {
	StormContext ctx;
	Rng rng;
	rng_init(&rng);
	__attribute__((aligned(32))) u8 keys[2][32] = {
	    {1,	 2,  3,	 4,  5,	 6,  7,	 8,  9,	 10, 11, 12, 13, 14, 15, 16,
	     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	    {1,	 2,  3,	 4,  5,	 6,  7,	 8,  9,	 10, 11, 12, 13, 14, 15, 16,
	     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 33}};
	__attribute__((aligned(32))) u8 inputs[2][2][32] = {
	    {{1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
	      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 35},
	     {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
	      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 36}},
	    {{1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
	      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 37},
	     {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
	      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 38}}};

	rng_gen(&rng, keys, sizeof(keys));
	rng_gen(&rng, inputs, sizeof(inputs));
	println("Building storm vectors!");
	unlink(VECTOR_FILE_PATH);
	i32 fd = file(VECTOR_FILE_PATH);
	Formatter fmt = FORMATTER_INIT;
	FORMAT(&fmt, "#ifndef _STORM_VECTORS_H\n");
	FORMAT(&fmt, "#define _STORM_VECTORS_H\n");
	FORMAT(&fmt, "\ntypedef struct { \n");
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 key[32]; \n");
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 input[{}][32]; \n",
	       sizeof(inputs) / sizeof(inputs[0]));
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 expected[{}][32]; \n",
	       sizeof(inputs) / sizeof(inputs[0]));
	FORMAT(&fmt, "} StormVector;\n\n");

	FORMAT(&fmt, "static const StormVector storm_vectors[] = {\n");

	for (u32 i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		FORMAT(&fmt, "\n  {\n    .key = {");
		for (u32 j = 0; j < 32; j++) {
			FORMAT(&fmt, "{}", keys[i][j]);
			if (j != 31) FORMAT(&fmt, ",");
		}
		FORMAT(&fmt, "},\n");
		FORMAT(&fmt, "    .input = {{\n");
		for (u32 j = 0; j < sizeof(inputs[i]) / sizeof(inputs[i][0]);
		     j++) {
			FORMAT(&fmt, "      {{");
			for (u32 k = 0; k < 32; k++) {
				FORMAT(&fmt, "{}", inputs[i][j][k]);
				if (k != 31) FORMAT(&fmt, ",");
			}
			FORMAT(&fmt, "}}");
			if (j != sizeof(inputs[i]) / sizeof(inputs[i][0]) - 1)
				FORMAT(&fmt, ",\n");
			else
				FORMAT(&fmt, "\n");
		}
		FORMAT(&fmt, "    }}\n,    .expected = {{\n");
		storm_init(&ctx, keys[i]);
		for (u32 j = 0; j < sizeof(inputs[i]) / sizeof(inputs[i][0]);
		     j++) {
			__attribute__((aligned(32))) u8 tmp[32];
			fastmemcpy(tmp, inputs[i][j], 32);
			storm_next_block(&ctx, tmp);
			FORMAT(&fmt, "      {{");
			for (u32 k = 0; k < 32; k++) {
				FORMAT(&fmt, "{}", tmp[k]);
				if (k != 31) FORMAT(&fmt, ",");
			}
			FORMAT(&fmt, "}}");
			if (j != sizeof(inputs[i]) / sizeof(inputs[i][0]) - 1)
				FORMAT(&fmt, ",\n");
			else
				FORMAT(&fmt, "\n");
		}
		FORMAT(&fmt, "    }}\n  }");
		if (i != sizeof(keys) / sizeof(keys[0]) - 1) FORMAT(&fmt, ",");
	}

	FORMAT(&fmt, "\n};\n");

	FORMAT(&fmt, "#endif /* _STORM_VECTORS_H */\n");
	const u8 *out = format_to_string(&fmt);

	pwrite(fd, out, faststrlen(out), 0);

	close(fd);
	return 0;
}

