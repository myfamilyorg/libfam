#include <libfam/bible.h>
#include <libfam/linux.h>
#include <libfam/test_base.h>

#define BDAT_PATH "resources/bible.dat"

Test(bible1) {
	const Bible *b;
	i32 fd;
	u8 out[32];

	fd = open(BDAT_PATH, O_RDONLY, 0);
	if (fd < 0) {
		b = bible_gen();
		bible_store(b, BDAT_PATH);
	} else
		b = bible_load(BDAT_PATH);

	bible_pow_hash(b, "", 0, out);
	u8 exp1[] = {106, 189, 246, 61,	 164, 204, 113, 221, 254, 23,  31,
		     163, 12,  190, 142, 203, 121, 98,	239, 212, 200, 205,
		     190, 67,  65,  196, 204, 56,  249, 21,  161, 185};
	ASSERT(!memcmp(exp1, out, 32), "hash1");

	bible_pow_hash(b, "1", 1, out);
	u8 exp2[] = {101, 170, 46,  185, 51,  240, 38, 249, 251, 184, 169,
		     44,  8,   102, 178, 8,   183, 91, 98,  247, 57,  156,
		     254, 207, 49,  188, 218, 173, 58, 0,   24,	 140};

	ASSERT(!memcmp(exp2, out, 32), "hash2");
	if (fd > 0) close(fd);
	bible_destroy(b);
}
