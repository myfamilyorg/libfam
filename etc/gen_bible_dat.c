#include <libfam/bible.h>
#include <libfam/main.h>

i32 cur_tests = 0;
i32 exe_test = 0;
typedef struct {
	void (*test_fn)(void);
	u8 name[1];
} TestEntry;

TestEntry tests[0];

void add_test_fn(void (*test_fn)(void), const u8 *name) {}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	const Bible *b = bible_gen();
	bible_store(b, argv[1]);
	return 0;
}
