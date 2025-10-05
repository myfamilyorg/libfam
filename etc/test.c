#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/types.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	u8 buf[1024] = {0};
	write(2, "hi\n", 3);
	i64 s = micros();
	printf("s=%ld\n", s);
	strcpy(buf, "abc");
	printf("s=%s\n", buf);
	return s;
}
