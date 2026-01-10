#include <cpuid.h>

int main(void) {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	__cpuid_count(7, 0, eax, ebx, ecx, edx);
	return (ecx & (1U << 9)) ? 0 : 1;
}
