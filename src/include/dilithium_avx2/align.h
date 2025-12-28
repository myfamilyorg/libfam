#ifndef ALIGN_H
#define ALIGN_H

#include <immintrin.h>

#define ALIGNED_UINT8(N)                    \
	union {                             \
		u8 coeffs[N];               \
		__m256i vec[(N + 31) / 32]; \
	}

#define ALIGNED_INT32(N)                  \
	union {                           \
		i32 coeffs[N];            \
		__m256i vec[(N + 7) / 8]; \
	}

#endif
