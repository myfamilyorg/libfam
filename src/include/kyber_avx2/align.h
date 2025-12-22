#ifndef ALIGN_H
#define ALIGN_H

#include <immintrin.h>
#include <libfam/types.h>
#include <stdint.h>

#define ALIGNED_UINT8(N)                    \
	union {                             \
		u8 coeffs[N];               \
		__m256i vec[(N + 31) / 32]; \
	}

#define ALIGNED_INT16(N)                    \
	union {                             \
		i16 coeffs[N];              \
		__m256i vec[(N + 15) / 16]; \
	}

#endif
