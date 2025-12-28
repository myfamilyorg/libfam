#ifndef CONSTS_H
#define CONSTS_H

#include <dilithium_avx2/params.h>

#define _8XQ 0
#define _8XQINV 8
#define _8XDIV_QINV 16
#define _8XDIV 24
#define _ZETAS_QINV 32
#define _ZETAS 328

#define cdecl(s) DILITHIUM_NAMESPACE(##s)

#ifndef __ASSEMBLER__

#include <dilithium_avx2/align.h>

typedef ALIGNED_INT32(624) qdata_t;

#define qdata DILITHIUM_NAMESPACE(qdata)
extern const qdata_t qdata;

#endif
#endif
