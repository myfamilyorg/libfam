#!/bin/bash

CZIP_SRC="etc/czip.c"
OUT_BIN="./target/bin/czip"
LIB_DIR="./target/lib"

if [ "${CFLAGS}" = "" ]; then
	CFLAGS="-O3 -flto"
fi
if [ "${CC}" = "" ]; then
	CC=clang
fi

if [ ! -e ${OUT_BIN} ] || [ ${CZIP_SRC} -nt ${OUT_BIN} ]; then
	COMMAND="${CC} \
		-Wno-pointer-sign \
		-Isrc/include ${CZIP_SRC} \
		${CFLAGS} \
		-o ${OUT_BIN} \
		-lfam -L${LIB_DIR}"
	echo ${COMMAND}
	${COMMAND}
fi
