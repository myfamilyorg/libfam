#!/bin/bash

CZIP_SRC=etc/czip.c

if [ "${CFLAGS}" = "" ]; then
	CFLAGS="-O3 -flto"
fi
if [ "${CC}" = "" ]; then
	CC=clang
fi
OUT_BIN="./target/bin/czip"

if [ ! -e ${OUT_BIN} ] || [ ${CZIP_SRC} -nt ${OUT_BIN} ]; then
	COMMAND="${CC} \
		-Wno-pointer-sign \
		-Isrc/include ${CZIP_SRC} \
		${CFLAGS} \
		-o ${OUT_BIN} \
		-lfam -Ltarget/lib"
	echo ${COMMAND}
	${COMMAND}
fi
