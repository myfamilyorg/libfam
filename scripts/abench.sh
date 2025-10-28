#!/bin/bash

ABENCH_SRC="etc/abench.c"
OUT_BIN="./target/bin/abench"
LIB_DIR="./target/lib"

if [ "${CFLAGS}" = "" ]; then
	CFLAGS="-O3"
fi
if [ "${CC}" = "" ]; then
	CC=clang
fi

if [ ! -e ${OUT_BIN} ] || [ ${ABENCH_SRC} -nt ${OUT_BIN} ]; then
COMMAND="${CC} -O3 -Wno-pointer-sign -Ltarget/lib -Isrc/include -o ${OUT_BIN} ${ABENCH_SRC} -lfam"

	echo ${COMMAND}
	${COMMAND} || exit $?;
fi
