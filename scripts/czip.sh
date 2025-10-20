#!/bin/bash

CZIP_SRC="etc/czip.c"
OUT_BIN="./target/bin/czip"
LIB_DIR="./target/lib"

if [ "${CFLAGS}" = "" ]; then
	CFLAGS="-O3"
fi
if [ "${CC}" = "" ]; then
	CC=clang
fi

if [ ! -e ${OUT_BIN} ] || [ ${CZIP_SRC} -nt ${OUT_BIN} ]; then
COMMAND="${CC} -O3 -Wno-pointer-sign -ffreestanding -nostdlib -nostdinc -Ltarget/lib -Isrc/include -o target/bin/czip etc/czip.c -lfam"

	echo ${COMMAND}
	${COMMAND} || exit $?;
fi
