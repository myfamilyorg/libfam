#!/bin/bash

if [ "${CFLAGS}" = "" ]; then
	CFLAGS="-O3 -flto"
fi
if [ "${CC}" = "" ]; then
	CC=clang
fi
OUT_BIN="./target/bin/czip"

COMMAND="${CC} -Wno-pointer-sign -Isrc/include etc/czip.c ${CFLAGS} -o ${OUT_BIN} -lfam -Ltarget/lib"
echo ${COMMAND}
${COMMAND}
