#!/bin/bash

XXDIR_SRC=./etc/xxdir.c
XXDIR_OUT_DIR=./target/bin
XXDIR_BIN=${XXDIR_OUT_DIR}/xxdir
XXDIR_RESOURCES=./resources/xxdir
XXDIR_HEADER=./src/include/libfam/xxdir_dat.h
INCLUDE_DIR=./src/include
XCFLAGS=-Wno-pointer-sign
if [ "${CC}" = "" ]; then
	CC=clang
fi

# make the output directory
mkdir -p ${XXDIR_OUT_DIR};

# build xxdir and create header
if [ ! -e ${XXDIR_BIN} ] || [ ${XXDIR_SRC} -nt  ${XXDIR_BIN} ]; then
	COMMAND="${CC} -I${INCLUDE_DIR} ${XCFLAGS} -o ${XXDIR_BIN} ${XXDIR_SRC}";
	if [ "$SILENT" != "1" ]; then
        	echo "${COMMAND}";
	fi
        ${COMMAND} || exit $?;
fi

if [ ! -e ${XXDIR_HEADER} ] || [ -n "$(find ${XXDIR_RESOURCES} -type f -newer ${XXDIR_HEADER})" ]; then
	COMMAND="${XXDIR_BIN} ${XXDIR_RESOURCES} ${XXDIR_HEADER}"
	if [ "$SILENT" != "1" ]; then
		echo "${COMMAND}";
	fi
        ${COMMAND}
fi

