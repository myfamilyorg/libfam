#!/bin/sh

GEN_SRC=./etc/gen_bible_dat.c
GEN_OUT_DIR=./target/bin
GEN_BIN=${GEN_OUT_DIR}/gen_bible
GEN_DAT_LOCATION=./resources/bible.dat
LIB_DIR=./target/lib
INCLUDE_DIR=./src/include
GENCFLAGS="-ffreestanding -nostdlib -O3 -flto=auto"
if [ "${CC}" = "" ]; then
        CC=clang
fi

# make the output directory
mkdir -p ${GEN_OUT_DIR};

# build xxdir and create header
if [ ! -e ${GEN_BIN} ] || [ ${GEN_SRC} -nt  ${GEN_BIN} ]; then
        COMMAND="${CC} -I${INCLUDE_DIR} ${GENCFLAGS} -lfam -L${LIB_DIR} -o ${GEN_BIN} ${GEN_SRC}";
        if [ "$SILENT" != "1" ]; then
                echo "${COMMAND}";
        fi
        ${COMMAND} || exit $?;
fi

if [ ! -e ${GEN_BIN} ] || [ ! -e ${GEN_DAT_LOCATION} ]; then
        COMMAND="${GEN_BIN} ${GEN_DAT_LOCATION}"
        if [ "$SILENT" != "1" ]; then
                echo "${COMMAND}";
        fi
        LD_LIBRARY_PATH=${LIB_DIR} ${COMMAND}
fi

