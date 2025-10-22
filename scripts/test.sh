#!/bin/bash

. ./scripts/common.sh

CDEFS="-DSTATIC= -DTEST=1";
LIB_NAME="${LIB_OUTPUT_DIR}/libfamtest.so";
TEST_BIN="target/bin/runtests";
TEST_SRC="src/test/main.c";
TEST_CFLAGS="-Wno-pointer-sign -ffreestanding -nostdlib -Ltarget/lib";
OBJECTS="";

mkdir -p ${LIB_OUTPUT_DIR};
mkdir -p ${BIN_DIR};
. ./scripts/xxdir.sh
for DIR in ${SUB_DIRS}; do
        build_dir ${DIR} 1 tobjs || exit $?;
done

for DIR in $SUB_DIRS; do
	shopt -s nullglob
	o_files=(./target/tobjs/"${DIR}"/*.o)
	if [ ${#o_files[@]} -gt 0 ]; then
		OBJECTS="$OBJECTS ${o_files[*]}"
	fi
done

if needs_linking "$LIB_NAME" $OBJECTS; then
	if [ "${OBJECTS}" != "" ]; then
        	COMMAND="${CC} ${LDFLAGS} -o ${LIB_NAME} ${OBJECTS}";
        	if [ "$SILENT" != "1" ]; then
                	echo ${COMMAND};
        	fi
        	${COMMAND} || exit $?;
	fi
fi

if [ ! -e target/bin/runtests ] || [ src/test/main.c -nt target/bin/runtests ]; then
        mkdir -p target/bin;
        COMMAND="${CC} \
                ${CDEFS} \
                ${TEST_CFLAGS} \
                -I${INCDIR} \
                -o ${TEST_BIN} \
                ${TEST_SRC} \
                -lfamtest";
        if [ "$SILENT" != "1" ]; then
                echo ${COMMAND};
        fi
        ${COMMAND} || exit $?;
fi

export TEST_PATTERN=${FILTER};
if [ "${VALGRIND}" = "1" ]; then
	export VALGRIND=1;
	LD_LIBRARY_PATH=${LIB_OUTPUT_DIR} \
		valgrind \
		--tool=memcheck \
		--track-origins=yes \
		--error-exitcode=1 \
		${TEST_BIN} || exit $?;
else
	LD_LIBRARY_PATH=${LIB_OUTPUT_DIR} ${TEST_BIN} || exit $?;
fi

