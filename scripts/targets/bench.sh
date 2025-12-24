#!/bin/sh

. "$PROJECT_DIR/scripts/core.sh"

mkdir -p ${LIB_DIR};
mkdir -p ${BIN_DIR};

for DIR in $SUB_DIRS; do
        build_subdir ${DIR} 1 || exit $?;
done
build_asm

OBJECTS=$(collect_objects)


if needs_rebuild "$TEST_LIB_NAME" $OBJECTS; then
        if [ "${OBJECTS}" != "" ]; then
                COMMAND="${CC} ${LDFLAGS} -o ${TEST_LIB_NAME} ${OBJECTS}";
                if [ "$SILENT" != "1" ]; then
                        echo ${COMMAND};
                fi
                ${COMMAND} || exit $?;
        fi
fi

if [ ! -e target/bin/runtests ] || [ src/test/main.c -nt target/bin/runtests ]; then
        if [ "${ARCH}" = "aarch64" ]; then
                CFLAGS="${CFLAGS} -mno-outline-atomics";
        fi

        COMMAND="${CC} \
                ${CDEFS} \
                ${CFLAGS} \
		-L${LIB_DIR} \
                -I${INCDIR} \
                -o ${TEST_BIN} \
                ${TEST_SRC} \
		-ffreestanding \
		-nostdlib \
                -lfamtest";

        if [ "$SILENT" != "1" ]; then
                echo ${COMMAND};
        fi
        ${COMMAND} || exit $?;
fi

export TEST_PATTERN=${FILTER};
if [ "${VALGRIND}" = "1" ]; then
        LD_LIBRARY_PATH=${LIB_DIR} \
                valgrind \
                --child-silent-after-fork=yes \
                --tool=memcheck \
                --track-origins=yes \
                --error-exitcode=1 \
                ${TEST_BIN} || exit $?;
else

        LD_LIBRARY_PATH=${LIB_DIR} ${TEST_BIN} bench || exit $?;
fi

