#!/bin/bash

. ./scripts/common.sh

OBJECTS="";
CDEFS="-DSTATIC=static -DTEST=0";
LIB_NAME="${LIB_OUTPUT_DIR}/libfam.so";


mkdir -p ${LIB_OUTPUT_DIR};
mkdir -p ${BIN_DIR};

. ./scripts/xxdir.sh || exit $?;

for DIR in $SUB_DIRS; do
	build_dir ${DIR} 0 objs || exit $?;
done

for DIR in $SUB_DIRS; do
        shopt -s nullglob
        o_files=(./target/objs/"${DIR}"/*.o)
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

. ./scripts/czip.sh || exit $?;
. ./scripts/abench.sh || exit $?;
