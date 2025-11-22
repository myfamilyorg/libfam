#!/bin/bash

. ./scripts/common.sh

CDEFS="-DSTATIC= -DTEST=1 -DCOVERAGE";
COV_CFLAGS="-fno-builtin -Wno-pointer-sign -lc -lgcc --coverage";
OBJECTS="";

LIB_NAME="${LIB_OUTPUT_DIR}/libfamtest.so";
BIN_DIR="./target/bin";
TEST_BIN="${BIN_DIR}/runtestscov";
TEST_SRC="src/test/main.c";

# Overwrite CC/CFLAGS
CC=gcc
CFLAGS="-O0 \
	-Werror \
	-Wall \
	-std=c11 \
	-fvisibility=hidden \
	-fno-pie \
	-fPIC \
	-fno-builtin \
	-Wno-pointer-sign \
	-march=${MARCH} \
	--coverage"

# Always build clean for coverage
rm -rf ./target/cobjs
mkdir -p ${LIB_OUTPUT_DIR};
mkdir -p "${BIN_DIR}";

. ./scripts/xxdir.sh

for DIR in $SUB_DIRS; do
        build_dir ${DIR} 1 cobjs || exit 1;
done

for dir in $SUB_DIRS; do
    OBJECTS="$OBJECTS ./target/cobjs/$dir/*.o";
done

COMMAND="${CC} \
	${CDEFS} \
	${COV_CFLAGS} \
	-I${INCDIR} \
	-o ${TEST_BIN} \
	${TEST_SRC} \
	${OBJECTS}";
if [ "$SILENT" != "1" ]; then
	echo ${COMMAND};
fi
${COMMAND} || exit 1;

export TEST_PATTERN="*";
LD_LIBRARY_PATH=${LIB_OUTPUT_DIR} ${TEST_BIN} || { echo "tests failed!"; exit $?; }

for DIR in ${SUB_DIRS}; do
	cp ./src/${DIR}/*.c ./target/cobjs/${DIR}/
	touch ./target/cobjs/${DIR}/*
done

LINESUM=0;
COVEREDSUM=0;
echo "------------------------------------------------------------------------------------------";


cd ./target/cobjs
for DIR in *; do
	cd ./${DIR};
	for FILE in ./*.c; do
		if [ "${FILE}" != "./test.c" ]; then
			PERCENT=`gcov ${FILE} 2> /dev/null \
				| grep "^Lines" | head -1 | cut -f2 -d ' ' \
				| cut -f2 -d ':' | cut -f1 -d '%' | tr -d \\n`;
			if [ "${PERCENT}" == "" ]; then
				PERCENT=0.00;
			fi;
			LINES=`gcov ${FILE} 2> /dev/null | grep "^Lines" \
				| head -1 | cut -f4 -d ' ' | tr -d \\n`;
			if [ "${LINES}" == "" ]; then
				LINES=0;
				PERCENT=100.00;
			fi
			BASENAME=$(basename "${FILE}")
			RATIO=`awk "BEGIN {print $PERCENT / 100}"`;
			COVERED=`awk "BEGIN {print int($RATIO * $LINES)}"`;
			LINESUM=`awk "BEGIN {print $LINESUM + $LINES}"`;
			COVEREDSUM=`awk "BEGIN {print ${COVEREDSUM} + ${COVERED}}"`;
			printf "${GREEN}%-20s${RESET} %6s%% -${YELLOW} [%3s/%3s]${RESET}\n" \
				"${DIR}/${BASENAME}" \
				"${PERCENT}" \
				"${COVERED}" \
				"${LINES}"
		fi

	done

	cd ..;
done
cd ../..;

echo "------------------------------------------------------------------------------------------";

CODECOV=`awk "BEGIN {printf \"%.2f\", 100 * ${COVEREDSUM} / ${LINESUM}}"`
echo "Coverage: ${CODECOV}% [${COVEREDSUM} / ${LINESUM}]";

TIMESTAMP=`date +%s`
echo "$CODECOV" > /tmp/cc_final;
echo "$TIMESTAMP $CODECOV $COVEREDSUM $LINESUM" > /tmp/cc.txt
chmod 777 /tmp/cc_final /tmp/cc.txt


