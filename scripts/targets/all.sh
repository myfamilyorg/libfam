#!/bin/sh

. "$PROJECT_DIR/scripts/core.sh"   # this sources config.sh + all build logic

mkdir -p ${LIB_DIR};
mkdir -p ${BIN_DIR};

for DIR in $SUB_DIRS; do
        build_subdir ${DIR} 0 objs || exit $?;
done

OBJECTS=$(collect_objects)

if needs_rebuild "$LIB_NAME" $OBJECTS; then
        if [ "${OBJECTS}" != "" ]; then
                COMMAND="${CC} ${LDFLAGS} -o ${LIB_NAME} ${OBJECTS}";
                if [ "$SILENT" != "1" ]; then
                        echo ${COMMAND};
                fi
                ${COMMAND} || exit $?;
        fi
fi

. "$PROJECT_DIR/scripts/gen_bible.sh"

