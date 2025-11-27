# scripts/core.sh
# Loaded by every target – contains ALL real build logic

# 1. Source configuration (flags, directories, etc.)
. "$PROJECT_DIR/scripts/config.sh"

# Generators
. "$PROJECT_DIR/scripts/xxdir.sh"

# 2. Generate version header
TAG=$(git describe --tags --dirty 2>/dev/null || echo "unknown")
printf '#define LIBFAM_VERSION "%s"\n' "$TAG" > "$PROJECT_DIR/src/include/libfam/version.h"

# 3. Global constants
SUB_DIRS="base bible"
INCDIR="src/include"
LIB_DIR="${OUTDIR}/lib"
LIB_NAME="${LIB_DIR}/libfam.so";
TEST_LIB_NAME="${LIB_DIR}/libfamtest.so";
BIN_DIR="${OUTDIR}/bin";
TEST_BIN="${BIN_DIR}/runtests";
TEST_SRC="src/test/main.c";

# 4. Helper functions
build_subdir() {
    local subdir="$1"
    local allow_test_c="$2"

    local srcdir="$PROJECT_DIR/src/$subdir"
    local objdir="$OBJDIR/$subdir"   # now absolute!

    mkdir -p "$objdir"

    for src in "$srcdir"/*.c; do
        [ -f "$src" ] || continue
        basename="${src##*/}"
        [ "$basename" = "test.c" ] && [ "$allow_test_c" = "0" ] && continue

        obj="$objdir/${basename%.c}.o"

        if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
            COMMAND="$CC -I$PROJECT_DIR/$INCDIR $CFLAGS $CDEFS -c $src -o $obj";
            [ "$SILENT" != "1" ] && echo ${COMMAND};
	    ${COMMAND} || exit $?;
        fi
    done
}

collect_objects() {
    find "$OBJDIR" -name '*.o' 2>/dev/null | tr '\n' ' '
}

needs_rebuild() {
    local target="$1"; shift
    [ ! -f "$target" ] && return 0
    for obj in "$@"; do
        [ "$obj" -nt "$target" ] && return 0
    done
    return 1
}

