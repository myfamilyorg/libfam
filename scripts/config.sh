# scripts/config.sh
# This file is sourced by core.sh – it defines EVERY flag and path based on BUILD_MODE

# ------------------------------------------------------------------
# 1. Determine build mode and set output directories
# ------------------------------------------------------------------
case "${BUILD_MODE:-all}" in
    all)
        OUTDIR="target"
        OBJDIR="target/objs"
        ;;
    test)
        OUTDIR="target/test"
        OBJDIR="target/test/objs"
        ;;
    cov)
        OUTDIR="target/cov"
        OBJDIR="target/cov/objs"
        ;;
    clean|install)
        OUTDIR="target"
        OBJDIR="target/objs"
        ;;
    *)
        echo "Error: Unknown BUILD_MODE='$BUILD_MODE'" >&2
        exit 1
        ;;
esac

# Export so core.sh and targets can use them
export OUTDIR OBJDIR
export LIBDIR="$OUTDIR/lib"
export BINDIR="$OUTDIR/bin"

# ------------------------------------------------------------------
# 2. Base compiler and linker settings (common to all modes)
# ------------------------------------------------------------------
CC="${CC:-clang}"

BASE_CFLAGS="-Werror -Wall -funroll-loops -fstack-protector-strong -std=c11"
BASE_LDFLAGS="-shared -fstack-protector-strong -nostdlib -ffreestanding"

# ------------------------------------------------------------------
# 3. Mode-specific flags
# ------------------------------------------------------------------
case "$BUILD_MODE" in
    all)
        CFLAGS="$BASE_CFLAGS -O3"
        LDFLAGS="$BASE_LDFLAGS -O3"
        VISIBILITY="-fvisibility=hidden"
        CDEFS="-DSTATIC=static -DTEST=0"
        COVERAGE=""
        LTO="-flto=auto"
        ;;
    test|cov)
        CFLAGS="$BASE_CFLAGS -O0 -g3"
        LDFLAGS="$BASE_LDFLAGS -g3"
        VISIBILITY=""
        CDEFS="-DTEST=1"
        COVERAGE=""
        [ "$BUILD_MODE" = "cov" ] && COVERAGE="--coverage" && LDFLAGS="$LDFLAGS --coverage"
        LTO=""
        ;;
    *)
        # clean/install – minimal flags (won't be used anyway)
        CFLAGS="$BASE_CFLAGS -O3"
        LDFLAGS="$BASE_LDFLAGS"
        VISIBILITY="-fvisibility=hidden"
        CDEFS="-DSTATIC=static -DTEST=0"
        COVERAGE=""
        LTO="-flto=auto"
        ;;
esac

# ------------------------------------------------------------------
# 4. Architecture-specific flags
# ------------------------------------------------------------------
case "$(uname -m)" in
    x86_64)
        MARCH="haswell"
        MARCH_EXTRA="-maes"
        ;;
    aarch64)
        MARCH="armv8.1-a"
        MARCH_EXTRA=""
        ;;
    *)
        MARCH="native"
        MARCH_EXTRA=""
        ;;
esac

# ------------------------------------------------------------------
# 5. Global user overrides and quirks
# ------------------------------------------------------------------
[ "$NO_LTO" = "1" ] && LTO=""
[ "$MEM_TRACKING" = "1" ] && CDEFS="$CDEFS -DMEM_TRACKING"

# Clang vs GCC quirks
case "$CC" in
    *clang*) COMPILER_FIXES="-fno-builtin" ;;
    *gcc*|*g++) COMPILER_FIXES="-fno-builtin" ;;
    *) COMPILER_FIXES="" ;;
esac

# ------------------------------------------------------------------
# 6. Final exported variables
# ------------------------------------------------------------------
export CFLAGS="$CFLAGS \
    -fno-pie -fPIC \
    $VISIBILITY $LTO \
    -march=$MARCH $MARCH_EXTRA -mtune=native \
    $COMPILER_FIXES $COVERAGE \
    $EXTRA_CFLAGS"

export LDFLAGS="$LDFLAGS \
    $VISIBILITY $LTO \
    $COVERAGE \
    $EXTRA_LDFLAGS"

export CDEFS

# For debugging – uncomment if you ever need to see what’s being used
# echo "BUILD_MODE=$BUILD_MODE  CC=$CC  CFLAGS=$CFLAGS" >&2
