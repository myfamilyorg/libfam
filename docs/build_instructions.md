# Overview

    Libfam is a C prgoramming language shared library that can be used to build other tools. The first such example is the czip tool which is part of the 1.0.0 release. czip is a utility that compresses and decompresses files. It demonstrates and showcases some of libfam's functionality.

# Build

    Libfam comes with its own build tool `build`. So, building it only requires that you have bash and a c compiler (clang or gcc). clang is preferred. 

```
    # sudo apt install git clang
    # git clone https://github.com/myfamilyorg/libfam
    # cd libfam
    # ./build
```

To see all options available under build run the help command:
```
    # ./build --help
Usage: build [<target>] [<options> ...]
  where <target> is one of: all | test | cov | install | clean | help
Options:
  -s := run in silent mode (less output)
  --cc=<compiler> := c compiler to use default 'clang'
  --cflags=<cflags> := c flags to use default '-O3 -Werror -Wall -std=x11'
  --f=<filter> := filter to target single test (e.g. --f=alloc1) default: all tests
  --novalgrind := runs tests without valgrind
  --quick := run without flto (link time optimization)
```

# Test

```
    # ./build test
==458043== Memcheck, a memory error detector
==458043== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==458043== Using Valgrind-3.25.1 and LibVEX; rerun with -h for copyright info
==458043== Command: target/bin/runtests
==458043== 
==458043== Warning: set address range perms: large range [0x4df8000, 0x14dfa000) (defined)
Running 68 tests...
--------------------------------------------------------------------------------------------
Running test 1 [rbtree1] [5500µs]
Running test 2 [rbtree2] [104274µs]
Running test 3 [strcmp] [89µs]
Running test 4 [strncpy] [546µs]
Running test 5 [f64_to_string] [10083µs]
Running test 6 [limits] [90µs]
Running test 7 [builtins] [76µs]
Running test 8 [string_chr_cat] [662µs]
Running test 9 [colors] [2422µs]
Running test 10 [errors] [2317µs]
Running test 11 [memmove] [711µs]
Running test 12 [stack_fails] [83µs]
Running test 13 [rand1] [2219µs]
Running test 14 [b64] [3048µs]
Running test 15 [b642] [2230µs]
Running test 16 [aes1] [11547µs]
Running test 17 [sha1] [23527µs]
Running test 18 [rng] [5584µs]
Running test 19 [sha3] [4612µs]
Running test 20 [sha3_others] [1180µs]
Running test 21 [bible1] [1570µs]
Running test 22 [bible2] [718µs]
Running test 23 [atomic] [1086µs]
Running test 24 [atomic_thread64] [872µs]
Running test 25 [atomic_thread32] [853µs]
Running test 26 [bitmap1] [863µs]
Running test 27 [bitmap2] [2788µs]
Running test 28 [bitmap_max] [3079µs]
Running test 29 [string_u128_fns] [207311µs]
Running test 30 [stubs] [72µs]
Running test 31 [memory] [4325µs]
Running test 32 [alloc1] [24231µs]
Running test 33 [alloc2] [133932µs]
Running test 34 [alloc3] [970µs]
Running test 35 [alloc_map] [13641µs]
Running test 36 [resize1] [8001µs]
Running test 37 [slab_sizes] [671µs]
Running test 38 [bits_per_slab_index] [600µs]
Running test 39 [alloc_all_slabs] [7139µs]
Running test 40 [sysext] [1602µs]
Running test 41 [futex1] [900µs]
Running test 42 [sys] [4395µs]
Running test 43 [file] [1726µs]
Running test 44 [pipetwo] [936µs]
Running test 45 [pipefork] [902µs]
Running test 46 [signal] [1046µs]
Running test 47 [sock_sys] [2001µs]
Running test 48 [epoll] [1861µs]
Running test 49 [msync] [1664µs]
Running test 50 [format1] [9040µs]
Running test 51 [format2] [8571µs]
Running test 52 [strstr] [82µs]
Running test 53 [fstatat] [1557µs]
Running test 54 [ioruring] [1520µs]
Running test 55 [ioruring_read_file] [2072µs]
Running test 56 [iouring_module] [4840µs]
Running test 57 [iouring_other] [2902µs]
Running test 58 [iouring_spin_wait] [917µs]
Running test 59 [spin_lock] [339µs]
Running test 60 [spin_threads] [875µs]
Running test 61 [bitstream_perf] [264889µs]
Running test 62 [bitstream_overflow] [107µs]
Running test 63 [compress1] [357038µs]
Running test 64 [compress_rand] [75272µs]
Running test 65 [compress_other] [3821µs]
Running test 66 [compress_oob] [64754µs]
Running test 67 [compress_file1] [3749196µs]
Running test 68 [bitstream_partial_masks] [531µs]
--------------------------------------------------------------------------------------------
Success! 68 tests passed! [5161.002 ms]
==458043== 
==458043== HEAP SUMMARY:
==458043==     in use at exit: 0 bytes in 0 blocks
==458043==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated
==458043== 
==458043== All heap blocks were freed -- no leaks are possible
==458043== 
==458043== For lists of detected and suppressed errors, rerun with: -s
==458043== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
#
```

# Coverage

    Coverage is reported through the use of the gcov library.

```
    # ./build cov
...
Success! 68 tests passed! [4263.729 ms]
------------------------------------------------------------------------------------------
base/colors.c        100.00% - [ 10/ 10]
base/debug.c         100.00% - [  0/  0]
base/env.c           100.00% - [ 45/ 45]
base/errno.c         100.00% - [ 50/ 50]
base/rbtree.c        100.00% - [200/200]
base/string.c        100.00% - [114/114]
base/stubs.c         100.00% - [ 10/ 10]
base/syscall.c       100.00% - [ 34/ 34]
base/sysext.c        100.00% - [  3/  3]
base/types.c         100.00% - [  0/  0]
bible/bible.c        100.00% - [ 38/ 38]
bible/debug.c        100.00% - [  0/  0]
compress/bitstream.c 100.00% - [ 40/ 40]
compress/compress.c   99.59% - [481/483]
compress/file.c       81.88% - [234/287]
core/alloc.c         100.00% - [140/140]
core/bitmap.c        100.00% - [ 47/ 47]
core/debug.c         100.00% - [  0/  0]
core/format.c        100.00% - [199/199]
core/iouring.c       100.00% - [124/124]
core/memory.c        100.00% - [ 20/ 20]
core/spin.c          100.00% - [  8/  8]
core/string.c        100.00% - [ 72/ 72]
core/stubs.c         100.00% - [ 38/ 38]
core/syscall.c       100.00% - [286/286]
core/sysext.c        100.00% - [ 80/ 80]
crypto/aes.c         100.00% - [117/117]
crypto/b64.c         100.00% - [ 62/ 62]
crypto/rng.c         100.00% - [ 16/ 16]
crypto/sha1.c        100.00% - [ 80/ 80]
crypto/sha3.c        100.00% - [ 99/ 99]
store/bptree.c       100.00% - [  0/  0]
------------------------------------------------------------------------------------------
Coverage: 97.96% [2647 / 2702]

```

# install

build install installs both the libfam.so library and the czip program on the system.

```
    # sudo ./build install
```

After running this, you should be able to use the czip command.

```
    # czip --help
Usage: czip [OPTION]... [FILE]...
-c, --console       write to standard output, keep files unchanged
-d, --decompress    decompress
-h, --help          print this message
-v, --version       print version

Note: if no file is specified stdin will be used as the input file.
```

# Czip

The czip utility is a gzip-like tool that compresses and decompresses files. You can use it to compress files like so:

```
    # ls -l resources/akjv5.txt 
-rw------- 1 chris chris 23171145 Oct 24 20:00 resources/akjv5.txt
    # md5sum resources/akjv5.txt 
52090bac792917a391136bc1fdfaaf15  resources/akjv5.txt
    # czip resources/akjv5.txt 
    # ls -l resources/akjv5.txt.cz 
-rw-rw-r-- 1 chris chris 8054358 Oct 25 21:38 resources/akjv5.txt.cz
    # czip -d resources/akjv5.txt.cz 
    # md5sum resources/akjv5.txt 
52090bac792917a391136bc1fdfaaf15  resources/akjv5.txt
```
