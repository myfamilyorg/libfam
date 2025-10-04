#!/bin/bash

clang -lfam -Wno-pointer-sign -fno-builtin -Isrc/include etc/czip.c -flto -o ./target/bin/czip
