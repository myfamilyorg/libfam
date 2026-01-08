
# Overview

Libfam is a c library that will be the basis a number of other projects. Currently the functionality implemented centers around compression, encryption, and system code.

# Building Libfam

Instructions assume ubuntu minimal, but similar commands are possible with other distros. Basically you need to have a c compiler (clang suggested, but gcc supported), assembler for x64 and 'sh'.
```
# sudo apt update
# sudo apt install clang git
# git clone https://github.com/myfamilyorg/libfam
# cd libfam
# ./build
```

Test can be run with the following command:
```
# ./build test
```

Coverage can be calculated with the following command:
```
# sudo apt install gcc
# ./build cov
```

# Features
* [Storm](storm.md)
* [BiblePOW](biblepow.md)
* [Compression](compression.md)
