
# Overview

Libfam is a high-performance, post-quantum-ready, freestanding C library with zero external dependencies.

It provides best-in-class implementations of compression (czip), symmetric cryptography (STORM), hashing (aighthash), CSPRNG, post-quantum KEM/signatures (Kyber/Dilithium with STORM XOF), safe formatting, and a modern test framework — all with 100% test coverage and direct kernel interfaces (io_uring + minimal syscalls).

Designed for systems programming, embedded, servers, and security-critical applications where speed, simplicity, and auditability matter.

# Building Libfam

Instructions assume ubuntu minimal, but similar commands are possible with other distros. Basically you need to have a c compiler (clang suggested, but gcc supported), assembler for x64 and 'sh'.
```
# sudo apt update
# sudo apt install clang git
# git clone https://github.com/myfamilyorg/libfam
# cd libfam
# ./build
# sudo ./build install
```

# Example usage

```
    // test.c
    #include <libfam/format.h>
    #include <libfam/main.h>

    i32 main(i32 argc, u8 **argv, u8 **envp) {
        println("Hello from libfam — {} + {} = {}", 1, 1, 2);
        return 0;
    }
```

```
# clang -ffreestanding -nostdlib test.c -lfam
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
