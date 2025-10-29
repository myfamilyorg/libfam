# LibFam

[![CI Pipeline](https://github.com/myfamilyorg/libfam/actions/workflows/main.yml/badge.svg)](https://github.com/myfamilyorg/libfam/actions/workflows/main.yml)
[![Release Version](https://img.shields.io/github/v/release/myfamilyorg/libfam.svg?color=blue)](https://github.com/myfamilyorg/libfam/releases)
[![Documentation](https://img.shields.io/static/v1?label=Documentation&message=Github+Pages&color=orange)](https://myfamilyorg.github.io/libfam/)
[![License](https://img.shields.io/github/license/myfamilyorg/libfam.svg)](https://github.com/myfamilyorg/libfam/blob/master/LICENSE)
[![Stars](https://img.shields.io/github/stars/myfamilyorg/libfam.svg?style=social)](https://github.com/myfamilyorg/libfam/stargazers)

<p align="center">
    <img src="docs/MyFamilyLogo.png" alt="Logo">
</p>

LibFam is a lightweight C library with no dependencies, supporting the My Family project (https://www.myfamilyworldwide.org/) to unite the Body of Christ through efficient software. Version 1.0.0 provides compression functionality which can be used to store and share scripture, messages, videos, and images, with a `gzip`-like tool called [czip](https://myfamilyorg.github.io/libfam/czip). [Alloc](https://myfamilyorg.github.io/libfam/alloc) and [Formatting](https://myfamilyorg.github.io/libfam/formatting)
are also core features within the release. Future releases will add a database/file system for further connectivity as well as other features. LibFam runs on Linux x64 and arm64.

From myfamilyworldwide.org: "Using this identifying name, My Family, individuals, groups, and organizations could declare themselves as part of the universal Body of Christ, no longer separated by differing doctrinal statements, but unified through the common belief in the God of Jesus Christ as represented within Scripture."

## Installation

Required: git and clang or gcc and minimal Linux install. clang suggested.

```
# sudo apt update
# sudo apt install clang git
# git clone https://github.com/myfamilyorg/libfam
# cd libfam
# ./build
# ./build test --novalgrind
# sudo ./build install
# czip --help
Usage: czip [OPTION]... [FILE]...
-c, --console       write to standard output, keep files unchanged
-d, --decompress    decompress
-h, --help          print this message
-v, --version       print version

Note: if no file is specified stdin will be used as the input file.
```

> “Just as a body, though one, has many parts, but all its many parts form one body, so it is with Christ. For we were all baptized by one Spirit so as to form one body—whether Jews or Gentiles, slave or free—and we were all given the one Spirit to drink. Even so the body is not made up of one part but of many.”
> — **1 Corinthians 12:12-14**

