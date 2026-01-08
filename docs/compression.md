# Overview

`czip`, a core component of the libfam library, is a multi-process, high-performance compression utility. It was developed with a specific focus on optimizing compression for structured data, particularly text, and excels in resource-constrained environments. It also outperforms the alterntives for practically any workload when speed is a priority.

# Build/install

`czip` is part of libfam. When you build/install libfam, czip is also installed:

```
cd libfam
./build
sudo ./build install
```

czip can then be found in /usr/local/bin.

# Performance

- **Test Data**: A 23.17 MB text file containing repeated sections of text. **Five copies of the American King James Version of the bible from github.com/bible-hub**
- **Hardware**: AMD Ryzen Zen 3 (6-core / 12-thread) @ 2.944 GHz.
- **Software**: Clang 18.1.3, Linux 6.14.0-33.
- **Notes**: The `zstd` benchmark was run with --fast=1. gzip and lz4 are ran with the -1 option (fastest).

| Compression Tool        | Compressed Size | Compression Ratio | Compression Time | Decompression Time | Memory Usage (Compression) | Memory Usage (Decompression) |
|-------------|-----------------|-------------------|------------------|--------------------|----------------------------|------------------------------|
| **czip**    | 7.6 MB         | 3.03:1 (33.04%)   | 0.025s           | 0.018s             | 0.7 MB (per core)     | 0.7 MB (per core)                      |
| **gzip** | 7.9 MB | 2.91 (34.35%) | 0.220s | 0.121s | 1.8 MB (per core) | 1.5 MB (per core) |
| **zstd**    | 8.5 MB   | 2.71 (36.96%)           | 0.087s           | 0.024s             | 22.8 MB (per core)                    | 5.0 MB (per core)           |
| **LZ4**     | 11.0 MB        | 2.09:1 (47.82%)   | 0.076s           | 0.034s             | 9.7 MB  (per core)                    | 1.6 MB (per core)  |


# Usage

```
$ ls -l resources/test_wikipedia.txt 
-rw-rw-r-- 1 chris chris 97265 Dec 26 10:56 resources/test_wikipedia.txt
$ czip resources/test_wikipedia.txt 
$ ls -l resources/test_wikipedia.txt.cz 
-rw------- 1 chris chris 40936 Jan  8 13:10 resources/test_wikipedia.txt.cz
$ czip -d resources/test_wikipedia.txt.cz 
$ ls -l resources/test_wikipedia.txt 
-rw-rw-r-- 1 chris chris 97265 Dec 26 10:56 resources/test_wikipedia.txt
$ czip --help
Usage: czip [OPTION]... [FILE]...
-c, --console       write to standard output, keep files unchanged
-d, --decompress    decompress
-h, --help          print this message
-v, --version       print version
-k, --keep          keep original file

Note: if no file is specified stdin will be used as the input file.
```

# Architectural Overview

`czip` achieves its speed and memory efficiency through several key design choices, focusing on algorithmic simplicity and hardware optimization.

**Combined Match Codes for Huffman Efficiency**

`czip` sidesteps the need for more complex encoding schemes like Finite State Entropy (FSE) by addressing the skewed distribution of length and distance codes typically seen in DEFLATE-like schemes.

- **Problem**: In DEFLATE-like implementations, the distribution of length codes (3-7) and distance codes (1-8) is highly skewed, favoring short codes. FSE is often used to handle this, but it is computationally more intensive than Huffman coding and uses more resources as well. In addition the implementation of FSE is quite complex leading to a greater attack surface and more ongoing maintenance.

- **czip Solution**: Length and distance codes are combined into a single "match code." This normalizes the statistical distribution of the codes, making them suitable for efficient Huffman coding.

- **Benefit**: This allows czip to leverage the speed of Huffman coding for all code types, resulting in faster compression and decompression than many FSE-based implementations. The core compression logic is also significantly smaller (approx. 1,500 lines of code).

- **Implementation**: The code values are derived using simple bitwise arithmetic, as seen in the following C functions:

```
static inline u16 get_match_code(u16 len, u32 dist) {
        u32 len_bits = 31 - clz_u32(len - 3);
        u32 dist_bits = 31 - clz_u32(dist);
        return ((len_bits << LEN_SHIFT) | dist_bits);
}

static inline u8 length_extra_bits(u8 match_code) {
        return match_code >> LEN_SHIFT;
}

static inline u8 distance_extra_bits(u8 match_code) {
        return match_code & DIST_MASK;
}
```

## Least Significant Bit (LSB) Bitstream

- By using an LSB bitstream, czip avoids the need for bit-reversal on little-endian systems (the majority of modern hardware), leading to faster bitstream operations.

- To support LSB processing, czip uses a "no-common-suffix" canonical Huffman coding scheme, allowing it to efficiently use lookup tables.

## High-Performance LZ77 Hashtable

`czip` utilizes a highly optimized LZ77 hashtable for fast pattern matching.

- **Stack-Allocated**: The table's fixed size (128 KB) allows it to be allocated on the stack, benefiting from cache locality.

- **Branchless Matching**: The match-finding logic is designed to be nearly branchless. It assumes a match exists, retrieves the candidate position, and then verifies it, which is highly efficient on modern CPUs.

- **SIMD Acceleration**: On systems with AVX2 support, the match-checking loop is replaced with SIMD instructions (_mm256_cmpeq_epi8), allowing for 32-byte comparisons in a single instruction and further accelerating performance.


