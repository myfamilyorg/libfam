# Overview

**Czip: An Optimized Compression Tool for libfam**

`czip`, a core component of the libfam library, is a single-threaded, high-performance compression utility. It was developed with a specific focus on optimizing compression for structured data, particularly text, and excels in resource-constrained environments.

# Performance Comparison

- **Test Data**: A 23.17 MB text file containing repeated sections of text. **Five copies of the American King James Version of the bible from github.com/bible-hub**
- **Hardware**: AMD Ryzen Zen 3 (6-core / 12-thread) @ 2.944 GHz.
- **Software**: Clang 18.1.3, Linux 6.14.0-33.
- **Notes**: The `zstd` benchmark was run with --single-thread --fast=1.

| Compression Tool        | Compressed Size | Compression Ratio | Compression Time | Decompression Time | Memory Usage (Compression) | Memory Usage (Decompression) |
|-------------|-----------------|-------------------|------------------|--------------------|----------------------------|------------------------------|
| **czip**    | 7.96 MB         | 2.91:1 (34.36%)   | 0.076s           | 0.033s             | 1.8 MB                     | 1.3 MB                       |
| **gzip -1** | 8.18 MB         | 2.83:1 (35.30%)   | 0.214s           | 0.119s             | 1.8 MB                      | 1.5 MB                        |
| **zstd**    | 8.82 MB   | 2.62 (38.10%)           | 0.079s           | 0.023s             | 22.8 MB                     | 5.0 MB            |
| **LZ4**     | 10.76 MB        | 2.15:1 (46.46%)   | 0.080s           | 0.035s             | 9.7 MB                      | 1.6 MB                       |

# Usage

`czip` provides a command-line interface designed to be familiar to gzip users.

```
$ ls -l 
total 96
-rw------- 1 chris chris 97265 Oct 15 14:55 test_wikipedia.txt
$ czip test_wikipedia.txt
$ ls -l
total 44
-rw-rw-r-- 1 chris chris 41280 Oct 26 08:53 test_wikipedia.txt.cz
$ czip -d test_wikipedia.txt.cz
$ ls -l 
total 96
-rw------- 1 chris chris 97265 Oct 15 14:55 test_wikipedia.txt
```

## Input/Output redirection.

```
$ cat test_wikipedia.txt | czip -c > ./test_wikipedia2.txt.cz   
$ ls -l
total 140
-rw-rw-r-- 1 chris chris 41280 Oct 26 08:55 test_wikipedia2.txt.cz
-rw------- 1 chris chris 97265 Oct 15 14:55 test_wikipedia.txt
$ cat test_wikipedia2.txt.cz | czip -dc > ./test_wikipedia2.txt
$ diff test_wikipedia.txt test_wikipedia2.txt
$ 
```

## Help menu.

```
$ czip --help
Usage: czip [OPTION]... [FILE]...
-c, --console       write to standard output, keep files unchanged
-d, --decompress    decompress
-h, --help          print this message
-v, --version       print version

Note: if no file is specified stdin will be used as the input file.
$ 
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

```
STATIC MatchInfo lz_hash_get(LzHash *restrict hash, const u8 *restrict text,
                             u32 cpos) {
        u16 pos, dist, len = 0;
        u32 mpos, key = *(u32 *)(text + cpos);
        pos = hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT];
        hash->table[(key * HASH_CONSTANT) >> HASH_SHIFT] = cpos;
        dist = (u16)cpos - pos;
        if (!dist) return (MatchInfo){.len = 0, .dist = 0};
        mpos = cpos - dist;

#ifdef __AVX2__
        u32 mask;
        do {
                __m256i vec1 =
                    _mm256_loadu_si256((__m256i *)(text + mpos + len));
                __m256i vec2 =
                    _mm256_loadu_si256((__m256i *)(text + cpos + len));
                __m256i cmp = _mm256_cmpeq_epi8(vec1, vec2);
                mask = _mm256_movemask_epi8(cmp);

                len += (mask != 0xFFFFFFFF) * __builtin_ctz(~mask) +
                       (mask == 0xFFFFFFFF) * 32;
        } while (mask == 0xFFFFFFFF && len < MAX_MATCH_LEN);
#else
        while (len < MAX_MATCH_LEN && text[mpos + len] == text[cpos + len])
                len++;
#endif /* !__AVX2__ */

        return (MatchInfo){.len = len, .dist = dist};
}
```

## Lookup table efficiency

All needed data is built into the lookup tables allowing for fast decoding of codes.

```
typedef struct {
        u16 symbol;
        u16 length;
        u8 dist_extra_bits;
        u8 len_extra_bits;
        u16 base_dist;
        u8 base_len;
} HuffmanLookup;
```

# Multi-threading

While czip's core compression and decompression functions are designed for high parallelization, multithreading has not been implemented in the core library. This decision was made to keep the implementation simple and prioritize development of the upcoming database implementation. Files can be parallelized by an application that chunks the data into 256KB blocks and processes them concurrently.
