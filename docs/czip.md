# Overview

`czip` is a tool that uses the libfam library compression functions. It has similar functionality to gzip. When you [build](https://myfamilyorg.github.io/libfam/build_instructions) the Libfam project, `czip` is be included and will be installed as well. `czip` is designed to be very fast while still achieving a moderately high level of compression. The compression/decompression speeds are faster than lz4 with significantly better compression levels which are better than gzip -1. In addition to the performance, `czip` uses minmal resources. `czip` is single threaded and uses less memory than either gzip -1 or lz4. See table below.

# Performance

The performance metrics are measured against the file in resources ./resources/akjv5.txt. This is a copy of the American King James bible text with 5 copies. The total size of the file is 23.17 MB. They are tested using Clang 18.1.3 using Linux 6.14.0-33 on a AMD Ryzen Zen 3 processor (6 core / 12 thread) running at 2.944 Ghz.

| Compression Tool        | Compressed Size | Compression Ratio | Compression Time | Decompression Time | Memory Usage (Compression) | Memory Usage (Decompression) |
|-------------|-----------------|-------------------|------------------|--------------------|----------------------------|------------------------------|
| **czip**    | 7.96 MB         | 2.91:1 (34.36%)   | 0.076s           | 0.033s             | 1.8 MB                     | 1.3 MB                       |
| **gzip -1** | 8.18 MB         | 2.83:1 (35.30%)   | 0.214s           | 0.119s             | 1.8 MB                      | 1.5 MB                        |
| **LZ4**     | 10.76 MB        | 2.15:1 (46.46%)   | 0.080s           | 0.035s             | 9.7 MB                      | 1.6 MB                       |

# Example Usage

`czip` is designed to function similarly to gzip. `czip` can be used to compress files and decompress them using the -d option. Additionally, redirect to/from stdin/stdout and pipe in other commands is available. Examples:

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

This example shows redirection with the console option for both compression and decompression.

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

Here is the full help option output.

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

# Design/Architecture

`czip` is designed to be fast with moderately good compression ratios. The way this is achieved is through several techniques. The [Zstandard](https://github.com/Cyan4973/FiniteStateEntropy) project has documented clearly the benefits of Finite State Entropy (FSE). However, as noted, huffman codes are significantly faster than FSE. While, Huffman codes generally have similar results with respect to encoding literals (which is why they are used in the Zstandard project for literals in most cases), FSE is superior for encoding length and distance codes which have skewed distributions. To solve this problem, without the use of FSE, we combine the length and distance codes into a single `match code`. Match codes have a code combined with length extra bits and distance extra bits. So, for instance match code 0 has 0 length/distance extra bits while match code 1 has 0 length extra bits and a single distance extra bits. This resolves the skew problem because in DEFLATE like schemes, length codes 3-7 are highly skewed as are distance codes 1-8. By combining them (into a single code), the skew is decreased. This decrease is significant enough that the ideal huffman length of these codes is now greater than 1 for most data sets. We now have the benefits of using huffman codes for non-skewed data. Additionally, we efficiently use the codes. The only difference between each code is how many extra bits are available to that code. So, each distance code has one more extra bit than the previous one and each length code has one more extra bit than the previous one. This leads to efficient calculation of these values, for instance:

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

These values can be determined with simple arithmetic calculations. This leads to the performance results that have been noted above (faster than lz4 on compression and decompression with better compression ratios than zlib level 1). In addition this results in very little memory usage as noted and a much simpler code base than FSE based implementations. The core of the compression library is roughly 1,500 lines of code.

Another advantage comes from using an least significant bit (LSB) bitstream. By using an LSB bitstream, we do not need to reverse the bits on little-endian systems and can therefore simply dereference a 64 bit unsigned integer in and out of the input/output. This allows for faster bitstream operations than, the more common MSB bitstreams that most projects use. To do this, we have to use no-common-suffix cannonical huffman codes as opposed to the more common no-common-prefix cannonical huffman codes. That way we can still take advantage of a lookup table. The lookup table is simply inverted from the regular no-common-prefix lookup tables.

A third advantage comes from our highly efficient hashtable. The size of the hashtable is small (128kb) so it is stored on the stack. By having this size fixed, we can use a shift of 16 bits and avoid an additional modulus opertaion. We also avoid many operations by simply assuming that the existing value is a match and checking it (either with scalar operations or SIMD where supported). But basically this allows for an almost completely branchless section of code where we determine matches and non-matches. See code below:

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

This function both gets and sets the target offset in the text with very little branching. This is possible due to the exact sizes of the hashtable and the fact that we can cast values from a u32 into a u16. We also take advantage of the fact that the maximum match length is 256. The SIMD instructions continue while len < MAX_MATCH_LEN (256). Because this is divisible by 256 we don't need an additional tail loop because we know we find the correct length which is either 256 or a partial match where mask != 0xFFFFFFFF. Additionally we increment len with a branchless addition. Additionally we use tail processing to ensure the reads of up to 32 bytes out are valid and do not involve undefined behavior.

Regarding decompression, as is customary we build a lookup table, but we store additional information in the lookup table values that reduces the computation time when we find a match. See data structure below:

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

This allows us to calculate these values once, when we build the lookup table and use them for our entire block.

# What's not implemented

While some implementations use multi-threading, we have not implemented multi-threading in the core library. This is something that could be implemented, but currently we expect to implement multi-threading in our upcoming database implementation and thus building it directly into the core compression library would be redundant. However, the core compression/decompression functions are highly conducive to performance improvements from multi-threading. That's because the blocks are completely self contained. Since compress_block/decompress_block only support up to 256kb blocks, that means a file that's several megabytes or larger could be parallelized by chunking the file into 256kb blocks and compressing/decompressing in parallel. That's something that could be done, but for now we are deferring this in favor of simplicity and our priorities of the database implementation.
