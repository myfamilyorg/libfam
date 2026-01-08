# Overview

Bible POW (Proof of work) is a proof of work function that utilizes the Bible (American King James Version) and extends it in a deterministic way. It requires a 16 MiB dataset (based on a ~1.6 MiB compressed version of the bible) text to work. So, it is a memory hard proof of work function. The design goal is not necessarily to be ASIC resistant, although, the 16 MiB data set makes ASICs non-trivial. The main goal is to be energy efficient (whether executed by ASIC or CPU). The reason for using the Bible as the data set is to ensure its survival. If there is an economic requirement to store a specific text, it will tend to be stored. Since Bible POW is not possible to execute without having a copy of these specific ~ 1.6 MiB of bible data, it will naturally require the text's preservation.

# Discussion of code

The `bible_hash` function has two main parts:

* Absorb phase - absorb the input header (128 byte header value).
* Hash phase - LOOKUP_ROUNDS (32) iterations of 32 byte loads followed by trivial mixing of the data.

## Absorb phase

The goal of the absorb phase is to completely absorb the header value. We use a 128 byte header here and typically the last 32 bits would be used as a nonce (as seen in the mining function).

```
        for (u64 quarter = 0; quarter < 4; quarter++) { // split 128 byte input into 4 quarters (32 bytes each)
                // lookup the value based on our 16 MiB range.
                u64 r =
                    (u64)b->data +
                    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
                // get pointer to header quarter
                const u8 *quarter_data = input + quarter * 32;
                const u8 *in = (const u8 *)d;

#ifdef USE_AVX2
                *(__m256i *)d = _mm256_load_si256((const __m256i *)r); // load data (avx2)
#else
                fastmemcpy(d, (void *)r, 32); // load data scalar
#endif /* !USE_AVX2 */

                // xor the input values with this current value
                d[0] ^= ((u64 *)quarter_data)[0];
                d[1] ^= ((u64 *)quarter_data)[1];
                d[2] ^= ((u64 *)quarter_data)[2];
                d[3] ^= ((u64 *)quarter_data)[3];

                // use an sbox operation to mix the value in a way that's dependent on all 32 bytes of the read value.
                for (int lane = 0; lane < 4; lane++) {
                        u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
                                 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
                                 in[lane + 24] ^ in[lane + 28];
                        s[lane] ^= sbox[idx];
                }
        }

```

Next we iterate LOOKUP_ROUNDS times (32) to do additional mixing in the same manner as above.

## Hash phase

```
        for (u64 i = 0; i < LOOKUP_ROUNDS; i++) {
                u64 r =
                    (u64)b->data +
                    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
                const u8 *in = (const u8 *)d;
#ifdef USE_AVX2
                *(__m256i *)d = _mm256_load_si256((const __m256i *)r);
#else
                fastmemcpy(d, (void *)r, 32);
#endif /* !USE_AVX2 */

                for (i32 lane = 0; lane < 4; lane++) {
                        u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
                                 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
                                 in[lane + 24] ^ in[lane + 28];

                        s[lane] ^= sbox[idx];
                }
        }
```

The end result is that to determine the hash value, you need to do a total of 36 memory lookups which are random accross this 16 MiB dataset. The memory lookups far outweigh any other operations (xor, add, and shift) and thus whether on ASIC or CPU, the majority of the time is spend waiting for memory latency. This results in an energy efficient proof of work function.

# SBOX generation

The SBOX is generated in a simple deterministic way:

```
PUBLIC void bible_sbox8_64(u64 sbox[256]) {
        __attribute__((aligned(32))) u8 buf[32] = {0};
        StormContext ctx;
        storm_init(&ctx, BIBLE_SBOX_DOMAIN);

        u8 *sbox_u8 = (void *)sbox;
        for (u32 i = 0; i < 256 / 4; i++) {
                storm_next_block(&ctx, buf);
                fastmemcpy(sbox_u8 + i * 32, buf, 32);
        }
}
```

# bible_gen function

The bible extended data is also generated in a deterministic way. Importantly we ensure that the cost to compute the next index in the data set is 1024X more computationally difficult than simply lookup up the value in the lookup table:

```
#define STORM_ITER (LOOKUP_ROUNDS * 1024)

...

        for (u64 offset = (xxdir_file_size_0 + 31) & ~31;
             offset < EXTENDED_BIBLE_SIZE; offset += 32) {
                for (u32 i = 0; i < STORM_ITER; i++)
                        storm_next_block(&ctx, buffer);

...
```

This results in it being more cost effective to simply store the 16 MiB data than to try to precalculate it in any way.

# bible_expand function

The bible expand function decompresses the bible data and stores it in the provided buffer. This allows actual usage of the bible data for desired purposes.

# CPU choice

Before ASICs exist for Bible POW, the question may arise: which CPU/GPU is best to use to mine BiblePOW? What it ultimately comes down to is that the goal of Bible POW is to make it inpractical to do anything other than to do these 36 memory lookups (and associated processing). There's really no shortcuts that we see. So, what that means is that Bible POW is essentially a "proof of memory memory latency" algorithm. Now, in most systems (in 2026), that means we're waiting for DRAM to load. In some cases, the L3 cache may fit a significant portion (or all of the dataset). This essentially never fits into L2 cache though as current L2 cache sizes are much smaller. So, we have this case where highend CPUs might benefit from L3 cache speeds and low end systems would need to use slower DRAM to access the dataset. So, while L3 caches are faster (perhaps around 10X faster), they are still shared accross all CPUs so, you only get something like a 10X boost in performance. But that comes at the higher cost of the large L3 cache. Since over 95% of the time will be spent waiting for this shared memory lookup, there is no real benefit to multi-cores beyond perhaps 2-4 threads (which essentially all CPUs have in 2026). So, the bottom line is that CPUs with larger L3 caches (>16 MiB) might do well and CPUs that have less than 16 MiB, but are much less expensive may also do fairly well and have a similar ROI. The bottom line is that you will probably be able to mine Bible POW on essentially whatever CPU you currently have, but it will not make much sense to buy high end server CPUs (like a threadripper or similar) because they will not add significant capabilities beyond having the larger L3 cache. So, the economics become: might as well use whatever you have, it's a sunk cost. No need to buy specialized hardware to mine Bible POW.

# Bible preservation

It's worth noting that the total size of the built libfam.so shared object is 1.7 MiB. This includes the 1.58 MiB czip compressed bible data and all the tools to decompress and use it (czip, storm, etc). There are no external dependencies (even libc) as the code relies solely on inline assembly calls to the minimal number of linux system calls it uses. So with this small self contained binary, the entire Bible can be transmitted and decompressed. This is meant to help ensure its survival and preservation. As far as we can tell this is the minimal amount of data and code required to preserve the text of the Bible in this form.
