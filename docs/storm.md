# Overview

Storm is a symmetric encryption algorithm that leverages AES-NI instructions without being AES itself. Its core security property stems from XORing the plaintext input with a secret internal state before the first AES-NI round. This ensures that an attacker can never observe the true input to any `aesenc` operation.

After the first round, the result is folded (high lane XORed into low lane) and a lane swap is performed before updating the saved state — guaranteeing full 256-bit avalanche. Two additional keyed AES-NI rounds then further separate the output from the internal state. Because the secret state remains hidden throughout, an attacker lacks the known plaintext-ciphertext pairs needed to apply standard differential or linear cryptanalysis against AES.

# Code Analysis

While NEON and scalar versions exist, we will focus on the AVX2 implementation.

```c
STATIC void storm_next_block_avx2(StormContext *ctx, u8 buf[32]) {
        StormContextImpl *st = (StormContextImpl *)ctx; // access opaque implementation
        __m256i p = _mm256_load_si256((const __m256i *)buf); // load plaintext block
        __m256i x = _mm256_xor_si256(*(const __m256i *)st->state, p); // mask with secret state
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key0); // first keyed AES round
        __m128i lo = _mm256_castsi256_si128(x); // extract low 128 bits
        __m128i hi = _mm256_extracti128_si256(x, 1); // extract high 128 bits
        lo = _mm_xor_si128(lo, hi); // fold high into low for full avalanche
        *(__m256i *)st->state = _mm256_set_m128i(lo, hi); // lane swap and update state
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key1); // second keyed round
        x = _mm256_xor_si256(*(__m256i *)st->state, x); // second state masking
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key2); // third round
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key3); // final round
        _mm256_store_si256((__m256i *)buf, x); // write ciphertext block
}
```

# Storm as a stream cipher

In addition to `storm_next_block`, the library provides `storm_xcrypt_buffer`, which turns Storm into a high-performance stream cipher. This function uses an internal 256-bit counter as input to `storm_next_block`. Since sender and receiver call it in identical order, the keystream is deterministic. All four 64-bit counter lanes are incremented simultaneously using a single SIMD addition, enabling fast updates and a 2⁶⁴ block counter space — more than sufficient for any practical use.


# Storm as an AEAD

Unlike traditional block ciphers, Storm is inherently stateful — previous states cannot be recreated. This means that even if an attacker knows a counter value x, they cannot replay storm_xcrypt_buffer with x and obtain the same keystream. Consequently, no additional hashing (e.g., Poly1305 or GHASH) is required for authentication. A simple authenticated format is therefore possible:

```
[message length]
[payload]
[16-32 byte tag - all 0x0]
```
The receiver, knowing the declared length, expects the final 16–32 bytes to be zeros after decryption. Any deviation means the message was tampered with, and the stream is rejected. An attacker cannot forge a valid message because any modification alters the internal state evolution, resulting in incorrect padding.

# Performance

Performance is measured on an AMD Ryzen - zen3 bogomips: 3993.00.

| Algorithm     | Performance |
|---------------|-------------|
| **Storm**     | 17.4 GB/s   |
| AES-256-CTR   | 9.7 GB/s    |
| AES-256-GCM   | 8.5 GB/s    |

# Examples

```
// xof.c
#include <libfam/format.h>
#include <libfam/main.h>
#include <libfam/storm.h>

i32 main(i32 argc, u8 **argv, u8 **envp) {
        StormContext ctx;
        __attribute__((aligned(32))) u8 buffer[32];
        __attribute__((aligned(32))) const u8 SEED[32] = {
            1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

        storm_init(&ctx, SEED);
        storm_next_block(&ctx, buffer);
        print("random1: [");
        for (u32 i = 0; i < 32; i++) {
                print("{X}", buffer[i]);
                if (i != 31) print(", ");
        }
        println("]");
        storm_next_block(&ctx, buffer);
        print("random2: [");
        for (u32 i = 0; i < 32; i++) {
                print("{X}", buffer[i]);
                if (i != 31) print(", ");
        }
        println("]");

        storm_next_block(&ctx, buffer);
        print("random3: [");
        for (u32 i = 0; i < 32; i++) {
                print("{X}", buffer[i]);
                if (i != 31) print(", ");
        }
        println("]");

        return 0;
}
```

```
clang -ffreestanding -nostdlib xof.c -o xof -lfam
./xof
```

```
// cipher.c
#include <libfam/format.h>
#include <libfam/main.h>
#include <libfam/storm.h>

i32 main(i32 argc, u8 **argv, u8 **envp) {
        StormContext ctx;
        __attribute__((aligned(32))) const u8 SEED[32] = {1, 2, 3};
        __attribute__((aligned(32))) u8 buffer1[32] = {0};
        __attribute__((aligned(32))) u8 buffer2[32] = {0};
        __attribute__((aligned(32))) u8 buffer3[32] = {0};

        storm_init(&ctx, SEED);
        memcpy(buffer1, "test1", 32);
        storm_xcrypt_buffer(&ctx, buffer1);
        memcpy(buffer2, "test2", 32);
        storm_xcrypt_buffer(&ctx, buffer2);
        memcpy(buffer3, "blahblah", 32);
        storm_xcrypt_buffer(&ctx, buffer3);

        StormContext ctx2;
        storm_init(&ctx2, SEED);

        print("buffer1[ciphertext]=[");
        for (u32 i = 0; i < 32; i++) {
                print("{}", buffer1[i]);
                if (i != 31) print(", ");
        }
        println("]");
        storm_xcrypt_buffer(&ctx2, buffer1);
        println("buffer1[plaintext]='{}'", buffer1);
        print("buffer2[ciphertext]=[");
        for (u32 i = 0; i < 32; i++) {
                print("{}", buffer2[i]);
                if (i != 31) print(", ");
        }
        println("]");
        storm_xcrypt_buffer(&ctx2, buffer2);
        println("buffer2[plaintext]='{}'", buffer2);
        print("buffer3[ciphertext]=[");
        for (u32 i = 0; i < 32; i++) {
                print("{}", buffer3[i]);
                if (i != 31) print(", ");
        }
        println("]");
        storm_xcrypt_buffer(&ctx2, buffer3);
        println("buffer3[plaintext]='{}'", buffer3);
        return 0;
}
```

```
clang -ffreestanding -nostdlib cipher.c -o cipher -lfam
./cipher
```
