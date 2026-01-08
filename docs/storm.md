# Overview
Storm is a symmetric encryption algorithm. It uses AES-NI instructions, but is not AES. The core idea is that since the input to the first AES-NI instruction is xored with a secret state, an attacker can never know the input to the AES-NI instructions. Additionally, after the first AES-NI instruction, the result is folded from hi to lo and a lane swap occurs. Finally state is saved. This ensures full 256 bit avalanche. At this point, two additional AES-NI instructions separate the output from the state. Since the secret state remains unknown, an attacker would never know the plaintext to the operation and thus not be able to use the standard techniques against AES.

# Code analysis

While, neon and scalar versions exist, we'll analyze the avx2 version.

```
STATIC void storm_next_block_avx2(StormContext *ctx, u8 buf[32]) {
        StormContextImpl *st = (StormContextImpl *)ctx; // get opaque type
        __m256i p = _mm256_load_si256((const __m256i *)buf); // load the input into a SIMD register
        __m256i x = _mm256_xor_si256(*(const __m256i *)st->state, p); // xor input with secret state
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key0); // aesenc operation on input/secret state
        __m128i lo = _mm256_castsi256_si128(x); // extract low bits
        __m128i hi = _mm256_extracti128_si256(x, 1); // extract high bits
        lo = _mm_xor_si128(lo, hi); // fold high bits into low bits
        *(__m256i *)st->state = _mm256_set_m128i(lo, hi); // lane swap and save state
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key1); // aesenc operation
        x = _mm256_xor_si256(*(__m256i *)st->state, x); // xor with secret state
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key2); // separate x from secret state further
        x = _mm256_aesenc_epi128(x, *(__m256i *)st->key3); // final aesenc
        _mm256_store_si256((__m256i *)buf, x); // store output to buffer
}
```

# Storm as a stream cipher

In addition to the storm_next_block function, storm provides a storm_xcrypt_buffer function. This function allows storm to be used as a stream cipher. The function simply incorporates a counter that is used as the input to the storm_next_block function. Since it is called in the same order by sender/reciever, the values are deterministic. Note that all four 64 bit lanes of the counter are incremented in the same operation. This allows for fast updates and 2^64 counter states, which is sufficient.

# Storm as an AEAD

Unlike AES, storm is stateful. Therefore, a previous state cannot be recreated. This means that even if I know that the counter is of value x, I can't call storm_xcrypt_buffer again with the value x and expect the same result. This means that there is no need for any sort of hashing like poly or ghash to authenticate the stream. So, a simple format like:
```
[message length]
[payload]
[16 byte tag - all 0x0]
```
can be used to authenticate a stream. The reason this works is because the recipient knows the message length and therefore expects 16 bytes of 0x0 at the end of the message. If anything other than this is encountered at the end of the message, the message is rejected and the stream is closed. An attacker cannot forge the message because modifying the stream would alter the tag. This is because the state is different.

# Performance

Performance is measured on an AMD Ryzen - zen3 bogomips: 3993.00.

| Algorithm     | Performance |
|---------------|-------------|
| **Storm**     | 17.4 GB/s   |
| AES-256-CTR   | 9.7 GB/s    |
| AES-256-GCM   | 8.5 GB/s    |
