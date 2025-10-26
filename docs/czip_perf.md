# Overview

`czip` is a tool that uses the libfam library compression functions. It's designed to be very fast while still achieving a moderately high level of compression. The compression/decompression speeds are comparable to lz4 with significantly better compression levels which are comparable to gzip -1. Additionally, czip uses significantly less memory than lz4. In addition to the performance, it uses minmal resources. It is single threaded and uses less memory than either gzip -1 or lz4. See table below.

# Performance

The performance metrics are measured against the file in resources ./resources/akjv5.txt. This is a copy of the American King James bible text with 5 copies. The total size of the file is 23.17 MB. They are tested using Clang 18.1.3 using Linux 6.14.0-33 on a AMD Ryzen Zen 3 processor (6 core / 12 thread) running at 2.944 Ghz.

| Compression Tool        | Compressed Size | Compression Ratio | Compression Time | Decompression Time | Memory Usage (Compression) | Memory Usage (Decompression) |
|-------------|-----------------|-------------------|------------------|--------------------|----------------------------|------------------------------|
| **czip**    | 7.96 MB         | 2.91:1 (34.36%)   | 0.076s           | 0.033s             | 1.8 MB                     | 1.3 MB                       |
| **gzip -1** | 8.18 MB         | 2.83:1 (35.30%)   | 0.214s           | 0.119s             | 1.8 MB                      | 1.5 MB                        |
| **LZ4**     | 10.76 MB        | 2.15:1 (46.46%)   | 0.080s           | 0.035s             | 9.7 MB                      | 1.6 MB                       |
