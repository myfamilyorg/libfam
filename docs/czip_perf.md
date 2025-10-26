# Overview

`czip` is a tool designed for high speed compression (speeds like lz4) with better compression than gzip on level 1. So, while it does not acheive the highest level of compressions available, it acheives good levels of compression very fast. Here's a benchmark decompressing the American King James verison of the bible (5X copies):

```
$ time czip resources/akjv5.txt ; ls -l resources/akjv5.txt.cz ; time czip -d resources/akjv5.txt.cz
real	0m0.076s
user	0m0.067s
sys	0m0.015s
-rw-rw-r-- 1 chris chris 8054358 Oct 25 21:09 resources/akjv5.txt.cz
real	0m0.033s
user	0m0.026s
sys	0m0.021s
chris@chris-ThinkPad-E16-Gen-1:~/projects/libfam$ time lz4 --rm resources/akjv5.txt ; ls -l resources/akjv5.txt.lz4; time lz4 -d --rm resources/akjv5.txt.lz4
Compressed filename will be : resources/akjv5.txt.lz4 
Compressed 23171145 bytes into 10764939 bytes ==> 46.46% 
real	0m0.080s
user	0m0.054s
sys	0m0.027s
-rw------- 1 chris chris 10764939 Oct 24 20:00 resources/akjv5.txt.lz4
Decoding file resources/akjv5.txt 
resources/akjv5.txt. : decoded 23171145 bytes
real	0m0.035s
user	0m0.016s
sys	0m0.019s
chris@chris-ThinkPad-E16-Gen-1:~/projects/libfam$ time gzip -1 resources/akjv5.txt ; ls -l resources/akjv5.txt.gz ; time gzip -d resources/akjv5.txt.gz
real	0m0.214s
user	0m0.201s
sys	0m0.013s
-rw------- 1 chris chris 8180597 Oct 24 20:00 resources/akjv5.txt.gz
real	0m0.119s
user	0m0.108s
sys	0m0.011s
```

# Summary

As you might have guessed it was on an E16-Gen-1 Lenovo ThinkPad. This is with a AMD Ryzen Zen3 (avx2) system.

So, to summarize here's a table showing the performance:

| Tool        | Compressed Size | Compression Ratio | Compression Time | Decompression Time | Memory Usage (Compression) |
|-------------|-----------------|-------------------|------------------|--------------------|----------------------------|
| **czip**    | 8.05 MB         | 2.88:1 (34.76%)   | 0.076s           | 0.033s             | <2 MB                      |
| **gzip -1** | 8.18 MB         | 2.83:1 (35.30%)   | 0.214s           | 0.119s             | <2 MB                      |
| **LZ4**     | 10.76 MB        | 2.15:1 (46.46%)   | 0.080s           | 0.035s             | ~9 MB                      |
