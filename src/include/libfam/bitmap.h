/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#ifndef _BITMAP_H
#define _BITMAP_H

#include <libfam/types.h>

/*
 * Constant: PAGE_SIZE
 * Size of a memory page in bytes (4096).
 * Used to align bitmap storage and calculate overhead.
 */
#define PAGE_SIZE 4096

/*
 * Type: BitMap
 * Opaque structure representing a dynamic bitmap.
 * notes:
 *         Must be initialized with bitmap_init before use.
 *         Internally manages memory for bit storage.
 *         Thread-safe only with external synchronization.
 */
typedef struct BitMap BitMap;

/*
 * Function: bitmap_bound
 * Calculates the maximum size in bytes of the bitmap
 * inputs:
 *         u64 bits - total number of bits in the bitmap.
 * return value: u64 - number of bytes needed to store the bitmap.
 * errors: None.
 * notes:
 *         Result is always a multiple of 8.
 *         Includes no padding or alignment overhead.
 *         Use to pre-allocate storage or estimate memory usage.
 */
u64 bitmap_bound(u64 bits);

/*
 * Function: bitmap_size
 * Returns the actual storage size of the initialized bitmap in bytes.
 * inputs:
 *         BitMap *bmp - pointer to initialized bitmap.
 * return value: u64 - size of internal storage in bytes.
 * errors: None.
 * notes:
 *         bmp must be non-null and initialized.
 *         May be larger than bitmap_bound due to alignment or internal
 * metadata. Useful for memory accounting and debugging.
 */
u64 bitmap_size(BitMap *bmp);

/*
 * Function: bitmap_init
 * Initializes a bitmap capable of tracking the given number of bits.
 * inputs:
 *         BitMap *bmap - pointer to uninitialized BitMap structure.
 *         u64 bits     - total number of bits to manage (must be > 0).
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         EINVAL         - if bmap is NULL or bits == 0.
 * notes:
 *         bmap must be a valid pointer to a BitMap object (not allocated).
 */
i32 bitmap_init(BitMap *bmap, u64 bits);

/*
 * Function: bitmap_find_free_bit
 * Finds and atomically claims the lowest free bit in the bitmap.
 * inputs:
 *         BitMap *bmap - pointer to initialized bitmap.
 * return value: i64 - index of claimed bit (0 to bits-1), or -1 if full.
 * errors: None.
 * notes:
 *         bmap must be non-null and initialized.
 *         Returns the lowest-indexed zero bit and sets it to 1.
 *         Thread-safe with respect to other bitmap_find_free_bit calls.
 *         Returns -1 if no free bits remain.
 */
i64 bitmap_find_free_bit(BitMap *bmap);

/*
 * Function: bitmap_release_bit
 * Releases a previously claimed bit back to the free pool.
 * inputs:
 *         BitMap *bmap - pointer to initialized bitmap.
 *         u64 bit      - index of bit to release.
 * return value: None.
 * errors: None.
 * notes:
 *         bmap must be non-null and initialized.
 *         bit must be in range [0, bits-1] and currently set (1).
 *         Passing an out-of-range or already-free bit results in undefined
 * behavior. panics if bit is invalid
 */
void bitmap_release_bit(BitMap *bmap, u64 bit);

#endif /* _BITMAP_H */
