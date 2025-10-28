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

#ifndef _BIBLE_H
#define _BIBLE_H

#include <libfam/types.h>

/*
 * Constant: BIBLE_SIZE
 * Total size of the embedded Bible text in bytes (4,634,229 bytes).
 */
#define BIBLE_SIZE 4634229

/*
 * Constant: BIBLE_VERSE_COUNT
 * Total number of verses in the Bible (31,107).
 * Indexed from 0 to 31106.
 */
#define BIBLE_VERSE_COUNT 31107

/*
 * Constant: MAX_VERSE_LEN
 * Maximum length of any single verse in bytes (537 bytes).
 * Includes null terminator.
 */
#define MAX_VERSE_LEN 537

/*
 * Type: Bible
 * Structure representing the loaded Bible text and index.
 * members:
 *         u8 *text                       - pointer to full concatenated Bible
 *                                          text.
 *         u32 offsets[BIBLE_VERSE_COUNT] - byte offsets of each verse in text.
 *         u16 lengths[BIBLE_VERSE_COUNT] - length of each verse (including
 *                                          null).
 *         u32 length                     - total length of text (should equal
 *                                          BIBLE_SIZE).
 * notes: Initialized once via init_bible(). Accessed via bible()
 * singleton accessor. All fields are read-only after initialization.
 */
typedef struct {
	u8 *text;
	u32 offsets[BIBLE_VERSE_COUNT];
	u16 lengths[BIBLE_VERSE_COUNT];
	u32 length;
} Bible;

/*
 * Function: init_bible
 * Initializes the global Bible data structure.
 * inputs: None.
 * return value: i32 - 0 on success, -1 on error with errno set.
 * errors:
 *         ENOMEM         - if memory allocation fails.
 *         EIO            - if embedded data is corrupted or inaccessible.
 * notes:
 *         Must be called once before any access via bible().
 *         Idempotent: safe to call multiple times (subsequent calls are
 * no-ops). On failure, bible() will return NULL until successful init.
 */
i32 init_bible(void);

/*
 * Function: bible_verse
 * Copies a specific verse into a caller-provided buffer.
 * inputs:
 *         const Bible *bible - pointer to initialized Bible structure.
 *         u16 verse          - verse index (0 to BIBLE_VERSE_COUNT-1).
 *         u8 buf[MAX_VERSE_LEN] - output buffer for verse text.
 * return value: None.
 * errors: None.
 * notes:
 *         bible must be non-null and initialized.
 *         verse must be in valid range; out-of-bounds results in undefined
 * behavior. buf is null-terminated on success. buf must have at least
 * MAX_VERSE_LEN bytes. Verse text includes book/chapter/verse prefix (e.g.,
 * "Genesis 1:1").
 */
void bible_verse(const Bible *bible, u16 verse, u8 buf[MAX_VERSE_LEN]);

/*
 * Function: bible
 * Returns a pointer to the global initialized Bible structure.
 * inputs: None.
 * return value: const Bible * - pointer to Bible, or NULL if not initialized.
 * errors: None.
 * notes:
 *         Returns the same pointer after successful init_bible().
 *         Thread-safe after initialization.
 *         Caller should check for NULL before use.
 *         Do not free or modify the returned structure.
 */
const Bible *bible(void);

#endif /* _BIBLE_H */
