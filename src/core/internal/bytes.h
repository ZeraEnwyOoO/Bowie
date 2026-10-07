
/*
 * Bowie — P2P Internet Sharing Tool (Repo: bowie)
 * Copyright (C) 2026 ASBM Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * ============================================================================
 * BOWIE — BYTES (INTERNAL)
 * ============================================================================
 *
 * Buffer cursor and byte serialization helpers.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. A cursor is a view over a caller-owned
 *     buffer. The caller owns the storage.
 *   - No I/O. Nothing here reads or writes a file, a socket, or
 *     a log.
 *   - No bounds-checked reads or writes beyond the cursor's own
 *     length. A caller that wants a length to be enforced must
 *     check the cursor's remaining length first, or use the
 *     return value of the get/put function.
 *   - No byte-order detection. The endian functions are used
 *     for every multi-byte read or write.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A cursor is a borrowed view over a byte buffer. It records a
 * position and a length; it does not own the buffer. Two
 * cursors over the same buffer are independent.
 *
 * A cursor is used in two directions:
 *
 *   - As a reader: the caller initializes it over a filled
 *     buffer, then calls the get functions in order. The
 *     position advances by the number of bytes read. A short
 *     buffer is reported by the return value, not by a crash.
 *
 *   - As a writer: the caller initializes it over an empty
 *     buffer, then calls the put functions in order. The
 *     position advances by the number of bytes written. A
 *     buffer that is too small is reported by the return value,
 *     not by a crash.
 *
 * The get functions return a status and write the value
 * through an out pointer. This is the same shape as the rest
 * of the internal API: a function that can fail reports
 * failure, and a function that cannot fail does not.
 *
 * The put functions return the number of bytes written, or 0
 * on failure. A caller that needs to know the total number of
 * bytes written accumulates the return values.
 *
 * The length-prefixed helpers (lp8) read and write a
 * single-byte length followed by that many bytes. The length
 * is an unsigned 8-bit value, so the maximum payload is 255
 * bytes. A longer payload is an error, not a silent truncation.
 *
 * The constant-time comparison (equal_ct) is used for
 * comparing secrets. It runs in time proportional to the
 * length, regardless of where the first difference is. A
 * regular memcmp would leak the position of the first
 * difference through timing.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t, uint16_t, uint32_t,
 *                                 uint64_t
 *   <stddef.h>                    size_t
 *   "bowie/err.h"                 bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_BYTES_H
#define BOWIE_CORE_INTERNAL_BYTES_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CURSOR
 * ============================================================================
 *
 * A borrowed view over a byte buffer.
 *
 * The data pointer is not owned. The caller must keep the
 * underlying storage valid for the lifetime of the cursor.
 *
 * The position is the offset of the next byte to read or
 * write. It is always in the range 0..len.
 *
 * The length is the total size of the buffer. It is set when
 * the cursor is initialized and does not change.
 */

typedef struct bowie_cursor {
    uint8_t *data;
    size_t   len;
    size_t   pos;
} bowie_cursor_t;

/*
 * Initialize a cursor over a buffer.
 *
 * The cursor does not own the buffer. Passing a NULL data
 * pointer with len == 0 is valid and produces an empty cursor.
 * Passing a NULL data pointer with len > 0 is a caller bug;
 * the cursor is created but every get and put will fail.
 *
 * Passing NULL for the cursor itself is a no-op.
 */
void bowie_cursor_init(bowie_cursor_t *c, void *data, size_t len);

/*
 * Reset a cursor to the beginning of its buffer. The length is
 * not changed.
 */
void bowie_cursor_reset(bowie_cursor_t *c);

/*
 * Return the number of bytes remaining between the position and
 * the end of the buffer.
 *
 * A NULL cursor returns 0.
 */
size_t bowie_cursor_remaining(const bowie_cursor_t *c);

/*
 * ============================================================================
 * READ — FIXED-WIDTH
 * ============================================================================
 *
 * Read a fixed-width integer in a defined byte order and
 * advance the cursor.
 *
 * Each function writes the value through an out pointer and
 * returns:
 *
 *   BOWIE_OK            on success.
 *   BOWIE_ERR_NULL_ARG  if the cursor or the out pointer is
 *                       NULL.
 *   BOWIE_ERR_TOO_SMALL if the cursor does not have enough
 *                       bytes remaining.
 *
 * On failure the cursor is not advanced and the out pointer is
 * not modified.
 */

bowie_error_t bowie_cursor_get_be16(bowie_cursor_t *c, uint16_t *out);
bowie_error_t bowie_cursor_get_be32(bowie_cursor_t *c, uint32_t *out);
bowie_error_t bowie_cursor_get_be64(bowie_cursor_t *c, uint64_t *out);

bowie_error_t bowie_cursor_get_le16(bowie_cursor_t *c, uint16_t *out);
bowie_error_t bowie_cursor_get_le32(bowie_cursor_t *c, uint32_t *out);
bowie_error_t bowie_cursor_get_le64(bowie_cursor_t *c, uint64_t *out);

/*
 * ============================================================================
 * READ — RAW
 * ============================================================================
 *
 * Read n raw bytes into a caller-supplied buffer and advance
 * the cursor.
 *
 * Returns BOWIE_OK on success, or one of the errors above. On
 * failure the cursor is not advanced.
 */
bowie_error_t bowie_cursor_get_raw(bowie_cursor_t *c,
                                   void *dst,
                                   size_t n);

/*
 * Advance the cursor by n bytes without reading.
 *
 * Returns BOWIE_OK on success, or BOWIE_ERR_TOO_SMALL if the
 * cursor does not have enough bytes remaining.
 */
bowie_error_t bowie_cursor_skip(bowie_cursor_t *c, size_t n);

/*
 * ============================================================================
 * READ — LENGTH-PREFIXED
 * ============================================================================
 *
 * Read a one-byte length, then read that many bytes.
 *
 * The length byte is read first. If it is larger than the
 * remaining space, the cursor is not advanced and the function
 * returns BOWIE_ERR_TOO_SMALL.
 */

/*
 * Read a length-prefixed byte string into a caller-supplied
 * buffer.
 *
 * On success, *out_len is the number of bytes read. The buffer
 * must be large enough; the function does not know the buffer
 * capacity and will overflow it if the encoded length is
 * larger than the buffer.
 *
 * A caller that wants a bounds check must pass a buffer that
 * is at least 255 bytes, or read the length byte first.
 */
bowie_error_t bowie_cursor_get_lp8(bowie_cursor_t *c,
                                   void *dst,
                                   size_t dst_cap,
                                   size_t *out_len);

/*
 * Read a length-prefixed string into a caller-supplied buffer
 * and NUL-terminate it.
 *
 * The buffer must be at least (max_len + 1) bytes. The
 * encoded length must be at most max_len; a longer payload is
 * BOWIE_ERR_TOO_LARGE.
 */
bowie_error_t bowie_cursor_get_lp8_str(bowie_cursor_t *c,
                                       char *dst,
                                       size_t max_len,
                                       size_t *out_len);

/*
 * ============================================================================
 * WRITE — FIXED-WIDTH
 * ============================================================================
 *
 * Write a fixed-width integer in a defined byte order and
 * advance the cursor.
 *
 * Each function returns the number of bytes written (2, 4, or
 * 8), or 0 on failure. Failure means the cursor or its data
 * pointer is NULL, or the cursor does not have enough room.
 *
 * On failure the cursor is not advanced.
 */

size_t bowie_cursor_put_be16(bowie_cursor_t *c, uint16_t v);
size_t bowie_cursor_put_be32(bowie_cursor_t *c, uint32_t v);
size_t bowie_cursor_put_be64(bowie_cursor_t *c, uint64_t v);

size_t bowie_cursor_put_le16(bowie_cursor_t *c, uint16_t v);
size_t bowie_cursor_put_le32(bowie_cursor_t *c, uint32_t v);
size_t bowie_cursor_put_le64(bowie_cursor_t *c, uint64_t v);

/*
 * ============================================================================
 * WRITE — RAW
 * ============================================================================
 *
 * Write n raw bytes from a caller-supplied buffer and advance
 * the cursor.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
size_t bowie_cursor_put_raw(bowie_cursor_t *c,
                            const void *src,
                            size_t n);

/*
 * Write n zero bytes and advance the cursor.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
size_t bowie_cursor_put_zero(bowie_cursor_t *c, size_t n);

/*
 * ============================================================================
 * WRITE — LENGTH-PREFIXED
 * ============================================================================
 *
 * Write a one-byte length, then write that many bytes.
 *
 * The length must fit in an unsigned 8-bit value; a payload
 * longer than 255 bytes returns 0 and writes nothing.
 */

/*
 * Write a length-prefixed byte string.
 *
 * Returns the number of bytes written (1 + n), or 0 on
 * failure.
 */
size_t bowie_cursor_put_lp8(bowie_cursor_t *c,
                            const void *src,
                            size_t n);

/*
 * Write a length-prefixed NUL-terminated string.
 *
 * The string is written without its terminator. The length is
 * the result of strlen(). A string longer than 255 bytes
 * returns 0 and writes nothing.
 */
size_t bowie_cursor_put_lp8_str(bowie_cursor_t *c, const char *s);

/*
 * ============================================================================
 * UTILITIES
 * ============================================================================
 */

/*
 * True when every byte of p is zero.
 *
 * A NULL p returns true. A p with n == 0 returns true.
 *
 * This is the same operation as bowie_mem_is_zero, exposed
 * here so that a caller can use one header for byte work.
 */
int bowie_bytes_is_zero(const void *p, size_t n);

/*
 * Constant-time comparison of two byte strings of length n.
 *
 * Returns 1 when the two are equal, 0 when they differ.
 *
 * The running time depends only on n, not on the contents.
 * This is the comparison to use for secrets: a regular memcmp
 * returns as soon as it finds a difference, and the position
 * of the first difference can be recovered from the timing.
 *
 * Two NULL pointers with n == 0 return 1 (equal). A NULL
 * pointer with n > 0 returns 0 (not equal).
 */
int bowie_bytes_equal_ct(const void *a, const void *b, size_t n);

/*
 * ============================================================================
 * END OF INTERNAL BYTES
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_BYTES_H */
