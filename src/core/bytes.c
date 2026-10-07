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
 * BOWIE — BYTES IMPLEMENTATION
 * ============================================================================
 *
 * Buffer cursor and byte serialization helpers.
 *
 * The implementation is byte-by-byte. Multi-byte reads and
 * writes go through the endian helpers, so there is no unaligned
 * access and no assumption about the host's byte order.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. A cursor is a view over a caller-owned
 *     buffer.
 *   - No I/O. Nothing here reads or writes a file, a socket, or
 *     a log.
 *   - No bounds check beyond the cursor's own length. A caller
 *     that wants a stricter check must do it before calling.
 *   - No byte-order detection. The endian helpers do that.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The cursor invariant is:
 *
 *     0 <= pos <= len
 *
 * Every function that advances pos preserves the invariant. A
 * function that cannot satisfy the invariant leaves the cursor
 * untouched and reports the failure.
 *
 * The get and put functions use a common shape:
 *
 *   - Check for NULL cursor or NULL data.
 *   - Check for enough room (len - pos).
 *   - On success, advance pos and store the value.
 *   - On failure, do not advance pos and do not store.
 *
 * The put functions return the number of bytes written, or 0
 * on failure. The get functions return BOWIE_OK or an error
 * code. The difference is deliberate: a put is used in a
 * sequence where the caller accumulates the count, while a get
 * is used in a sequence where the caller checks each step.
 *
 * The length-prefixed helpers (lp8) write a single length byte
 * followed by the payload. The length byte is an unsigned
 * 8-bit value, so the maximum payload is 255 bytes. A longer
 * payload is rejected before any byte is written, so a caller
 * never sees a half-written message.
 *
 * The constant-time comparison is written so that the loop
 * reads every byte of both inputs and accumulates the
 * difference in a single accumulator. The compiler cannot
 * short-circuit this loop, because the loop condition does not
 * depend on the data.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>                  memcpy, memset
 *   "bowie/err.h"               error codes
 *   "core/internal/endian.h"    byte-order helpers
 *   "core/internal/bytes.h"     the declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/err.h"
#include "core/internal/endian.h"
#include "core/internal/bytes.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 *
 * A small helper for the room check. It returns the number of
 * bytes remaining, or 0 if the cursor or its data is NULL.
 */

static size_t cursor_room(const bowie_cursor_t *c)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (c->pos >= c->len) {
        return 0u;
    }
    return c->len - c->pos;
}

/*
 * A small helper that advances the cursor by n bytes.
 *
 * The caller must have already checked the room. This function
 * does not check anything.
 */
static void cursor_advance(bowie_cursor_t *c, size_t n)
{
    c->pos += n;
}

/*
 * ============================================================================
 * CURSOR
 * ============================================================================
 */

void bowie_cursor_init(bowie_cursor_t *c, void *data, size_t len)
{
    if (c == NULL) {
        return;
    }
    c->data = (uint8_t *)data;
    c->len  = len;
    c->pos  = 0u;
}

void bowie_cursor_reset(bowie_cursor_t *c)
{
    if (c == NULL) {
        return;
    }
    c->pos = 0u;
}

size_t bowie_cursor_remaining(const bowie_cursor_t *c)
{
    return cursor_room(c);
}

/*
 * ============================================================================
 * READ — FIXED-WIDTH
 * ============================================================================
 */

bowie_error_t bowie_cursor_get_be16(bowie_cursor_t *c, uint16_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 2u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_be16_get(c->data + c->pos);
    cursor_advance(c, 2u);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_be32(bowie_cursor_t *c, uint32_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 4u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_be32_get(c->data + c->pos);
    cursor_advance(c, 4u);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_be64(bowie_cursor_t *c, uint64_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 8u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_be64_get(c->data + c->pos);
    cursor_advance(c, 8u);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_le16(bowie_cursor_t *c, uint16_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 2u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_le16_get(c->data + c->pos);
    cursor_advance(c, 2u);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_le32(bowie_cursor_t *c, uint32_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 4u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_le32_get(c->data + c->pos);
    cursor_advance(c, 4u);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_le64(bowie_cursor_t *c, uint64_t *out)
{
    if (c == NULL || out == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < 8u) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out = bowie_le64_get(c->data + c->pos);
    cursor_advance(c, 8u);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * READ — RAW
 * ============================================================================
 */

bowie_error_t bowie_cursor_get_raw(bowie_cursor_t *c,
                                   void *dst,
                                   size_t n)
{
    if (c == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (n == 0u) {
        return BOWIE_OK;
    }
    if (dst == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < n) {
        return BOWIE_ERR_TOO_SMALL;
    }
    memcpy(dst, c->data + c->pos, n);
    cursor_advance(c, n);
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_skip(bowie_cursor_t *c, size_t n)
{
    if (c == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cursor_room(c) < n) {
        return BOWIE_ERR_TOO_SMALL;
    }
    cursor_advance(c, n);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * READ — LENGTH-PREFIXED
 * ============================================================================
 */

bowie_error_t bowie_cursor_get_lp8(bowie_cursor_t *c,
                                   void *dst,
                                   size_t dst_cap,
                                   size_t *out_len)
{
    if (c == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cursor_room(c) < 1u) {
        return BOWIE_ERR_TOO_SMALL;
    }

    uint8_t len = c->data[c->pos];

    if (cursor_room(c) < (size_t)1u + (size_t)len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if (len > 0u && dst == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if ((size_t)len > dst_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if (len > 0u) {
        memcpy(dst, c->data + c->pos + 1u, len);
    }

    cursor_advance(c, (size_t)1u + (size_t)len);

    if (out_len != NULL) {
        *out_len = (size_t)len;
    }
    return BOWIE_OK;
}

bowie_error_t bowie_cursor_get_lp8_str(bowie_cursor_t *c,
                                       char *dst,
                                       size_t max_len,
                                       size_t *out_len)
{
    if (c == NULL || c->data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cursor_room(c) < 1u) {
        return BOWIE_ERR_TOO_SMALL;
    }

    uint8_t len = c->data[c->pos];

    if (cursor_room(c) < (size_t)1u + (size_t)len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if ((size_t)len > max_len) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (dst == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (len > 0u) {
        memcpy(dst, c->data + c->pos + 1u, len);
    }
    dst[len] = '\0';

    cursor_advance(c, (size_t)1u + (size_t)len);

    if (out_len != NULL) {
        *out_len = (size_t)len;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * WRITE — FIXED-WIDTH
 * ============================================================================
 */

size_t bowie_cursor_put_be16(bowie_cursor_t *c, uint16_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 2u) {
        return 0u;
    }
    (void)bowie_be16_put(c->data + c->pos, v);
    cursor_advance(c, 2u);
    return 2u;
}

size_t bowie_cursor_put_be32(bowie_cursor_t *c, uint32_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 4u) {
        return 0u;
    }
    (void)bowie_be32_put(c->data + c->pos, v);
    cursor_advance(c, 4u);
    return 4u;
}

size_t bowie_cursor_put_be64(bowie_cursor_t *c, uint64_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 8u) {
        return 0u;
    }
    (void)bowie_be64_put(c->data + c->pos, v);
    cursor_advance(c, 8u);
    return 8u;
}

size_t bowie_cursor_put_le16(bowie_cursor_t *c, uint16_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 2u) {
        return 0u;
    }
    (void)bowie_le16_put(c->data + c->pos, v);
    cursor_advance(c, 2u);
    return 2u;
}

size_t bowie_cursor_put_le32(bowie_cursor_t *c, uint32_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 4u) {
        return 0u;
    }
    (void)bowie_le32_put(c->data + c->pos, v);
    cursor_advance(c, 4u);
    return 4u;
}

size_t bowie_cursor_put_le64(bowie_cursor_t *c, uint64_t v)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (cursor_room(c) < 8u) {
        return 0u;
    }
    (void)bowie_le64_put(c->data + c->pos, v);
    cursor_advance(c, 8u);
    return 8u;
}

/*
 * ============================================================================
 * WRITE — RAW
 * ============================================================================
 */

size_t bowie_cursor_put_raw(bowie_cursor_t *c,
                            const void *src,
                            size_t n)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (n == 0u) {
        return 0u;
    }
    if (src == NULL) {
        return 0u;
    }
    if (cursor_room(c) < n) {
        return 0u;
    }
    memcpy(c->data + c->pos, src, n);
    cursor_advance(c, n);
    return n;
}

size_t bowie_cursor_put_zero(bowie_cursor_t *c, size_t n)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (n == 0u) {
        return 0u;
    }
    if (cursor_room(c) < n) {
        return 0u;
    }
    memset(c->data + c->pos, 0, n);
    cursor_advance(c, n);
    return n;
}

/*
 * ============================================================================
 * WRITE — LENGTH-PREFIXED
 * ============================================================================
 */

size_t bowie_cursor_put_lp8(bowie_cursor_t *c,
                            const void *src,
                            size_t n)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (n > 255u) {
        return 0u;
    }
    if (n > 0u && src == NULL) {
        return 0u;
    }
    if (cursor_room(c) < (size_t)1u + n) {
        return 0u;
    }

    c->data[c->pos] = (uint8_t)n;
    if (n > 0u) {
        memcpy(c->data + c->pos + 1u, src, n);
    }
    cursor_advance(c, (size_t)1u + n);
    return (size_t)1u + n;
}

size_t bowie_cursor_put_lp8_str(bowie_cursor_t *c, const char *s)
{
    if (c == NULL || c->data == NULL) {
        return 0u;
    }
    if (s == NULL) {
        return 0u;
    }

    size_t len = strlen(s);
    if (len > 255u) {
        return 0u;
    }

    return bowie_cursor_put_lp8(c, s, len);
}

/*
 * ============================================================================
 * UTILITIES
 * ============================================================================
 */

int bowie_bytes_is_zero(const void *p, size_t n)
{
    if (p == NULL || n == 0u) {
        return 1;
    }

    const unsigned char *bytes = (const unsigned char *)p;
    for (size_t i = 0u; i < n; i++) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_bytes_equal_ct(const void *a, const void *b, size_t n)
{
    if (n == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }

    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;

    /*
     * Accumulate the difference in a single accumulator. The
     * loop reads every byte of both inputs, so the running time
     * depends only on n.
     */
    unsigned int diff = 0u;
    for (size_t i = 0u; i < n; i++) {
        diff |= (unsigned int)(pa[i] ^ pb[i]);
    }

    return (diff == 0u) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
