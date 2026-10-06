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
 * BOWIE — TYPE HELPERS IMPLEMENTATION
 * ============================================================================
 *
 * Value operations for the types in bowie/types.h.
 *
 * Every function here is a pure value operation. There is no
 * allocation, no I/O, and no platform dependency.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No hashing. A hash is a policy decision, not a value
 *     operation, and no Bowie layer has asked for one yet.
 *   - No ordering. Same reason.
 *   - No string formatting or parsing. The wire and display
 *     formats are protocol concerns, not type concerns.
 *   - No address classification. Whether an address is
 *     loopback, private, or global is a policy decision that
 *     belongs to the layer that needs it.
 *   - No random generation. Randomness is a platform service;
 *     it does not belong in a type helper.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The ID helpers are deliberately byte-wise. Peer ID, public ID,
 * session ID, and grant ID are fixed-size byte arrays; two IDs
 * are equal when their bytes are equal, and an ID is unset when
 * its bytes are zero. There is no normalization and no
 * canonical form to compute.
 *
 * The address helper compares only the bytes that are meaningful
 * for the family. An IPv4 address uses the first four bytes of
 * the sixteen-byte payload; the remaining twelve are ignored for
 * comparison. This lets a caller compare addresses without
 * first zeroing the unused bytes.
 *
 * The functions that take a pointer accept NULL and define a
 * behavior for it. The functions that take a value by copy do
 * not need a NULL check.
 *
 * No function here is thread-unsafe. None of them write to
 * global state.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>        memcmp, memset
 *   "bowie/types.h"   the types and the declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"

/*
 * ============================================================================
 * SPANS AND STRINGS
 * ============================================================================
 */

int bowie_span_is_empty(bowie_span_t span)
{
    return (span.len == 0u) ? 1 : 0;
}

int bowie_span_equal(bowie_span_t a, bowie_span_t b)
{
    if (a.len != b.len) {
        return 0;
    }
    if (a.len == 0u) {
        return 1;
    }
    if (a.data == NULL || b.data == NULL) {
        /*
         * One of the spans is malformed. A span with len > 0
         * must have data != NULL. Treat a malformed span as
         * not equal to any other span.
         */
        return 0;
    }
    return (memcmp(a.data, b.data, a.len) == 0) ? 1 : 0;
}

int bowie_str_is_empty(bowie_str_t str)
{
    return (str.len == 0u) ? 1 : 0;
}

int bowie_str_equal(bowie_str_t a, bowie_str_t b)
{
    if (a.len != b.len) {
        return 0;
    }
    if (a.len == 0u) {
        return 1;
    }
    if (a.data == NULL || b.data == NULL) {
        return 0;
    }
    return (memcmp(a.data, b.data, a.len) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * BUFFERS
 * ============================================================================
 */

void bowie_buf_clear(bowie_buf_t *buf)
{
    if (buf == NULL) {
        return;
    }
    buf->len = 0u;
}

/*
 * ============================================================================
 * ADDRESSES
 * ============================================================================
 */

/*
 * Number of meaningful address bytes for a family.
 *
 * Returns 0 for any family that is not a real address family.
 * The caller decides what to do with that; the comparison
 * helpers treat it as "no meaningful bytes".
 */
static size_t addr_byte_count(bowie_af_t family)
{
    switch (family) {
    case BOWIE_AF_INET:
        return BOWIE_IPV4_LEN;
    case BOWIE_AF_INET6:
        return BOWIE_IPV6_LEN;
    default:
        return 0u;
    }
}

void bowie_addr_clear(bowie_addr_t *addr)
{
    if (addr == NULL) {
        return;
    }
    addr->family = BOWIE_AF_UNSPEC;
    memset(addr->addr, 0, sizeof(addr->addr));
    addr->port = 0u;
}

int bowie_addr_is_set(const bowie_addr_t *addr)
{
    if (addr == NULL) {
        return 0;
    }
    return (addr->family == BOWIE_AF_INET ||
            addr->family == BOWIE_AF_INET6) ? 1 : 0;
}

int bowie_addr_equal(const bowie_addr_t *a, const bowie_addr_t *b)
{
    if (a == NULL || b == NULL) {
        /*
         * Two NULL pointers are equal; a NULL and a non-NULL
         * are not.
         */
        return (a == b) ? 1 : 0;
    }

    if (a->family != b->family) {
        return 0;
    }

    size_t n = addr_byte_count(a->family);
    if (n == 0u) {
        /*
         * Both addresses are unset. The family matches (both
         * are BOWIE_AF_UNSPEC), so they are equal.
         */
        return 1;
    }

    if (memcmp(a->addr, b->addr, n) != 0) {
        return 0;
    }

    return (a->port == b->port) ? 1 : 0;
}

/*
 * ============================================================================
 * PEER ID
 * ============================================================================
 */

void bowie_peer_id_clear(bowie_peer_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id->bytes, 0, sizeof(id->bytes));
}

int bowie_peer_id_is_zero(const bowie_peer_id_t *id)
{
    if (id == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_peer_id_equal(const bowie_peer_id_t *a,
                        const bowie_peer_id_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        /*
         * One is NULL and the other is not. The non-NULL side
         * is equal to NULL only when it is all-zero.
         */
        const bowie_peer_id_t *real = (a != NULL) ? a : b;
        return bowie_peer_id_is_zero(real);
    }
    return (memcmp(a->bytes, b->bytes, BOWIE_PEER_ID_LEN) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * PUBLIC ID
 * ============================================================================
 */

void bowie_public_id_clear(bowie_public_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id->bytes, 0, sizeof(id->bytes));
}

int bowie_public_id_is_zero(const bowie_public_id_t *id)
{
    if (id == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_PUBLIC_ID_LEN; i++) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_public_id_equal(const bowie_public_id_t *a,
                          const bowie_public_id_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        const bowie_public_id_t *real = (a != NULL) ? a : b;
        return bowie_public_id_is_zero(real);
    }
    return (memcmp(a->bytes, b->bytes, BOWIE_PUBLIC_ID_LEN) == 0)
           ? 1 : 0;
}

/*
 * ============================================================================
 * SESSION ID
 * ============================================================================
 */

void bowie_session_id_clear(bowie_session_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id->bytes, 0, sizeof(id->bytes));
}

int bowie_session_id_is_zero(const bowie_session_id_t *id)
{
    if (id == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_SESSION_ID_LEN; i++) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_session_id_equal(const bowie_session_id_t *a,
                           const bowie_session_id_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        const bowie_session_id_t *real = (a != NULL) ? a : b;
        return bowie_session_id_is_zero(real);
    }
    return (memcmp(a->bytes, b->bytes, BOWIE_SESSION_ID_LEN) == 0)
           ? 1 : 0;
}

/*
 * ============================================================================
 * GRANT ID
 * ============================================================================
 */

void bowie_grant_id_clear(bowie_grant_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id->bytes, 0, sizeof(id->bytes));
}

int bowie_grant_id_is_zero(const bowie_grant_id_t *id)
{
    if (id == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_GRANT_ID_LEN; i++) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_grant_id_equal(const bowie_grant_id_t *a,
                         const bowie_grant_id_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        const bowie_grant_id_t *real = (a != NULL) ? a : b;
        return bowie_grant_id_is_zero(real);
    }
    return (memcmp(a->bytes, b->bytes, BOWIE_GRANT_ID_LEN) == 0)
           ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
