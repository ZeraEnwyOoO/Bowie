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
 * BOWIE — DHT NODE IMPLEMENTATION
 * ============================================================================
 *
 * Value operations and compact format conversion for a DHT
 * node.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O.
 *   - No routing.
 *   - No policy beyond the Mainline staleness rules.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The XOR distance is computed byte by byte. The two inputs
 * are the same size, so the operation is a simple loop.
 *
 * The first-set-bit function scans the distance from the most
 * significant byte. A byte of zero skips eight positions. The
 * first non-zero byte determines the bit within that byte. The
 * function returns the position from the most significant
 * bit, so a byte with the high bit set returns a multiple of
 * 8.
 *
 * The compact format is the Mainline 26-byte entry. The
 * conversion is the same as the one in the message layer. The
 * two are kept in sync by hand; a future version can move the
 * conversion into this file and have the message layer call
 * it.
 *
 * The staleness rules are Mainline policy. They are applied
 * here, not in the routing layer, because they are properties
 * of a node and not of a bucket.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, token, distance
 *   "dht/node.h"                 the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_dht_node_clear(bowie_dht_node_t *node)
{
    if (node == NULL) {
        return;
    }
    memset(node, 0, sizeof(*node));
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

int bowie_dht_node_is_set(const bowie_dht_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    if (bowie_dht_node_id_is_zero(&node->id)) {
        return 0;
    }
    if (!bowie_addr_is_set(&node->addr)) {
        return 0;
    }
    return 1;
}

int bowie_dht_node_equal(const bowie_dht_node_t *a,
                         const bowie_dht_node_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_dht_node_id_t zero;
    bowie_dht_node_id_clear(&zero);

    const bowie_dht_node_id_t *id_a =
        (a != NULL) ? &a->id : &zero;
    const bowie_dht_node_id_t *id_b =
        (b != NULL) ? &b->id : &zero;

    return bowie_dht_node_id_equal(id_a, id_b);
}

int bowie_dht_node_has_token(const bowie_dht_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    return node->has_token ? 1 : 0;
}

/*
 * ============================================================================
 * DISTANCE
 * ============================================================================
 */

/*
 * Compute the XOR of two 20-byte values.
 */
static void xor20(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

bowie_error_t bowie_dht_distance_between_ids(
    const bowie_dht_node_id_t *a,
    const bowie_dht_node_id_t *b,
    bowie_dht_distance_t      *out)
{
    if (a == NULL || b == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    xor20(a->bytes, b->bytes, out->bytes);
    return BOWIE_OK;
}

bowie_error_t bowie_dht_distance_id_to_hash(
    const bowie_dht_node_id_t   *id,
    const bowie_dht_info_hash_t *hash,
    bowie_dht_distance_t        *out)
{
    if (id == NULL || hash == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    xor20(id->bytes, hash->bytes, out->bytes);
    return BOWIE_OK;
}

int bowie_dht_distance_compare(const bowie_dht_distance_t *a,
                               const bowie_dht_distance_t *b)
{
    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }

    /*
     * Byte-wise comparison from the most significant byte.
     * The distances are always 160 bits, so there is no
     * shorter-prefix case.
     */
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        if (a->bytes[i] < b->bytes[i]) {
            return -1;
        }
        if (a->bytes[i] > b->bytes[i]) {
            return 1;
        }
    }
    return 0;
}

int bowie_dht_distance_first_bit(const bowie_dht_distance_t *d)
{
    if (d == NULL) {
        return -1;
    }

    /*
     * Scan the distance from the most significant byte. The
     * first non-zero byte determines the bit position within
     * the byte. The position is counted from the most
     * significant bit, so a byte with the high bit set
     * returns a multiple of 8.
     *
     * A distance of zero has no set bit; the function
     * returns -1.
     */
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        uint8_t b = d->bytes[i];
        if (b == 0u) {
            continue;
        }

        /*
         * Find the position of the most significant set
         * bit in the byte. The loop counts how many
         * leading zero bits the byte has.
         */
        int leading = 0;
        if (b < 0x10u) { leading += 4; b = (uint8_t)(b << 4); }
        if (b < 0x40u) { leading += 2; b = (uint8_t)(b << 2); }
        if (b < 0x80u) { leading += 1; }

        return (int)(i * 8u) + leading;
    }

    return -1;
}

/*
 * ============================================================================
 * STALENESS AND GOODNESS
 * ============================================================================
 */

int bowie_dht_node_is_fresh(const bowie_dht_node_t *node,
                            bowie_mtime_t now_ms)
{
    if (node == NULL) {
        return 0;
    }
    if (node->last_seen_ms == 0u) {
        /*
         * A node that has never been seen is not fresh.
         * The timestamp of 0 is the unset value.
         */
        return 0;
    }
    if (now_ms < node->last_seen_ms) {
        /*
         * The clock moved backwards. Treat the node as
         * fresh; the alternative is to treat a clock
         * adjustment as a mass node failure.
         */
        return 1;
    }
    return ((now_ms - node->last_seen_ms) <=
            (bowie_mtime_t)BOWIE_DHT_NODE_GOOD_MS) ? 1 : 0;
}

int bowie_dht_node_is_failed(const bowie_dht_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    return (node->fail_count >= 3u) ? 1 : 0;
}

int bowie_dht_node_is_good(const bowie_dht_node_t *node,
                           bowie_mtime_t now_ms)
{
    if (node == NULL) {
        return 0;
    }
    if (bowie_dht_node_is_failed(node)) {
        return 0;
    }
    if (bowie_dht_node_is_fresh(node, now_ms)) {
        return 1;
    }
    /*
     * A node that has ever responded and has not failed
     * three times in a row is good. A node that has never
     * been seen is not good, even if its fail count is
     * zero.
     */
    return (node->last_seen_ms != 0u) ? 1 : 0;
}

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

void bowie_dht_node_seen(bowie_dht_node_t *node,
                         bowie_mtime_t now_ms)
{
    if (node == NULL) {
        return;
    }
    node->last_seen_ms = now_ms;
    node->fail_count   = 0u;
}

void bowie_dht_node_failed(bowie_dht_node_t *node)
{
    if (node == NULL) {
        return;
    }
    if (node->fail_count < UINT32_MAX) {
        node->fail_count++;
    }
}

void bowie_dht_node_set_token(bowie_dht_node_t *node,
                              const bowie_dht_token_t *token)
{
    if (node == NULL) {
        return;
    }
    if (token == NULL) {
        bowie_dht_token_clear(&node->token);
        node->has_token = 0;
        return;
    }

    /*
     * Copy the token. The token's own length is the source
     * of truth; the has_token flag is set when the length
     * is non-zero.
     */
    bowie_dht_token_clear(&node->token);
    if (token->len > 0u) {
        memcpy(node->token.bytes, token->bytes, token->len);
        node->token.len = token->len;
        node->has_token = 1;
    } else {
        node->has_token = 0;
    }
}

/*
 * ============================================================================
 * COMPACT FORMAT
 * ============================================================================
 *
 * The compact node entry is 26 bytes:
 *
 *   20 bytes   node id
 *    4 bytes   IPv4 address, network byte order
 *    2 bytes   port, big-endian
 */

bowie_error_t bowie_dht_node_from_compact(
    bowie_span_t        encoded,
    bowie_dht_node_t   *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (encoded.len != BOWIE_DHT_COMPACT_NODE_LEN) {
        return BOWIE_ERR_FORMAT;
    }
    if (encoded.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Clear the output, then fill the fields that the
     * compact entry carries. The timestamp, the fail
     * count, and the token are left at their default
     * values; the caller fills them when the node is
     * added to the routing table.
     */
    bowie_dht_node_clear(out);

    memcpy(out->id.bytes, encoded.data, BOWIE_DHT_NODE_ID_LEN);

    out->addr.family = BOWIE_AF_INET;
    out->addr.addr[0] = encoded.data[20];
    out->addr.addr[1] = encoded.data[21];
    out->addr.addr[2] = encoded.data[22];
    out->addr.addr[3] = encoded.data[23];
    out->addr.port = (uint16_t)((uint16_t)encoded.data[24] << 8)
                   | (uint16_t)encoded.data[25];

    return BOWIE_OK;
}

bowie_error_t bowie_dht_node_to_compact(
    const bowie_dht_node_t *node,
    uint8_t                *out,
    size_t                  out_cap,
    size_t                 *out_len)
{
    if (node == NULL || out == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out_cap < BOWIE_DHT_COMPACT_NODE_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }
    if (node->addr.family != BOWIE_AF_INET) {
        return BOWIE_ERR_TYPE;
    }

    memcpy(out, node->id.bytes, BOWIE_DHT_NODE_ID_LEN);
    out[20] = node->addr.addr[0];
    out[21] = node->addr.addr[1];
    out[22] = node->addr.addr[2];
    out[23] = node->addr.addr[3];
    out[24] = (uint8_t)((node->addr.port >> 8) & 0xFFu);
    out[25] = (uint8_t)(node->addr.port & 0xFFu);

    *out_len = BOWIE_DHT_COMPACT_NODE_LEN;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
