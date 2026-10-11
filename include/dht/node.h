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
 * BOWIE — DHT NODE
 * ============================================================================
 *
 * A DHT node as Bowie sees it: the remote peer's identity, its
 * address, when we last heard from it, how many times it has
 * failed, and the token it gave us.
 *
 * The node struct is a value type. It is stored in the routing
 * table and in the search state. It is copied, not referenced.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing. The routing table owns the buckets; this
 *     file owns a single node.
 *   - No I/O. Nothing here sends a packet.
 *   - No policy. Whether a node is "good" or "stale" is a
 *     policy decision made by the routing layer; this file
 *     provides the operations that decision needs.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The node struct carries the fields that the routing layer
 * needs to decide whether to keep a node:
 *
 *   id            identity; also the DHT routing key
 *   addr          where to reach the node
 *   last_seen_ms  for the staleness check
 *   fail_count    for the "good" check
 *   token         the token the node gave us, if any
 *   has_token     1 when token is set
 *
 * The token is the value the node gave us in a get_peers
 * response. It is needed to announce a peer to that node. A
 * node that has not given us a token cannot be announced to.
 * The has_token flag distinguishes "no token yet" from "a
 * token whose bytes happen to be zero".
 *
 * The fail_count is the number of consecutive failures. It is
 * reset to zero on every successful response. It is not a
 * total; a node that fails once, then succeeds, then fails
 * again has a fail_count of 1, not 2.
 *
 * The staleness and goodness rules are Mainline policy:
 *
 *   - A node is "good" if it has responded within the last
 *     15 minutes, or if it has ever responded and has not
 *     failed more than twice in a row.
 *
 *   - A node is "questionable" if it has not responded within
 *     the last 15 minutes and is not yet failed.
 *
 *   - A node is "bad" if it has failed more than twice in a
 *     row.
 *
 * This file does not enforce the rules. It provides the
 * helpers that the routing layer uses to apply them.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, token, distance
 * ============================================================================
 */

#ifndef BOWIE_DHT_NODE_H
#define BOWIE_DHT_NODE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * NODE
 * ============================================================================
 */

typedef struct bowie_dht_node {
    bowie_dht_node_id_t id;
    bowie_addr_t        addr;
    bowie_mtime_t       last_seen_ms;
    uint32_t            fail_count;
    bowie_dht_token_t   token;
    int                 has_token;
} bowie_dht_node_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a node to the unset state.
 *
 * Every field becomes zero. The id is unset, the address is
 * unset, the token is unset, and the has_token flag is
 * cleared.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_node_clear(bowie_dht_node_t *node);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * True when the node has a set id and a set address.
 *
 * A node with an unset id or an unset address is not usable.
 * The function returns 0 for NULL.
 */
int bowie_dht_node_is_set(const bowie_dht_node_t *node);

/*
 * True when two nodes have the same id.
 *
 * Only the id is compared. The address, the timestamp, and
 * the fail count may differ and the nodes are still equal:
 * they identify the same remote node.
 *
 * Two NULL pointers are equal. A NULL pointer and an unset
 * node are equal.
 */
int bowie_dht_node_equal(const bowie_dht_node_t *a,
                         const bowie_dht_node_t *b);

/*
 * True when the node has a token from the remote node.
 *
 * A NULL node returns 0.
 */
int bowie_dht_node_has_token(const bowie_dht_node_t *node);

/*
 * ============================================================================
 * DISTANCE
 * ============================================================================
 *
 * The XOR distance is the core of Kademlia routing. The
 * distance between two node IDs, or between a node ID and an
 * info hash, is the bitwise XOR of the two values.
 */

/*
 * Compute the XOR distance between a node ID and a node ID.
 *
 * The output is a 160-bit value. The distance is symmetric:
 * distance(a, b) == distance(b, a).
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 */
bowie_error_t bowie_dht_distance_between_ids(
    const bowie_dht_node_id_t *a,
    const bowie_dht_node_id_t *b,
    bowie_dht_distance_t      *out);

/*
 * Compute the XOR distance between a node ID and an info
 * hash.
 *
 * The two are the same size, so the operation is the same as
 * distance_between_ids with a different input type.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 */
bowie_error_t bowie_dht_distance_id_to_hash(
    const bowie_dht_node_id_t  *id,
    const bowie_dht_info_hash_t *hash,
    bowie_dht_distance_t       *out);

/*
 * Compare two distances.
 *
 * The comparison is byte-wise from the most significant byte.
 * A shorter prefix is not used; the distances are always 160
 * bits.
 *
 * Returns:
 *   < 0  a is smaller (closer)
 *   = 0  a and b are equal
 *   > 0  a is larger (further)
 *
 * Returns 0 for NULL pointers.
 */
int bowie_dht_distance_compare(const bowie_dht_distance_t *a,
                               const bowie_dht_distance_t *b);

/*
 * Return the index of the first differing bit between a
 * distance and zero.
 *
 * The result is the position of the most significant set bit
 * in the distance, counted from the left (bit 0 is the most
 * significant). A distance of zero has no set bit; the
 * function returns -1.
 *
 * This value is the Kademlia bucket index: a node whose
 * distance has its first set bit at position i belongs in
 * bucket i.
 *
 * Returns -1 for a NULL pointer or a zero distance.
 */
int bowie_dht_distance_first_bit(const bowie_dht_distance_t *d);

/*
 * ============================================================================
 * STALENESS AND GOODNESS
 * ============================================================================
 *
 * The Mainline rules for a good node:
 *
 *   - A node that has responded within the last 15 minutes
 *     is good.
 *   - A node that has ever responded and has failed fewer
 *     than three times in a row is good.
 *   - A node that has failed three or more times in a row is
 *     bad.
 *
 * The helpers below apply the rules. They take the current
 * monotonic time as an argument so that the caller can batch
 * the time read.
 */

/*
 * The staleness threshold: 15 minutes in milliseconds.
 */
#define BOWIE_DHT_NODE_GOOD_MS  (15u * 60u * 1000u)

/*
 * True when the node has been seen within the good window.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_node_is_fresh(const bowie_dht_node_t *node,
                            bowie_mtime_t now_ms);

/*
 * True when the node has failed three or more times in a row.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_node_is_failed(const bowie_dht_node_t *node);

/*
 * True when the node is good: fresh or not failed.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_node_is_good(const bowie_dht_node_t *node,
                           bowie_mtime_t now_ms);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Record a successful response from the node.
 *
 * Sets the last-seen timestamp to now_ms and resets the fail
 * count to zero.
 *
 * Passing NULL for node is a no-op.
 */
void bowie_dht_node_seen(bowie_dht_node_t *node,
                         bowie_mtime_t now_ms);

/*
 * Record a failed request to the node.
 *
 * Increments the fail count. The last-seen timestamp is not
 * changed; a failure does not make a node fresh.
 *
 * Passing NULL for node is a no-op.
 */
void bowie_dht_node_failed(bowie_dht_node_t *node);

/*
 * Set the token the node gave us.
 *
 * The token is copied. The has_token flag is set to 1 when
 * the token has a non-zero length.
 *
 * Passing NULL for node is a no-op. Passing NULL for token
 * clears the token.
 */
void bowie_dht_node_set_token(bowie_dht_node_t *node,
                              const bowie_dht_token_t *token);

/*
 * ============================================================================
 * COMPACT FORMAT
 * ============================================================================
 *
 * A node is stored in the wire format as a 26-byte compact
 * entry. The conversion is the same as the one in the message
 * layer; the two are kept in sync.
 */

/*
 * Decode a compact node entry into a node.
 *
 * The input must be a 26-byte byte string. The node's id,
 * address, and port are filled. The last-seen timestamp, the
 * fail count, and the token are left at their default values.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_FORMAT if the input is not 26 bytes.
 */
bowie_error_t bowie_dht_node_from_compact(
    bowie_span_t        encoded,
    bowie_dht_node_t   *out);

/*
 * Encode a node into a compact node entry.
 *
 * The node's address must be IPv4. The output buffer must be
 * at least 26 bytes.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_TYPE if the address is not IPv4.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is too
 *   small.
 */
bowie_error_t bowie_dht_node_to_compact(
    const bowie_dht_node_t *node,
    uint8_t                *out,
    size_t                  out_cap,
    size_t                 *out_len);

/*
 * ============================================================================
 * END OF DHT NODE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_NODE_H */
