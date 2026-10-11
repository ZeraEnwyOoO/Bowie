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
 * BOWIE — DHT ROUTING TABLE
 * ============================================================================
 *
 * The Kademlia routing table for a DHT node.
 *
 * The routing table is a list of K-buckets. Each bucket covers
 * a range of the 160-bit ID space. The bucket that holds a
 * node is determined by the position of the first bit where
 * the node's ID differs from the local ID:
 *
 *   bucket 0    the first differing bit is bit 0
 *   bucket 1    the first differing bit is bit 1
 *   ...
 *   bucket i    the first differing bit is bit i
 *
 * The bucket index is computed by the first-set-bit function
 * on the XOR distance between the node ID and the local ID.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network. The routing table does not send packets.
 *   - No search. The lookup algorithm is in search.h.
 *   - No storage. The routing table does not store values.
 *   - No allocation. The table has a fixed capacity.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The number of buckets is fixed at 160, the number of bits in
 * a node ID. A table with 160 buckets covers the whole ID
 * space. A table that grows to 160 buckets is the largest a
 * Kademlia routing table can be for a 160-bit ID.
 *
 * The table starts with one bucket that covers the whole
 * space. When that bucket is full, the table may split it. A
 * split replaces one bucket with two buckets: the old bucket
 * covers the half of the range that contains the local ID,
 * and the new bucket covers the other half.
 *
 * The split rule in this implementation is the simplified
 * one:
 *
 *   - A bucket is split only when it is full and its range
 *     contains the local ID.
 *   - A bucket that does not contain the local ID is never
 *     split. A new node that belongs in such a bucket is
 *     dropped, or cached in the bucket's replacement cache.
 *
 * This is the rule the Mainline DHT uses. It keeps the
 * buckets near the local ID small and the buckets far from
 * the local ID large.
 *
 * The routing table does not know about the bucket's range
 * directly. It uses the first-set-bit function on the
 * distance to determine the bucket index. The index of a
 * bucket is the position of the first bit where the bucket's
 * range differs from the local ID.
 *
 * The table is a value type. It is stored in the DHT engine
 * and copied with the engine. It is not a handle.
 *
 * ----------------------------------------------------------------------------
 * Bucket index
 * ----------------------------------------------------------------------------
 *
 * The index of a node is the position of the most significant
 * set bit in the XOR distance between the node ID and the
 * local ID. A node whose ID is identical to the local ID has
 * no set bit; it is not a valid node for the routing table.
 *
 * The index is in the range [0, 159]. The table's bucket count
 * is the highest index in use plus one.
 *
 * ----------------------------------------------------------------------------
 * Split
 * ----------------------------------------------------------------------------
 *
 * A split replaces the bucket at index i with two buckets.
 * The old bucket covers the half of the range that contains
 * the local ID; the new bucket covers the other half. In
 * terms of the first-set-bit index, a split of bucket i
 * produces the buckets that cover the ranges for bit i and
 * the ranges for the higher bits.
 *
 * The simplified implementation does not track the ranges.
 * It tracks the bucket count. A split of the last bucket
 * increases the bucket count by one. The node that caused the
 * split is re-added to the new bucket.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id
 *   "dht/node.h"                 the node struct
 *   "dht/bucket.h"               the bucket struct
 * ============================================================================
 */

#ifndef BOWIE_DHT_ROUTING_H
#define BOWIE_DHT_ROUTING_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/bucket.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 */

#define BOWIE_DHT_MAX_BUCKETS  160

/*
 * ============================================================================
 * ROUTING TABLE
 * ============================================================================
 */

typedef struct bowie_dht_routing {
    bowie_dht_node_id_t local_id;
    bowie_dht_bucket_t  buckets[BOWIE_DHT_MAX_BUCKETS];
    size_t              bucket_count;
} bowie_dht_routing_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a routing table with a local node ID.
 *
 * The table starts with one bucket that covers the whole ID
 * space. The local ID is copied.
 *
 * Passing NULL for table is a no-op.
 * Passing NULL for local_id clears the table and leaves the
 *   bucket count at one. A table with an unset local ID is
 *   not usable; the caller must set one.
 */
void bowie_dht_routing_init(bowie_dht_routing_t       *table,
                            const bowie_dht_node_id_t *local_id);

/*
 * Reset a routing table to the empty state.
 *
 * The local ID is cleared. The bucket count becomes one, with
 * an empty bucket.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_routing_clear(bowie_dht_routing_t *table);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the number of buckets.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_routing_bucket_count(
    const bowie_dht_routing_t *table);

/*
 * Return the bucket at the given index.
 *
 * Returns NULL if the index is out of range or the table is
 * NULL.
 */
const bowie_dht_bucket_t *bowie_dht_routing_bucket_at(
    const bowie_dht_routing_t *table, size_t index);

/*
 * Return the total number of live nodes in all buckets.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_routing_node_count(
    const bowie_dht_routing_t *table);

/*
 * Compute the bucket index for a node ID.
 *
 * The index is the position of the most significant set bit
 * in the XOR distance between the node ID and the local ID.
 *
 * Returns -1 if the node ID equals the local ID, or if the
 * table or id is NULL.
 */
int bowie_dht_routing_bucket_index(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *id);

/*
 * Find a node in the routing table by ID.
 *
 * Returns a pointer to the node, or NULL if the ID is not in
 * the table.
 */
const bowie_dht_node_t *bowie_dht_routing_find(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *id);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Add or update a node in the routing table.
 *
 * The node is placed in the bucket determined by its ID. If
 * the bucket is full, the table attempts to split it:
 *
 *   - If the bucket's index is 0, or if a split would not
 *     change the bucket's coverage of the node, the split is
 *     not performed. The node is cached in the bucket's
 *     replacement cache.
 *
 *   - Otherwise, the bucket is split and the node is added to
 *     the appropriate half.
 *
 * The split rule is the simplified one: a bucket is split
 * only when its index is greater than 0 and the split can
 * separate the node from the existing nodes. In practice the
 * implementation splits whenever the bucket is full and the
 * bucket count is less than the maximum.
 *
 * The result is the result from the bucket add, except that
 * ADDED and UPDATED are returned as-is and CACHED and
 * CACHE_FULL are returned after a split attempt.
 *
 * The return value tells the caller what happened:
 *
 *   ADDED        the node was added to a live bucket
 *   UPDATED      the node was already present and was
 *                refreshed
 *   CACHED       the node was added to a replacement cache
 *   CACHE_FULL   the node could not be added at all
 *   INVALID      the table or node is not usable
 */
bowie_dht_bucket_add_result_t bowie_dht_routing_add(
    bowie_dht_routing_t    *table,
    const bowie_dht_node_t *node,
    bowie_mtime_t           now_ms);

/*
 * Remove a node from the routing table.
 *
 * The node's bucket is found by its ID. If the node is not in
 * the table, the function returns BOWIE_ERR_NOT_FOUND.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if table or id is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the node is not in the
 *   table.
 */
bowie_error_t bowie_dht_routing_remove(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Record a successful response from a node.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if table or id is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the node is not in the
 *   table.
 */
bowie_error_t bowie_dht_routing_seen(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Record a failed request to a node.
 *
 * The node's bucket is found by its ID. The bucket's failed
 * function is called. The node may be removed if it has
 * failed three times in a row.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if table or id is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the node is not in the
 *   table.
 */
bowie_error_t bowie_dht_routing_failed(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Store the token that a node gave us.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if table or id is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the node is not in the
 *   table.
 */
bowie_error_t bowie_dht_routing_set_token(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    const bowie_dht_token_t   *token);

/*
 * ============================================================================
 * SELECTION
 * ============================================================================
 */

/*
 * Select up to max_nodes nodes closest to a target.
 *
 * The target is a 160-bit ID. The nodes are drawn from all
 * buckets, sorted by XOR distance from the target, closest
 * first. A node that is not good is skipped.
 *
 * The output array is caller-supplied. The number of nodes
 * written is returned through out_count.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 */
bowie_error_t bowie_dht_routing_select_closest(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *target,
    bowie_mtime_t              now_ms,
    bowie_dht_node_t          *out,
    size_t                     out_cap,
    size_t                    *out_count);

/*
 * ============================================================================
 * MAINTENANCE
 * ============================================================================
 */

/*
 * Return the index of the bucket that has not changed for the
 * longest time, or -1 when the table is empty.
 *
 * The caller uses the index to decide which bucket to refresh
 * with a find_node query.
 */
int bowie_dht_routing_stalest_bucket(
    const bowie_dht_routing_t *table);

/*
 * ============================================================================
 * END OF DHT ROUTING
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_ROUTING_H */
