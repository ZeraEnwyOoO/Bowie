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
 * BOWIE — DHT BUCKET
 * ============================================================================
 *
 * A K-bucket for the Mainline DHT routing table.
 *
 * A K-bucket holds up to K nodes whose IDs share a common
 * prefix with the local node ID. The bucket covers one range
 * of the 160-bit ID space. The routing table is a list of
 * buckets, each covering a smaller range as the table grows.
 *
 * The bucket is a value type. It is stored in the routing
 * table and copied with the table. It is not a handle.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing table. The routing table owns the list of
 *     buckets and decides which bucket a node belongs in.
 *     This file owns a single bucket.
 *   - No I/O. Nothing here sends a packet.
 *   - No allocation. The bucket has a fixed capacity.
 *   - No policy on when to split. Splitting a bucket is a
 *     routing-table decision, not a bucket decision.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The bucket has two arrays:
 *
 *   nodes         the live nodes, up to BOWIE_DHT_K
 *   replacements  the cached nodes that can take a live
 *                 node's place if it fails
 *
 * Both arrays are fixed-size. The bucket does not allocate.
 *
 * The replacement cache is the Mainline answer to the
 * "stale node" problem. When a live node fails, the routing
 * table promotes a node from the replacement cache into the
 * live set. The cache is a small FIFO; a new replacement
 * pushes out the oldest one when the cache is full.
 *
 * The bucket tracks the time of the last change. The routing
 * table uses this to decide when to refresh a bucket by
 * sending a find_node query for a random ID in the bucket's
 * range.
 *
 * The bucket does not enforce the Kademlia distance rule. It
 * does not know which range it covers; the routing table
 * knows. The bucket is a container.
 *
 * A node is added with bowie_dht_bucket_add. The function
 * returns a result code that tells the caller what happened:
 *
 *   ADDED        the node was added to the live set
 *   UPDATED      the node was already in the live set; its
 *                timestamp was refreshed
 *   CACHED       the live set was full; the node was added
 *                to the replacement cache
 *   CACHE_FULL   the live set and the replacement cache were
 *                both full; the node was not added
 *
 * The caller uses the result to decide whether to split the
 * bucket, evict a node, or drop the new node.
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
 * ============================================================================
 */

#ifndef BOWIE_DHT_BUCKET_H
#define BOWIE_DHT_BUCKET_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 *
 * BOWIE_DHT_K is the Mainline bucket size. It is 8 in the
 * BitTorrent DHT specification. A smaller K makes the table
 * shallower; a larger K makes each lookup ask more nodes.
 *
 * BOWIE_DHT_REPLACEMENT is the size of the replacement cache.
 * It is a policy choice; the specification does not fix a
 * value. Four is a reasonable small number.
 */

#define BOWIE_DHT_K             8
#define BOWIE_DHT_REPLACEMENT   4

/*
 * ============================================================================
 * ADD RESULT
 * ============================================================================
 */

typedef enum bowie_dht_bucket_add_result {
    BOWIE_DHT_BUCKET_ADD_INVALID   = 0,
    BOWIE_DHT_BUCKET_ADD_ADDED     = 1,
    BOWIE_DHT_BUCKET_ADD_UPDATED   = 2,
    BOWIE_DHT_BUCKET_ADD_CACHED    = 3,
    BOWIE_DHT_BUCKET_ADD_CACHE_FULL = 4,
} bowie_dht_bucket_add_result_t;

/*
 * ============================================================================
 * BUCKET
 * ============================================================================
 */

typedef struct bowie_dht_bucket {
    /*
     * The live set. The first "count" entries are valid. The
     * rest are unused.
     */
    bowie_dht_node_t nodes[BOWIE_DHT_K];
    size_t           count;

    /*
     * The replacement cache. The first "replacement_count"
     * entries are valid.
     */
    bowie_dht_node_t replacements[BOWIE_DHT_REPLACEMENT];
    size_t           replacement_count;

    /*
     * The time of the last change to the bucket. The routing
     * table uses this to decide when to refresh.
     */
    bowie_mtime_t    last_changed_ms;
} bowie_dht_bucket_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a bucket to the empty state.
 *
 * Every node slot becomes zero. The counts become zero. The
 * last-changed time becomes zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_bucket_clear(bowie_dht_bucket_t *bucket);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * True when the bucket has no live nodes.
 *
 * Returns 1 for NULL.
 */
int bowie_dht_bucket_is_empty(const bowie_dht_bucket_t *bucket);

/*
 * True when the bucket has no room for a new live node.
 *
 * A bucket that is full still has a replacement cache; the
 * function returns 1 only for the live set.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_bucket_is_full(const bowie_dht_bucket_t *bucket);

/*
 * Return the number of live nodes.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_bucket_count(const bowie_dht_bucket_t *bucket);

/*
 * Return the live node at the given index.
 *
 * Returns NULL if the index is out of range or the bucket is
 * NULL.
 */
const bowie_dht_node_t *bowie_dht_bucket_at(
    const bowie_dht_bucket_t *bucket, size_t index);

/*
 * Find a live node by ID.
 *
 * Returns a pointer to the node, or NULL if the ID is not in
 * the live set.
 */
const bowie_dht_node_t *bowie_dht_bucket_find(
    const bowie_dht_bucket_t  *bucket,
    const bowie_dht_node_id_t *id);

/*
 * Return the number of replacement nodes.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_bucket_replacement_count(
    const bowie_dht_bucket_t *bucket);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Add or update a node in the bucket.
 *
 * The bucket is updated as follows:
 *
 *   - If the node is already in the live set, its timestamp
 *     and fail count are refreshed from the input, and the
 *     result is UPDATED.
 *
 *   - If the live set has room, the node is appended, and
 *     the result is ADDED.
 *
 *   - If the live set is full, the node is added to the
 *     replacement cache. If the node is already in the
 *     cache, its timestamp is refreshed. The result is
 *     CACHED.
 *
 *   - If the live set and the replacement cache are both
 *     full, the oldest replacement is evicted and the new
 *     node takes its place. The result is CACHED.
 *
 * A node with an unset ID or an unset address is rejected
 * with the result INVALID. A NULL bucket or node also
 * returns INVALID.
 *
 * The bucket's last-changed time is set to now_ms when a
 * node is added or updated. It is not changed when a node is
 * only cached.
 */
bowie_dht_bucket_add_result_t bowie_dht_bucket_add(
    bowie_dht_bucket_t     *bucket,
    const bowie_dht_node_t *node,
    bowie_mtime_t           now_ms);

/*
 * Remove a live node by ID.
 *
 * If the node is in the live set, it is removed and a node
 * from the replacement cache (if any) takes its place. The
 * bucket's last-changed time is updated.
 *
 * Returns BOWIE_OK when the node was removed.
 * Returns BOWIE_ERR_NOT_FOUND when the node was not in the
 *   live set.
 * Returns BOWIE_ERR_NULL_ARG if bucket or id is NULL.
 */
bowie_error_t bowie_dht_bucket_remove(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Record a successful response from a live node.
 *
 * The node's timestamp is refreshed and its fail count is
 * reset.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NOT_FOUND when the node is not in the
 *   live set.
 * Returns BOWIE_ERR_NULL_ARG if bucket or id is NULL.
 */
bowie_error_t bowie_dht_bucket_seen(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Record a failed request to a live node.
 *
 * The node's fail count is incremented. If the count reaches
 * the "bad" threshold, the node is removed from the live set
 * and a replacement takes its place.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NOT_FOUND when the node is not in the
 *   live set.
 * Returns BOWIE_ERR_NULL_ARG if bucket or id is NULL.
 */
bowie_error_t bowie_dht_bucket_failed(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms);

/*
 * Store the token that a live node gave us.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NOT_FOUND when the node is not in the
 *   live set.
 * Returns BOWIE_ERR_NULL_ARG if bucket or id is NULL.
 */
bowie_error_t bowie_dht_bucket_set_token(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    const bowie_dht_token_t   *token);

/*
 * ============================================================================
 * SELECTION
 * ============================================================================
 *
 * The routing layer needs to pick nodes to query. The
 * selection functions fill a caller-supplied array with the
 * best nodes for a target.
 *
 * "Best" means closest by XOR distance, and good by the
 * Mainline rules. A bad node is never selected.
 */

/*
 * Select up to max_nodes live nodes closest to the target.
 *
 * The target is a 160-bit ID. The nodes are sorted by XOR
 * distance from the target, closest first. A node that is not
 * good is skipped.
 *
 * The output array is caller-supplied. The number of nodes
 * written is returned through out_count.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the output array is smaller
 *   than max_nodes and the function cannot write a partial
 *   result.
 */
bowie_error_t bowie_dht_bucket_select_closest(
    const bowie_dht_bucket_t  *bucket,
    const bowie_dht_node_id_t *target,
    bowie_mtime_t              now_ms,
    bowie_dht_node_t          *out,
    size_t                     out_cap,
    size_t                    *out_count);

/*
 * ============================================================================
 * END OF DHT BUCKET
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_BUCKET_H */
