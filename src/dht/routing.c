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
 * BOWIE — DHT ROUTING TABLE IMPLEMENTATION
 * ============================================================================
 *
 * A Kademlia routing table: a list of K-buckets, one per
 * position of the first set bit in the XOR distance between a
 * node ID and the local ID.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network.
 *   - No search.
 *   - No storage.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The table starts with one bucket. When a bucket is full and
 * the table has room, the table adds a new bucket. The new
 * bucket is empty; the nodes that belong in it are moved
 * there by a re-add pass.
 *
 * The re-add pass is the simple way to handle a split without
 * tracking each bucket's range. When the table splits, it
 * walks every node in every bucket and re-adds it. The
 * routing-add logic places each node in the correct bucket
 * based on its first-set-bit index. A node that is already in
 * the correct bucket is left alone.
 *
 * The re-add pass is O(N) in the number of nodes. With a K of
 * 8 and a maximum of 160 buckets, the table holds at most
 * 1280 nodes. The pass is fast enough that it does not need
 * to be incremental.
 *
 * The bucket index is computed by bowie_dht_distance_first_bit
 * on the XOR distance between the node ID and the local ID. A
 * node whose ID equals the local ID has no set bit; the
 * function returns -1, and the node is not added.
 *
 * The routing table's add function returns the result from
 * the bucket add. A node that is cached because its bucket is
 * full is not re-tried after a split; the caller can retry
 * later. The Mainline DHT retries on the next lookup.
 *
 * The stalest-bucket function returns the index of the bucket
 * with the smallest last-changed timestamp. The caller sends
 * a find_node query for a random ID in that bucket's range.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset
 *   "bowie/types.h"              bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, distance
 *   "dht/node.h"                 the node struct
 *   "dht/bucket.h"               the bucket struct
 *   "dht/routing.h"              the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/bucket.h"
#include "dht/routing.h"

/*
 * ============================================================================
 * INTERNAL — SPLIT
 * ============================================================================
 *
 * Add a new empty bucket at the end of the table. The table's
 * bucket count is increased. The new bucket's last-changed
 * timestamp is set to now_ms.
 *
 * A split does not move any nodes. The nodes are re-added by
 * the caller. See the file header for the reason.
 */

static void table_add_bucket(bowie_dht_routing_t *table,
                             bowie_mtime_t now_ms)
{
    if (table->bucket_count >= BOWIE_DHT_MAX_BUCKETS) {
        return;
    }
    size_t idx = table->bucket_count;
    bowie_dht_bucket_clear(&table->buckets[idx]);
    table->buckets[idx].last_changed_ms = now_ms;
    table->bucket_count++;
}

/*
 * ============================================================================
 * INTERNAL — RE-ADD PASS
 * ============================================================================
 *
 * Walk every node in every bucket and re-add it. A node that
 * is already in the correct bucket is left alone. A node that
 * belongs in a different bucket is moved.
 *
 * The pass is used after a split. It is also used at
 * initialization to place a node that was added before the
 * table had more than one bucket.
 */

static void table_rebalance(bowie_dht_routing_t *table,
                            bowie_mtime_t now_ms)
{
    /*
     * Snapshot the nodes. The re-add pass may move nodes
     * between buckets; walking the live buckets while
     * modifying them is not safe. The snapshot is a fixed
     * array of at most K * MAX_BUCKETS nodes. That is large
     * but bounded, and it is on the stack for the duration
     * of the call.
     */
    bowie_dht_node_t snapshot[BOWIE_DHT_K * BOWIE_DHT_MAX_BUCKETS];
    size_t           n = 0u;

    for (size_t i = 0u; i < table->bucket_count; i++) {
        const bowie_dht_bucket_t *b = &table->buckets[i];
        for (size_t j = 0u; j < b->count; j++) {
            if (n < sizeof(snapshot) / sizeof(snapshot[0])) {
                snapshot[n++] = b->nodes[j];
            }
        }
    }

    /*
     * Clear every bucket. The bucket's last-changed
     * timestamp is preserved for the existing buckets;
     * the new buckets keep their own timestamps.
     */
    for (size_t i = 0u; i < table->bucket_count; i++) {
        bowie_mtime_t saved = table->buckets[i].last_changed_ms;
        bowie_dht_bucket_clear(&table->buckets[i]);
        table->buckets[i].last_changed_ms = saved;
    }

    /*
     * Re-add every node. The node is placed in the bucket
     * for its index. A node that is not good is still
     * placed; the selection function filters bad nodes
     * later.
     */
    for (size_t i = 0u; i < n; i++) {
        int idx = bowie_dht_routing_bucket_index(table,
                                                 &snapshot[i].id);
        if (idx < 0) {
            continue;
        }
        if ((size_t)idx >= table->bucket_count) {
            continue;
        }
        (void)bowie_dht_bucket_add(&table->buckets[idx],
                                   &snapshot[i], now_ms);
    }
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_dht_routing_init(bowie_dht_routing_t       *table,
                            const bowie_dht_node_id_t *local_id)
{
    if (table == NULL) {
        return;
    }
    memset(table, 0, sizeof(*table));
    if (local_id != NULL) {
        table->local_id = *local_id;
    }
    table->bucket_count = 1u;
}

void bowie_dht_routing_clear(bowie_dht_routing_t *table)
{
    if (table == NULL) {
        return;
    }
    memset(table, 0, sizeof(*table));
    table->bucket_count = 1u;
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

size_t bowie_dht_routing_bucket_count(
    const bowie_dht_routing_t *table)
{
    if (table == NULL) {
        return 0u;
    }
    return table->bucket_count;
}

const bowie_dht_bucket_t *bowie_dht_routing_bucket_at(
    const bowie_dht_routing_t *table, size_t index)
{
    if (table == NULL) {
        return NULL;
    }
    if (index >= table->bucket_count) {
        return NULL;
    }
    return &table->buckets[index];
}

size_t bowie_dht_routing_node_count(
    const bowie_dht_routing_t *table)
{
    if (table == NULL) {
        return 0u;
    }
    size_t total = 0u;
    for (size_t i = 0u; i < table->bucket_count; i++) {
        total += table->buckets[i].count;
    }
    return total;
}

int bowie_dht_routing_bucket_index(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return -1;
    }

    bowie_dht_distance_t d;
    bowie_error_t rc = bowie_dht_distance_between_ids(
        &table->local_id, id, &d);
    if (rc != BOWIE_OK) {
        return -1;
    }

    return bowie_dht_distance_first_bit(&d);
}

const bowie_dht_node_t *bowie_dht_routing_find(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return NULL;
    }

    int idx = bowie_dht_routing_bucket_index(table, id);
    if (idx < 0 || (size_t)idx >= table->bucket_count) {
        return NULL;
    }

    return bowie_dht_bucket_find(&table->buckets[idx], id);
}

/*
 * ============================================================================
 * MUTATION — ADD
 * ============================================================================
 */

bowie_dht_bucket_add_result_t bowie_dht_routing_add(
    bowie_dht_routing_t    *table,
    const bowie_dht_node_t *node,
    bowie_mtime_t           now_ms)
{
    if (table == NULL || node == NULL) {
        return BOWIE_DHT_BUCKET_ADD_INVALID;
    }
    if (!bowie_dht_node_is_set(node)) {
        return BOWIE_DHT_BUCKET_ADD_INVALID;
    }

    int idx = bowie_dht_routing_bucket_index(table, &node->id);
    if (idx < 0) {
        /*
         * The node ID equals the local ID. It is not a
         * valid routing entry.
         */
        return BOWIE_DHT_BUCKET_ADD_INVALID;
    }

    /*
     * The node belongs in a bucket beyond the current
     * table. Grow the table until the bucket exists.
     */
    while ((size_t)idx >= table->bucket_count) {
        if (table->bucket_count >= BOWIE_DHT_MAX_BUCKETS) {
            return BOWIE_DHT_BUCKET_ADD_CACHE_FULL;
        }
        table_add_bucket(table, now_ms);
    }

    /*
     * Try to add the node to its bucket.
     */
    bowie_dht_bucket_add_result_t r =
        bowie_dht_bucket_add(&table->buckets[idx], node, now_ms);

    if (r == BOWIE_DHT_BUCKET_ADD_ADDED ||
        r == BOWIE_DHT_BUCKET_ADD_UPDATED) {
        return r;
    }

    /*
     * The bucket is full. If the table has room, split the
     * table and rebalance. The split adds an empty bucket
     * at the end. The rebalance moves nodes into the new
     * bucket as needed.
     *
     * The split is only worth doing when the node's index
     * is less than the new bucket count; otherwise the
     * node is still in the last bucket and the split does
     * not help. The caller can retry later.
     */
    if (table->bucket_count >= BOWIE_DHT_MAX_BUCKETS) {
        return r;
    }

    table_add_bucket(table, now_ms);
    table_rebalance(table, now_ms);

    /*
     * Retry the add. After the rebalance, the bucket for
     * this node may have room.
     */
    int new_idx = bowie_dht_routing_bucket_index(table, &node->id);
    if (new_idx < 0 ||
        (size_t)new_idx >= table->bucket_count) {
        return BOWIE_DHT_BUCKET_ADD_CACHE_FULL;
    }

    return bowie_dht_bucket_add(&table->buckets[new_idx],
                                node, now_ms);
}

/*
 * ============================================================================
 * MUTATION — REMOVE / SEEN / FAILED / SET_TOKEN
 * ============================================================================
 *
 * The bucket for a node is found by its index. The
 * corresponding bucket function is called.
 *
 * A node whose index is beyond the current table is not in
 * the table; the function returns NOT_FOUND.
 */

bowie_error_t bowie_dht_routing_remove(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (table == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = bowie_dht_routing_bucket_index(table, id);
    if (idx < 0 || (size_t)idx >= table->bucket_count) {
        return BOWIE_ERR_NOT_FOUND;
    }

    return bowie_dht_bucket_remove(&table->buckets[idx], id,
                                   now_ms);
}

bowie_error_t bowie_dht_routing_seen(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (table == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = bowie_dht_routing_bucket_index(table, id);
    if (idx < 0 || (size_t)idx >= table->bucket_count) {
        return BOWIE_ERR_NOT_FOUND;
    }

    return bowie_dht_bucket_seen(&table->buckets[idx], id, now_ms);
}

bowie_error_t bowie_dht_routing_failed(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (table == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = bowie_dht_routing_bucket_index(table, id);
    if (idx < 0 || (size_t)idx >= table->bucket_count) {
        return BOWIE_ERR_NOT_FOUND;
    }

    return bowie_dht_bucket_failed(&table->buckets[idx], id,
                                   now_ms);
}

bowie_error_t bowie_dht_routing_set_token(
    bowie_dht_routing_t       *table,
    const bowie_dht_node_id_t *id,
    const bowie_dht_token_t   *token)
{
    if (table == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = bowie_dht_routing_bucket_index(table, id);
    if (idx < 0 || (size_t)idx >= table->bucket_count) {
        return BOWIE_ERR_NOT_FOUND;
    }

    return bowie_dht_bucket_set_token(&table->buckets[idx], id,
                                      token);
}

/*
 * ============================================================================
 * SELECTION
 * ============================================================================
 *
 * The selection function gathers the good nodes from every
 * bucket, sorts them by XOR distance from the target, and
 * writes the first max_nodes into the output array. The sort
 * is an insertion sort on the output array, which is at most
 * max_nodes entries.
 *
 * The gather step is a linear scan. The number of nodes is
 * bounded by K * MAX_BUCKETS, so the gather is fast.
 */

bowie_error_t bowie_dht_routing_select_closest(
    const bowie_dht_routing_t *table,
    const bowie_dht_node_id_t *target,
    bowie_mtime_t              now_ms,
    bowie_dht_node_t          *out,
    size_t                     out_cap,
    size_t                    *out_count)
{
    if (table == NULL || target == NULL ||
        out == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out_cap == 0u) {
        *out_count = 0u;
        return BOWIE_OK;
    }

    size_t n = 0u;

    for (size_t i = 0u; i < table->bucket_count; i++) {
        const bowie_dht_bucket_t *b = &table->buckets[i];

        for (size_t j = 0u; j < b->count; j++) {
            const bowie_dht_node_t *node = &b->nodes[j];

            if (!bowie_dht_node_is_good(node, now_ms)) {
                continue;
            }
            if (n >= out_cap) {
                break;
            }

            /*
             * Compute the distance to the target. The
             * insertion sort compares distances. The
             * distance is recomputed for the previous
             * entries on each insertion. This is O(n^2)
             * in the number of entries, which is at most
             * out_cap. The cap is small, so the cost is
             * acceptable.
             */
            bowie_dht_distance_t d;
            (void)bowie_dht_distance_between_ids(&node->id,
                                                 target, &d);

            size_t pos = n;
            while (pos > 0u) {
                bowie_dht_distance_t prev_d;
                (void)bowie_dht_distance_between_ids(
                    &out[pos - 1u].id, target, &prev_d);
                if (bowie_dht_distance_compare(&d, &prev_d) >= 0) {
                    break;
                }
                out[pos] = out[pos - 1u];
                pos--;
            }

            out[pos] = *node;
            n++;
        }
    }

    *out_count = n;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * MAINTENANCE
 * ============================================================================
 */

int bowie_dht_routing_stalest_bucket(
    const bowie_dht_routing_t *table)
{
    if (table == NULL || table->bucket_count == 0u) {
        return -1;
    }

    /*
     * The stalest bucket is the one with the smallest
     * last-changed timestamp. An empty bucket's timestamp
     * is zero, which is the smallest possible value; an
     * empty bucket is the stalest bucket, because it has
     * never held a node.
     */
    int    best_idx = -1;
    bowie_mtime_t best_time = 0u;
    int    have_best = 0;

    for (size_t i = 0u; i < table->bucket_count; i++) {
        bowie_mtime_t t = table->buckets[i].last_changed_ms;
        if (!have_best || t < best_time) {
            best_time = t;
            best_idx  = (int)i;
            have_best = 1;
        }
    }

    return best_idx;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
