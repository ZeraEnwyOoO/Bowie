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
 * BOWIE — DHT BUCKET IMPLEMENTATION
 * ============================================================================
 *
 * A K-bucket: a fixed-capacity container of DHT nodes.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing table.
 *   - No I/O.
 *   - No allocation.
 *   - No bucket splitting.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The bucket has two fixed-capacity arrays: the live set and
 * the replacement cache. A new node is added to the live set
 * if there is room, otherwise to the replacement cache. If
 * both are full, the oldest replacement is evicted.
 *
 * The "oldest" replacement is the one at index 0. New
 * replacements are appended; when the cache is full, the
 * entries are shifted left and the new one takes the last
 * slot. This is a FIFO.
 *
 * A node that fails three times in a row is removed from the
 * live set. A replacement, if any, takes its place. The
 * removal is the same as an explicit remove, except that the
 * caller does not have to call it.
 *
 * The selection function sorts the live nodes by XOR distance
 * from a target. The sort is a simple insertion sort; the
 * bucket holds at most K nodes, so the cost is negligible.
 * The function does not allocate a temporary array; it fills
 * the caller's output array directly.
 *
 * The selection function skips nodes that are not good. A
 * node that is good but stale is included; a node that has
 * failed three times in a row is not.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, distance
 *   "dht/node.h"                 the node struct
 *   "dht/bucket.h"               the declarations
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

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_dht_bucket_clear(bowie_dht_bucket_t *bucket)
{
    if (bucket == NULL) {
        return;
    }
    memset(bucket, 0, sizeof(*bucket));
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

int bowie_dht_bucket_is_empty(const bowie_dht_bucket_t *bucket)
{
    if (bucket == NULL) {
        return 1;
    }
    return (bucket->count == 0u) ? 1 : 0;
}

int bowie_dht_bucket_is_full(const bowie_dht_bucket_t *bucket)
{
    if (bucket == NULL) {
        return 0;
    }
    return (bucket->count >= BOWIE_DHT_K) ? 1 : 0;
}

size_t bowie_dht_bucket_count(const bowie_dht_bucket_t *bucket)
{
    if (bucket == NULL) {
        return 0u;
    }
    return bucket->count;
}

const bowie_dht_node_t *bowie_dht_bucket_at(
    const bowie_dht_bucket_t *bucket, size_t index)
{
    if (bucket == NULL) {
        return NULL;
    }
    if (index >= bucket->count) {
        return NULL;
    }
    return &bucket->nodes[index];
}

/*
 * Find a live node by ID. Returns the index, or -1 when not
 * found. The index is used by the mutation functions.
 */
static int find_live_index(const bowie_dht_bucket_t *bucket,
                           const bowie_dht_node_id_t *id)
{
    for (size_t i = 0u; i < bucket->count; i++) {
        if (bowie_dht_node_id_equal(&bucket->nodes[i].id, id)) {
            return (int)i;
        }
    }
    return -1;
}

const bowie_dht_node_t *bowie_dht_bucket_find(
    const bowie_dht_bucket_t  *bucket,
    const bowie_dht_node_id_t *id)
{
    if (bucket == NULL || id == NULL) {
        return NULL;
    }
    int i = find_live_index(bucket, id);
    if (i < 0) {
        return NULL;
    }
    return &bucket->nodes[i];
}

size_t bowie_dht_bucket_replacement_count(
    const bowie_dht_bucket_t *bucket)
{
    if (bucket == NULL) {
        return 0u;
    }
    return bucket->replacement_count;
}

/*
 * ============================================================================
 * INTERNAL — REPLACEMENT CACHE
 * ============================================================================
 *
 * The cache is a FIFO. A new node is appended if there is
 * room. If the cache is full, the entries are shifted left
 * and the new node takes the last slot.
 */

static void replacement_push(bowie_dht_bucket_t     *bucket,
                             const bowie_dht_node_t *node)
{
    if (bucket->replacement_count < BOWIE_DHT_REPLACEMENT) {
        bucket->replacements[bucket->replacement_count] = *node;
        bucket->replacement_count++;
        return;
    }

    /*
     * Shift left by one. The oldest entry at index 0 is
     * overwritten.
     */
    for (size_t i = 1u; i < BOWIE_DHT_REPLACEMENT; i++) {
        bucket->replacements[i - 1u] = bucket->replacements[i];
    }
    bucket->replacements[BOWIE_DHT_REPLACEMENT - 1u] = *node;
}

/*
 * Pop the oldest replacement. Returns 1 when one was
 * available, 0 when the cache was empty.
 */
static int replacement_pop(bowie_dht_bucket_t *bucket,
                           bowie_dht_node_t    *out)
{
    if (bucket->replacement_count == 0u) {
        return 0;
    }
    *out = bucket->replacements[0];

    for (size_t i = 1u; i < bucket->replacement_count; i++) {
        bucket->replacements[i - 1u] = bucket->replacements[i];
    }
    bucket->replacement_count--;
    return 1;
}

/*
 * ============================================================================
 * MUTATION — ADD
 * ============================================================================
 */

bowie_dht_bucket_add_result_t bowie_dht_bucket_add(
    bowie_dht_bucket_t     *bucket,
    const bowie_dht_node_t *node,
    bowie_mtime_t           now_ms)
{
    if (bucket == NULL || node == NULL) {
        return BOWIE_DHT_BUCKET_ADD_INVALID;
    }
    if (!bowie_dht_node_is_set(node)) {
        return BOWIE_DHT_BUCKET_ADD_INVALID;
    }

    /*
     * Update path: the node is already in the live set.
     */
    int idx = find_live_index(bucket, &node->id);
    if (idx >= 0) {
        bowie_dht_node_t *existing = &bucket->nodes[idx];
        existing->addr = node->addr;
        existing->last_seen_ms = now_ms;
        existing->fail_count = 0u;
        if (node->has_token) {
            existing->token = node->token;
            existing->has_token = 1;
        }
        bucket->last_changed_ms = now_ms;
        return BOWIE_DHT_BUCKET_ADD_UPDATED;
    }

    /*
     * Add path: the live set has room.
     */
    if (bucket->count < BOWIE_DHT_K) {
        bowie_dht_node_t *slot = &bucket->nodes[bucket->count];
        *slot = *node;
        slot->last_seen_ms = now_ms;
        slot->fail_count = 0u;
        bucket->count++;
        bucket->last_changed_ms = now_ms;
        return BOWIE_DHT_BUCKET_ADD_ADDED;
    }

    /*
     * Cache path: the live set is full. The node goes into
     * the replacement cache.
     */
    replacement_push(bucket, node);

    /*
     * The last-changed time is not updated for a cache-only
     * add. The live set did not change.
     */
    return BOWIE_DHT_BUCKET_ADD_CACHED;
}

/*
 * ============================================================================
 * MUTATION — REMOVE
 * ============================================================================
 *
 * Remove a live node. If the replacement cache has a node,
 * it takes the removed node's slot. The cache is a FIFO, so
 * the promoted node is the oldest replacement.
 */

static void remove_at(bowie_dht_bucket_t *bucket, size_t index,
                      bowie_mtime_t now_ms)
{
    /*
     * Shift the live set left, overwriting the removed
     * node.
     */
    for (size_t i = index + 1u; i < bucket->count; i++) {
        bucket->nodes[i - 1u] = bucket->nodes[i];
    }
    bucket->count--;
    bucket->nodes[bucket->count] = (bowie_dht_node_t){0};

    /*
     * Promote a replacement into the empty slot, if any.
     */
    bowie_dht_node_t promoted;
    if (replacement_pop(bucket, &promoted)) {
        promoted.last_seen_ms = now_ms;
        promoted.fail_count = 0u;
        bucket->nodes[bucket->count] = promoted;
        bucket->count++;
    }

    bucket->last_changed_ms = now_ms;
}

bowie_error_t bowie_dht_bucket_remove(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (bucket == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = find_live_index(bucket, id);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    remove_at(bucket, (size_t)idx, now_ms);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * MUTATION — SEEN / FAILED / SET_TOKEN
 * ============================================================================
 */

bowie_error_t bowie_dht_bucket_seen(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (bucket == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = find_live_index(bucket, id);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    bowie_dht_node_seen(&bucket->nodes[idx], now_ms);
    bucket->last_changed_ms = now_ms;
    return BOWIE_OK;
}

bowie_error_t bowie_dht_bucket_failed(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    bowie_mtime_t              now_ms)
{
    if (bucket == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = find_live_index(bucket, id);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    bowie_dht_node_failed(&bucket->nodes[idx]);

    /*
     * A node that has failed three times in a row is
     * removed. A replacement, if any, takes its place.
     */
    if (bowie_dht_node_is_failed(&bucket->nodes[idx])) {
        remove_at(bucket, (size_t)idx, now_ms);
    } else {
        bucket->last_changed_ms = now_ms;
    }

    return BOWIE_OK;
}

bowie_error_t bowie_dht_bucket_set_token(
    bowie_dht_bucket_t        *bucket,
    const bowie_dht_node_id_t *id,
    const bowie_dht_token_t   *token)
{
    if (bucket == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    int idx = find_live_index(bucket, id);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    bowie_dht_node_set_token(&bucket->nodes[idx], token);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * SELECTION
 * ============================================================================
 *
 * The selection function returns the live nodes that are good
 * and closest to a target, sorted by XOR distance. The sort
 * is an insertion sort on the caller's output array.
 */

static int distance_less(const bowie_dht_distance_t *a,
                         const bowie_dht_distance_t *b)
{
    return bowie_dht_distance_compare(a, b) < 0;
}

bowie_error_t bowie_dht_bucket_select_closest(
    const bowie_dht_bucket_t  *bucket,
    const bowie_dht_node_id_t *target,
    bowie_mtime_t              now_ms,
    bowie_dht_node_t          *out,
    size_t                     out_cap,
    size_t                    *out_count)
{
    if (bucket == NULL || target == NULL ||
        out == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out_cap == 0u) {
        *out_count = 0u;
        return BOWIE_OK;
    }

    size_t n = 0u;

    for (size_t i = 0u; i < bucket->count; i++) {
        const bowie_dht_node_t *node = &bucket->nodes[i];

        if (!bowie_dht_node_is_good(node, now_ms)) {
            continue;
        }
        if (n >= out_cap) {
            break;
        }

        /*
         * Insertion sort by XOR distance. The distance is
         * computed once per node and stored in a local
         * array for the comparison.
         */
        bowie_dht_distance_t d;
        (void)bowie_dht_distance_between_ids(&node->id, target, &d);

        size_t pos = n;
        while (pos > 0u) {
            bowie_dht_distance_t prev_d;
            (void)bowie_dht_distance_between_ids(
                &out[pos - 1u].id, target, &prev_d);
            if (!distance_less(&d, &prev_d)) {
                break;
            }
            out[pos] = out[pos - 1u];
            pos--;
        }

        out[pos] = *node;
        n++;
    }

    *out_count = n;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
