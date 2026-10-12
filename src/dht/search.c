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
 * BOWIE — DHT SEARCH IMPLEMENTATION
 * ============================================================================
 *
 * The iterative lookup for the DHT.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network.
 *   - No allocation.
 *   - No timers.
 *   - No concurrency.
 *   - No retries.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The candidate list is kept sorted by XOR distance from the
 * target, closest first. The sort is an insertion sort; the
 * list is small (bounded by the candidate capacity) and the
 * cost is acceptable.
 *
 * The "queried" flag is a bit in the node struct. The bit is
 * set when the node is returned by next_query. The bit is
 * cleared when the node is added to the candidate list. The
 * storage layer does not use the bit, so the search owns it.
 *
 * The seed functions add nodes to the list. A node that is
 * already in the list is not added again. A node that does
 * not fit is dropped.
 *
 * The response function adds the compact nodes to the
 * candidate list. The compact nodes are converted to full
 * nodes with bowie_dht_node_from_compact. A node that is
 * already in the list is not added again. A node that does
 * not fit is dropped.
 *
 * The peer add function adds peers to the peer array. A peer
 * that is already in the array is not added again. The
 * comparison is by address.
 *
 * The "queried" flag is a private bit in the node struct's
 * "fail_count" field. The search does not use the fail
 * count; the routing layer owns it. The two do not conflict
 * because a search node is a copy of a routing node, not the
 * routing node itself.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, info hash, distance
 *   "dht/node.h"                 the node struct
 *   "dht/message.h"              the compact node struct
 *   "dht/storage.h"              the peer entry struct
 *   "dht/routing.h"              the routing table
 *   "dht/search.h"               the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/message.h"
#include "dht/storage.h"
#include "dht/routing.h"
#include "dht/search.h"

/*
 * ============================================================================
 * INTERNAL — QUERIED FLAG
 * ============================================================================
 *
 * The queried flag is stored in the node's fail_count field.
 * The search uses the high bit of the field; the routing
 * layer uses the low bits. A search node is a copy of a
 * routing node, so the two do not conflict.
 *
 * The flag is cleared when a node is added to the candidate
 * list and set when the node is returned by next_query.
 */

#define SEARCH_QUERIED_BIT  0x80000000u

static int node_is_queried(const bowie_dht_node_t *n)
{
    return (n->fail_count & SEARCH_QUERIED_BIT) != 0u;
}

static void node_set_queried(bowie_dht_node_t *n)
{
    n->fail_count |= SEARCH_QUERIED_BIT;
}

static void node_clear_queried(bowie_dht_node_t *n)
{
    n->fail_count &= ~SEARCH_QUERIED_BIT;
}

/*
 * ============================================================================
 * INTERNAL — DISTANCE HELPERS
 * ============================================================================
 */

static int node_distance_less(const bowie_dht_node_t    *a,
                              const bowie_dht_node_t    *b,
                              const bowie_dht_node_id_t *target)
{
    bowie_dht_distance_t da;
    bowie_dht_distance_t db;
    (void)bowie_dht_distance_between_ids(&a->id, target, &da);
    (void)bowie_dht_distance_between_ids(&b->id, target, &db);
    return bowie_dht_distance_compare(&da, &db) < 0;
}

/*
 * ============================================================================
 * INTERNAL — INSERT A CANDIDATE
 * ============================================================================
 *
 * Insert a node into the candidate list, keeping the list
 * sorted by XOR distance from the target. A node that is
 * already in the list is not inserted. A node that does not
 * fit is dropped.
 *
 * Returns 1 when the node was inserted, 0 otherwise.
 */

static int candidate_insert(bowie_dht_search_t     *search,
                            const bowie_dht_node_t *node)
{
    /*
     * Check for duplicates.
     */
    for (size_t i = 0u; i < search->candidates_used; i++) {
        if (bowie_dht_node_id_equal(&search->candidates[i].id,
                                    &node->id)) {
            return 0;
        }
    }

    if (search->candidates_used >= search->candidates_cap) {
        return 0;
    }

    /*
     * Insertion sort by distance. The new node is placed at
     * the first position where it is closer than the
     * current entry.
     */
    bowie_dht_node_t copy = *node;
    node_clear_queried(&copy);

    size_t pos = search->candidates_used;
    while (pos > 0u) {
        if (node_distance_less(&search->candidates[pos - 1u],
                               &copy, &search->target)) {
            break;
        }
        search->candidates[pos] = search->candidates[pos - 1u];
        pos--;
    }
    search->candidates[pos] = copy;
    search->candidates_used++;
    return 1;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_dht_search_init(
    bowie_dht_search_t          *search,
    bowie_dht_search_type_t      type,
    const bowie_dht_node_id_t   *target,
    const bowie_dht_info_hash_t *info_hash,
    bowie_dht_node_t            *candidates,
    size_t                       candidates_cap,
    bowie_dht_peer_entry_t      *peers,
    size_t                       peers_cap,
    size_t                       alpha,
    size_t                       max_queries,
    bowie_mtime_t                timeout_ms,
    bowie_mtime_t                now_ms)
{
    if (search == NULL || target == NULL || candidates == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (candidates_cap == 0u) {
        return BOWIE_ERR_INVAL;
    }

    switch (type) {
    case BOWIE_DHT_SEARCH_FIND_NODE:
        break;
    case BOWIE_DHT_SEARCH_GET_PEERS:
        if (info_hash == NULL || peers == NULL || peers_cap == 0u) {
            return BOWIE_ERR_NULL_ARG;
        }
        break;
    default:
        return BOWIE_ERR_INVAL;
    }

    memset(search, 0, sizeof(*search));
    search->type   = type;
    search->state  = BOWIE_DHT_SEARCH_PENDING;
    search->target = *target;

    if (info_hash != NULL) {
        search->info_hash = *info_hash;
    }

    search->candidates      = candidates;
    search->candidates_cap  = candidates_cap;
    search->candidates_used = 0u;

    search->peers      = peers;
    search->peers_cap  = peers_cap;
    search->peers_used = 0u;

    search->max_in_flight = (alpha == 0u)
        ? BOWIE_DHT_SEARCH_DEFAULT_ALPHA : alpha;
    search->in_flight = 0u;

    search->max_queries = (max_queries == 0u)
        ? BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES : max_queries;
    search->queries_sent = 0u;

    search->started_at_ms = now_ms;
    search->timeout_ms    = (timeout_ms == 0u)
        ? BOWIE_DHT_SEARCH_DEFAULT_TIMEOUT_MS : timeout_ms;

    return BOWIE_OK;
}

void bowie_dht_search_clear(bowie_dht_search_t *search)
{
    if (search == NULL) {
        return;
    }
    search->state        = BOWIE_DHT_SEARCH_PENDING;
    search->candidates_used = 0u;
    search->peers_used   = 0u;
    search->in_flight    = 0u;
    search->queries_sent = 0u;
}

/*
 * ============================================================================
 * SEEDING
 * ============================================================================
 */

bowie_error_t bowie_dht_search_seed(
    bowie_dht_search_t     *search,
    const bowie_dht_node_t *node)
{
    if (search == NULL || node == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!bowie_dht_node_is_set(node)) {
        return BOWIE_ERR_INVAL;
    }

    if (search->candidates_used >= search->candidates_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    (void)candidate_insert(search, node);
    return BOWIE_OK;
}

bowie_error_t bowie_dht_search_seed_routing(
    bowie_dht_search_t        *search,
    const bowie_dht_routing_t *routing,
    bowie_mtime_t              now_ms)
{
    if (search == NULL || routing == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * The routing table's select function returns the
     * closest good nodes to the target. The number is
     * bounded by the candidate capacity.
     */
    size_t count = 0u;
    bowie_dht_node_t buf[BOWIE_DHT_K * 4];
    size_t buf_cap = sizeof(buf) / sizeof(buf[0]);

    (void)bowie_dht_routing_select_closest(
        routing, &search->target, now_ms,
        buf, buf_cap, &count);

    for (size_t i = 0u; i < count; i++) {
        if (search->candidates_used >= search->candidates_cap) {
            break;
        }
        (void)candidate_insert(search, &buf[i]);
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STEP
 * ============================================================================
 */

bowie_error_t bowie_dht_search_next_query(
    bowie_dht_search_t *search,
    bowie_dht_node_t   *out_node)
{
    if (search == NULL || out_node == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (search->state == BOWIE_DHT_SEARCH_DONE ||
        search->state == BOWIE_DHT_SEARCH_FAILED) {
        return BOWIE_ERR_NOT_FOUND;
    }
    if (search->in_flight >= search->max_in_flight) {
        return BOWIE_ERR_BUSY;
    }
    if (search->queries_sent >= search->max_queries) {
        bowie_dht_search_finish(search);
        return BOWIE_ERR_NOT_FOUND;
    }

    /*
     * Find the closest unqueried candidate.
     */
    for (size_t i = 0u; i < search->candidates_used; i++) {
        if (!node_is_queried(&search->candidates[i])) {
            *out_node = search->candidates[i];
            node_set_queried(&search->candidates[i]);
            search->in_flight++;
            search->queries_sent++;
            if (search->state == BOWIE_DHT_SEARCH_PENDING) {
                search->state = BOWIE_DHT_SEARCH_IN_PROGRESS;
            }
            return BOWIE_OK;
        }
    }

    /*
     * No unqueried candidate. The search is done when the
     * in-flight queries have finished; the caller checks
     * with is_done.
     */
    return BOWIE_ERR_NOT_FOUND;
}

bowie_error_t bowie_dht_search_query_done(
    bowie_dht_search_t *search)
{
    if (search == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (search->in_flight == 0u) {
        return BOWIE_ERR_INVAL;
    }
    search->in_flight--;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * RESPONSE
 * ============================================================================
 */

bowie_error_t bowie_dht_search_add_response(
    bowie_dht_search_t              *search,
    const bowie_dht_compact_node_t  *nodes,
    size_t                           nodes_count)
{
    if (search == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (nodes_count > 0u && nodes == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * The response means one of the in-flight queries is
     * done.
     */
    (void)bowie_dht_search_query_done(search);

    /*
     * Add each compact node to the candidate list.
     */
    for (size_t i = 0u; i < nodes_count; i++) {
        bowie_dht_node_t full;
        uint8_t buf[BOWIE_DHT_COMPACT_NODE_LEN];

        /*
         * Re-encode the compact node into bytes, then
         * decode with the node function. This is the
         * simplest way to share the conversion code.
         */
        size_t out_len = 0u;
        bowie_error_t rc = bowie_dht_compact_nodes_encode(
            &nodes[i], 1u, buf, sizeof(buf), &out_len);
        if (rc != BOWIE_OK) {
            continue;
        }

        bowie_span_t sp = { buf, out_len };
        rc = bowie_dht_node_from_compact(sp, &full);
        if (rc != BOWIE_OK) {
            continue;
        }

        if (search->candidates_used >= search->candidates_cap) {
            break;
        }
        (void)candidate_insert(search, &full);
    }

    return BOWIE_OK;
}

bowie_error_t bowie_dht_search_add_peers(
    bowie_dht_search_t           *search,
    const bowie_dht_peer_entry_t *peers,
    size_t                        peers_count)
{
    if (search == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (peers_count > 0u && peers == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    for (size_t i = 0u; i < peers_count; i++) {
        if (search->peers_used >= search->peers_cap) {
            break;
        }

        /*
         * Deduplicate by address.
         */
        int duplicate = 0;
        for (size_t j = 0u; j < search->peers_used; j++) {
            if (bowie_addr_equal(&search->peers[j].addr,
                                 &peers[i].addr)) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        search->peers[search->peers_used] = peers[i];
        search->peers_used++;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STATUS
 * ============================================================================
 */

int bowie_dht_search_is_done(const bowie_dht_search_t *search)
{
    if (search == NULL) {
        return 0;
    }
    if (search->state == BOWIE_DHT_SEARCH_DONE ||
        search->state == BOWIE_DHT_SEARCH_FAILED) {
        return 1;
    }
    if (search->queries_sent >= search->max_queries) {
        return 1;
    }
    if (search->in_flight == 0u) {
        /*
         * No query in flight. Check whether any candidate
         * has not been queried.
         */
        for (size_t i = 0u; i < search->candidates_used; i++) {
            if (!node_is_queried(&search->candidates[i])) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

void bowie_dht_search_finish(bowie_dht_search_t *search)
{
    if (search == NULL) {
        return;
    }
    search->state = BOWIE_DHT_SEARCH_DONE;
}

void bowie_dht_search_fail(bowie_dht_search_t *search)
{
    if (search == NULL) {
        return;
    }
    search->state = BOWIE_DHT_SEARCH_FAILED;
}

int bowie_dht_search_timed_out(const bowie_dht_search_t *search,
                               bowie_mtime_t now_ms)
{
    if (search == NULL) {
        return 0;
    }
    if (search->timeout_ms == 0u) {
        return 0;
    }
    if (now_ms < search->started_at_ms) {
        return 0;
    }
    bowie_mtime_t elapsed = now_ms - search->started_at_ms;
    return (elapsed >= search->timeout_ms) ? 1 : 0;
}

size_t bowie_dht_search_peer_count(
    const bowie_dht_search_t *search)
{
    if (search == NULL) {
        return 0u;
    }
    return search->peers_used;
}

size_t bowie_dht_search_candidate_count(
    const bowie_dht_search_t *search)
{
    if (search == NULL) {
        return 0u;
    }
    return search->candidates_used;
}

size_t bowie_dht_search_query_count(
    const bowie_dht_search_t *search)
{
    if (search == NULL) {
        return 0u;
    }
    return search->queries_sent;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
