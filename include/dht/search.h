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
 * BOWIE — DHT SEARCH
 * ============================================================================
 *
 * The iterative lookup for the DHT.
 *
 * A search finds the nodes closest to a target ID, or the
 * peers that serve an info hash. The search is the Kademlia
 * lookup: it starts with the closest known nodes, queries
 * them, adds the nodes they return, and repeats until no
 * closer node is found.
 *
 * The search is a state machine. The caller drives it:
 *
 *   - It calls bowie_dht_search_init to set up the search.
 *   - It calls bowie_dht_search_next_query to get the next
 *     node to query.
 *   - It sends the query and waits for a response.
 *   - It calls bowie_dht_search_add_response (or
 *     bowie_dht_search_add_peers) with the response.
 *   - It repeats until bowie_dht_search_is_done returns 1.
 *
 * The state machine does not send or receive packets. The
 * caller owns the network.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network. The caller sends the queries.
 *   - No allocation. The caller supplies the arrays.
 *   - No timers. The caller checks the timeout.
 *   - No concurrency. The state machine tracks the number of
 *     queries in flight, but the caller is the one that
 *     sends them.
 *   - No retries. A query that times out is the caller's
 *     problem; the state machine does not track individual
 *     queries.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The candidate list is sorted by XOR distance from the
 * target, closest first. The search takes the first
 * unqueried candidate that is within the "in flight" budget.
 *
 * A candidate that has been queried is marked. The mark is
 * a flag in the node struct; the storage layer does not use
 * the flag, so the search owns it. The flag is set by
 * bowie_dht_search_next_query and is not cleared.
 *
 * The candidate list has a fixed capacity. A response that
 * returns more nodes than the list can hold adds only the
 * closest ones. The search does not grow the list.
 *
 * The search stops when:
 *
 *   - The caller has queried max_queries nodes, or
 *   - No unqueried candidate is closer than the closest
 *     queried candidate, or
 *   - The timeout has elapsed, or
 *   - The caller calls bowie_dht_search_finish.
 *
 * The timeout is in monotonic milliseconds. The caller
 * passes the current time to the step functions; the search
 * does not read the clock itself.
 *
 * The search is not thread-safe. The caller serializes
 * access.
 *
 * ----------------------------------------------------------------------------
 * Peer storage
 * ----------------------------------------------------------------------------
 *
 * A GET_PEERS search also collects peers. The peers are
 * stored in a caller-supplied array. The array is filled in
 * the order the peers arrive; the search does not sort them.
 *
 * A peer that is already in the array is not added again.
 * The deduplication is O(n) per peer; the array is small.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, info hash
 *   "dht/node.h"                 the node struct
 *   "dht/message.h"              the compact node struct
 *   "dht/storage.h"              the peer entry struct
 *   "dht/routing.h"              the routing table
 * ============================================================================
 */

#ifndef BOWIE_DHT_SEARCH_H
#define BOWIE_DHT_SEARCH_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/message.h"
#include "dht/storage.h"
#include "dht/routing.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * SEARCH TYPE
 * ============================================================================
 */

typedef enum bowie_dht_search_type {
    BOWIE_DHT_SEARCH_FIND_NODE = 0,
    BOWIE_DHT_SEARCH_GET_PEERS = 1,
} bowie_dht_search_type_t;

/*
 * ============================================================================
 * SEARCH STATE
 * ============================================================================
 */

typedef enum bowie_dht_search_state {
    BOWIE_DHT_SEARCH_PENDING     = 0,
    BOWIE_DHT_SEARCH_IN_PROGRESS = 1,
    BOWIE_DHT_SEARCH_DONE        = 2,
    BOWIE_DHT_SEARCH_FAILED      = 3,
} bowie_dht_search_state_t;

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

#define BOWIE_DHT_SEARCH_DEFAULT_ALPHA        3u
#define BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES  20u
#define BOWIE_DHT_SEARCH_DEFAULT_TIMEOUT_MS   30000u  /* 30 s */

/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 *
 * The search state. The caller supplies the candidate and
 * peer arrays.
 *
 * The "queried" flag is stored in the node struct. The
 * search owns the flag; a node that is added to the
 * candidate list has its flag cleared, and a node that is
 * returned by next_query has its flag set.
 *
 * A node in the candidate list with the flag set is not
 * returned again.
 */

typedef struct bowie_dht_search {
    bowie_dht_search_type_t  type;
    bowie_dht_search_state_t state;

    bowie_dht_node_id_t      target;
    bowie_dht_info_hash_t    info_hash;

    bowie_dht_node_t        *candidates;
    size_t                   candidates_cap;
    size_t                   candidates_used;

    bowie_dht_peer_entry_t  *peers;
    size_t                   peers_cap;
    size_t                   peers_used;

    size_t                   in_flight;
    size_t                   max_in_flight;

    size_t                   queries_sent;
    size_t                   max_queries;

    bowie_mtime_t            started_at_ms;
    bowie_mtime_t            timeout_ms;
} bowie_dht_search_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a search.
 *
 * The type selects between a node search and a peer search.
 * The target is the node ID the search looks for. For a peer
 * search, the info_hash is the hash the peers serve; for a
 * node search, the info_hash is unused.
 *
 * The caller supplies:
 *
 *   candidates       the node array
 *   candidates_cap   its capacity
 *   peers            the peer array (for a peer search)
 *   peers_cap        its capacity
 *
 * alpha is the maximum number of queries in flight. A value
 * of 0 means the default (BOWIE_DHT_SEARCH_DEFAULT_ALPHA).
 *
 * max_queries is the maximum number of queries the search
 * sends. A value of 0 means the default
 * (BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES).
 *
 * timeout_ms is the search timeout. A value of 0 means the
 * default (BOWIE_DHT_SEARCH_DEFAULT_TIMEOUT_MS).
 *
 * now_ms is the current monotonic time.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if the search, the target, the
 *   candidates array, or (for a peer search) the peers array
 *   is NULL.
 * Returns BOWIE_ERR_INVAL if the type is unknown or a
 *   capacity is 0.
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
    bowie_mtime_t                now_ms);

/*
 * Reset a search to the empty state.
 *
 * The arrays are not cleared; the used counters are reset.
 * The state becomes PENDING.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_search_clear(bowie_dht_search_t *search);

/*
 * ============================================================================
 * SEEDING
 * ============================================================================
 */

/*
 * Seed the search with a node.
 *
 * The node is added to the candidate list if there is room.
 * The list is kept sorted by XOR distance from the target,
 * closest first. A node that is already in the list is not
 * added again.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_INVAL if the node is not set.
 * Returns BOWIE_ERR_TOO_SMALL if the candidate list is
 *   full.
 */
bowie_error_t bowie_dht_search_seed(
    bowie_dht_search_t     *search,
    const bowie_dht_node_t *node);

/*
 * Seed the search with the nodes from a routing table.
 *
 * The routing table's closest nodes to the target are added
 * to the candidate list. The number added is at most the
 * candidate capacity.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 */
bowie_error_t bowie_dht_search_seed_routing(
    bowie_dht_search_t        *search,
    const bowie_dht_routing_t *routing,
    bowie_mtime_t              now_ms);

/*
 * ============================================================================
 * STEP
 * ============================================================================
 */

/*
 * Get the next node to query.
 *
 * The function finds the closest unqueried candidate, marks
 * it as queried, and writes it through out_node. The number
 * of queries in flight is incremented.
 *
 * The function returns BOWIE_ERR_NOT_FOUND when there is no
 * unqueried candidate, or when the number of queries sent
 * has reached the limit, or when the search is done.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND when there is no node to
 *   query.
 * Returns BOWIE_ERR_BUSY when the in-flight budget is full.
 */
bowie_error_t bowie_dht_search_next_query(
    bowie_dht_search_t *search,
    bowie_dht_node_t   *out_node);

/*
 * Mark a query as complete.
 *
 * The number of queries in flight is decremented. The
 * function is called when a response arrives or when the
 * query times out.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if search is NULL.
 * Returns BOWIE_ERR_INVAL if there are no queries in flight.
 */
bowie_error_t bowie_dht_search_query_done(
    bowie_dht_search_t *search);

/*
 * ============================================================================
 * RESPONSE
 * ============================================================================
 */

/*
 * Add the response from a node.
 *
 * The response is a list of compact nodes. Each node is
 * added to the candidate list if it is not already there and
 * if there is room.
 *
 * The "in flight" counter is decremented; the caller does
 * not call bowie_dht_search_query_done separately.
 *
 * For a peer search, the response may also carry a peer
 * list. The peer list is added with
 * bowie_dht_search_add_peers.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 */
bowie_error_t bowie_dht_search_add_response(
    bowie_dht_search_t              *search,
    const bowie_dht_compact_node_t  *nodes,
    size_t                           nodes_count);

/*
 * Add peers to the search result.
 *
 * The peers are added to the peer array. A peer that is
 * already in the array is not added again. A peer array that
 * is full is not extended.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 */
bowie_error_t bowie_dht_search_add_peers(
    bowie_dht_search_t           *search,
    const bowie_dht_peer_entry_t *peers,
    size_t                        peers_count);

/*
 * ============================================================================
 * STATUS
 * ============================================================================
 */

/*
 * True when the search is done.
 *
 * A search is done when:
 *
 *   - The state is DONE or FAILED, or
 *   - The number of queries sent has reached the limit, or
 *   - There is no unqueried candidate and no query is in
 *     flight.
 *
 * The function does not check the timeout. The caller checks
 * the timeout with bowie_dht_search_timed_out.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_search_is_done(const bowie_dht_search_t *search);

/*
 * Mark the search as done.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_search_finish(bowie_dht_search_t *search);

/*
 * Mark the search as failed.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_search_fail(bowie_dht_search_t *search);

/*
 * True when the search has timed out.
 *
 * Returns 1 when the elapsed time is greater than or equal
 * to the timeout, or when the clock has moved backwards past
 * the start. Returns 0 for NULL.
 */
int bowie_dht_search_timed_out(const bowie_dht_search_t *search,
                               bowie_mtime_t now_ms);

/*
 * Return the number of peers collected by the search.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_search_peer_count(
    const bowie_dht_search_t *search);

/*
 * Return the number of candidates in the search.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_search_candidate_count(
    const bowie_dht_search_t *search);

/*
 * Return the number of queries sent.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_search_query_count(
    const bowie_dht_search_t *search);

/*
 * ============================================================================
 * END OF DHT SEARCH
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_SEARCH_H */
