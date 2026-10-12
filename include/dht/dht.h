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
 * BOWIE — DHT ENGINE
 * ============================================================================
 *
 * The DHT engine: the orchestration layer that ties the
 * routing table, the storage, the token state, and the
 * security state together.
 *
 * The engine is a value type. The caller supplies the arrays
 * that the routing table and the storage use. The engine
 * does not allocate.
 *
 * The engine is the layer that the rest of Bowie talks to.
 * The DHT engine receives a message, applies the security
 * checks, and produces a response. The DHT engine creates a
 * query for a target. The DHT engine runs the periodic
 * maintenance.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network. The caller sends and receives packets.
 *   - No allocation. The caller supplies the arrays.
 *   - No thread safety. The caller serializes access.
 *   - No search orchestration. The search state machine is
 *     in search.h; the engine creates queries and handles
 *     responses, but the caller drives the search.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine holds:
 *
 *   config        the DHT config (copied)
 *   local_id      the node ID of this node
 *   routing       the routing table
 *   storage       the key-value storage
 *   token_state   the token generator state
 *   security      the security state
 *   last_refresh  the time of the last refresh tick
 *
 * The routing table and the storage are value types with
 * caller-supplied arrays. The engine copies the config, the
 * local ID, and the state, but not the arrays; the arrays
 * are shared with the caller and the engine writes into
 * them.
 *
 * The engine's message handler is a state machine over the
 * message type:
 *
 *   QUERY     process the query and produce a response
 *   RESPONSE  process the response; the caller updates the
 *             search and the routing table
 *   ERROR     log and ignore
 *
 * The engine's query builder produces a query message from a
 * target and a query type. The caller sends the message.
 *
 * The engine's tick function runs the periodic maintenance:
 *
 *   - rotate the token secret when the interval has elapsed
 *   - expire the stale peer entries
 *   - refresh a routing bucket when the interval has elapsed
 *
 * The refresh is a find_node query for a random ID in the
 * bucket's range. The engine does not send the query; the
 * tick function returns the refresh query through an out
 * parameter, and the caller sends it.
 *
 * ----------------------------------------------------------------------------
 * Message handling
 * ----------------------------------------------------------------------------
 *
 * A query message that the engine accepts produces a
 * response. The response is built in a caller-supplied
 * message struct. The caller serializes the message and
 * sends it.
 *
 * A query message that the engine rejects (because of a
 * security check) produces an error response. The error code
 * and message are set in the response struct.
 *
 * A response message is not answered. The caller updates the
 * routing table and the search. The engine's handler updates
 * the routing table on the caller's behalf.
 *
 * A message that is malformed or that has an unknown type is
 * ignored. The caller does not send a response.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, info hash, token
 *   "dht/node.h"                 the node struct
 *   "dht/bucket.h"               the bucket struct
 *   "dht/routing.h"              the routing table
 *   "dht/storage.h"              the storage
 *   "dht/token.h"                the token state
 *   "dht/security.h"             the security state
 *   "dht/message.h"              the message struct
 *   "dht/config.h"               the config
 * ============================================================================
 */

#ifndef BOWIE_DHT_DHT_H
#define BOWIE_DHT_DHT_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/bucket.h"
#include "dht/routing.h"
#include "dht/storage.h"
#include "dht/token.h"
#include "dht/security.h"
#include "dht/message.h"
#include "dht/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * DHT ENGINE
 * ============================================================================
 *
 * The engine state. The struct is transparent; a caller may
 * read the fields. The arrays are borrowed from the caller
 * and are not owned by the engine.
 */

typedef struct bowie_dht {
    bowie_dht_config_t       config;
    bowie_dht_node_id_t      local_id;
    bowie_dht_routing_t      routing;
    bowie_dht_storage_t      storage;
    bowie_dht_token_state_t  token_state;
    bowie_dht_security_t     security;
    bowie_mtime_t            last_refresh_ms;
    int                      initialized;
} bowie_dht_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a DHT engine.
 *
 * The caller supplies:
 *
 *   config          the DHT config (copied)
 *   local_id        the local node ID (copied)
 *   hashes          the storage's hash array
 *   hashes_cap      its capacity
 *   peers           the storage's peer array
 *   peers_cap       its capacity
 *   metadata        the storage's metadata array, or NULL
 *                   when store_metadata is 0
 *   rate_limits     the security's rate-limit table, or
 *                   NULL when the level is not STRICT
 *   rate_limits_cap its capacity
 *   now_ms          the current monotonic time
 *
 * The routing table is initialized from the local ID. The
 * storage is initialized from the config. The token state is
 * initialized with a rotation interval from the config. The
 * security state is initialized with the level from the
 * config.
 *
 * The config is normalized before it is copied.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht, config, or local_id is
 *   NULL, or if a required array is NULL.
 * Returns BOWIE_ERR_INVAL if the config is not usable after
 *   normalization.
 * Returns a CRYPTO-class error if the token state cannot be
 *   initialized.
 */
bowie_error_t bowie_dht_init(
    bowie_dht_t                    *dht,
    const bowie_dht_config_t       *config,
    const bowie_dht_node_id_t      *local_id,
    bowie_dht_hash_entry_t         *hashes,
    size_t                          hashes_cap,
    bowie_dht_peer_entry_t         *peers,
    size_t                          peers_cap,
    bowie_dht_peer_metadata_t      *metadata,
    bowie_dht_rate_limit_t         *rate_limits,
    size_t                          rate_limits_cap,
    bowie_mtime_t                   now_ms);

/*
 * Shut down a DHT engine.
 *
 * The state is cleared. The arrays are not freed; the caller
 * owns them.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_shutdown(bowie_dht_t *dht);

/*
 * Reset the engine's state without changing the config.
 *
 * The routing table, the storage, the token state, and the
 * security state are cleared. The config and the local ID
 * are kept.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_clear(bowie_dht_t *dht);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Build a query message.
 *
 * The query type selects the fields that are filled. The
 * transaction id is copied into the message. The sender ID
 * is the local ID.
 *
 * The caller serializes the message and sends it. The
 * caller's search state tracks the query.
 *
 * For a find_node query, the target is required and the
 * info_hash is ignored. For a get_peers query, the
 * info_hash is required and the target is ignored. For a
 * ping query, both are ignored.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht or out is NULL, or if
 *   a required field for the query type is NULL.
 * Returns BOWIE_ERR_INVAL if the engine is not initialized,
 *   or if the query type is unknown.
 */
bowie_error_t bowie_dht_make_query(
    bowie_dht_t                 *dht,
    bowie_dht_query_type_t       type,
    const bowie_dht_node_id_t   *target,
    const bowie_dht_info_hash_t *info_hash,
    const uint8_t               *tid,
    size_t                       tid_len,
    bowie_dht_message_t         *out);

/*
 * ============================================================================
 * MESSAGE HANDLING
 * ============================================================================
 */

/*
 * Handle an incoming message.
 *
 * The message has already been parsed by the message layer.
 * The sender's address is given.
 *
 * For a QUERY message:
 *
 *   - The security checks are applied. A failed node ID
 *     check or a failed rate limit produces an error
 *     response.
 *   - A ping query produces a pong response.
 *   - A find_node query produces a nodes response with the
 *     closest nodes from the routing table.
 *   - A get_peers query produces a response with the peers
 *     for the info hash, or with the closest nodes when
 *     there are no peers. The response includes a token.
 *   - An announce_peer query stores the peer. The token is
 *     validated; a failed token produces an error response.
 *
 * For a RESPONSE message:
 *
 *   - The routing table is updated with the sender's node
 *     ID and address.
 *   - The response is not answered. The caller reads the
 *     response's nodes and peers and updates its search.
 *
 * For an ERROR message:
 *
 *   - The message is ignored.
 *
 * The out_response is filled when a response is produced.
 * The out_has_response is set to 1 when there is a response
 * to send, and to 0 otherwise.
 *
 * The caller serializes the response and sends it.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_INVAL if the engine is not initialized,
 *   or if the message is malformed for its type.
 */
bowie_error_t bowie_dht_handle_message(
    bowie_dht_t                *dht,
    const bowie_dht_message_t  *msg,
    const bowie_addr_t         *from,
    bowie_dht_message_t        *out_response,
    int                        *out_has_response);

/*
 * ============================================================================
 * MAINTENANCE
 * ============================================================================
 */

/*
 * Run the periodic maintenance.
 *
 * The function:
 *
 *   - rotates the token secret when the interval has elapsed
 *   - expires the stale peer entries
 *   - builds a refresh query when the refresh interval has
 *     elapsed
 *
 * The refresh query is a find_node query for a random ID.
 * The query is written through out_refresh when it is time
 * to refresh. The caller sends it.
 *
 * The out_has_refresh flag is set to 1 when a refresh query
 * was produced.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht is NULL.
 * Returns BOWIE_ERR_INVAL if the engine is not initialized.
 */
bowie_error_t bowie_dht_tick(
    bowie_dht_t          *dht,
    bowie_mtime_t         now_ms,
    bowie_dht_message_t  *out_refresh,
    int                  *out_has_refresh);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the local node ID.
 *
 * Returns NULL for NULL.
 */
const bowie_dht_node_id_t *bowie_dht_local_id(
    const bowie_dht_t *dht);

/*
 * Return the number of live nodes in the routing table.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_node_count(const bowie_dht_t *dht);

/*
 * Return the number of distinct info hashes in the storage.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_hash_count(const bowie_dht_t *dht);

/*
 * Return the number of peer entries in the storage.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_peer_count(const bowie_dht_t *dht);

/*
 * ============================================================================
 * END OF DHT ENGINE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_DHT_H */
