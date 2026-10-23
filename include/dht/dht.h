 
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
 * The engine owns a background thread that receives packets,
 * parses them, handles them, and sends responses. The caller
 * drives the engine through the public functions; the thread
 * runs on its own.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation of the routing or storage arrays. The
 *     caller supplies them.
 *   - No search orchestration. The search state machine is
 *     in search.h; the engine creates queries and handles
 *     responses, but the caller drives the search.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine has three states: uninitialized, initialized,
 * and running. A caller initializes the engine with
 * bowie_dht_init(), starts the background thread with
 * bowie_dht_start(), and stops it with bowie_dht_stop().
 *
 * The background thread owns the socket. The caller does not
 * see the socket; it can send queries through the engine's
 * query functions.
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
 *   socket        the UDP socket (owned by the thread)
 *   thread        the background thread
 *   running       1 when the thread is running
 *   stop_request  set to 1 to ask the thread to stop
 *
 * The arenas used by the thread are stored in the engine,
 * not as static variables. This allows two DHT engines to
 * run in the same process without sharing buffers.
 *
 * ----------------------------------------------------------------------------
 * Message handling
 * ----------------------------------------------------------------------------
 *
 * The background thread reads a packet, parses it, and calls
 * the message handler. The handler produces a response; the
 * thread serializes the response and sends it.
 *
 * A query message that the engine accepts produces a
 * response. A query message that the engine rejects
 * (because of a security check) produces an error response.
 * A response message updates the routing table and the
 * search; it is not answered. An error message is ignored.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <pthread.h>                  pthread_t
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
 *   "dht/bencode.h"              the bencode arena
 *   "dht/config.h"               the config
 * ============================================================================
 */

#ifndef BOWIE_DHT_DHT_H
#define BOWIE_DHT_DHT_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

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
#include "dht/bencode.h"
#include "dht/config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOWIE_DHT_TRANSACTION_CAP 64u

typedef struct bowie_dht_transaction {
    uint8_t                  tid[BOWIE_DHT_MSG_TID_MAX];
    size_t                   tid_len;
    bowie_dht_query_type_t   query_type;
    bowie_dht_info_hash_t    info_hash;
    int                      used;
} bowie_dht_transaction_t;

/*
 * ============================================================================
 * DHT ENGINE
 * ============================================================================
 *
 * The engine state. The struct is transparent for the
 * fields that the caller may read; the socket and the
 * thread are private.
 */

typedef struct bowie_dht {
    pthread_mutex_t          state_lock;
    int                      state_lock_ready;
    pthread_mutex_t          transaction_lock;
    int                      transaction_lock_ready;
    bowie_dht_transaction_t  transactions[BOWIE_DHT_TRANSACTION_CAP];
    size_t                   transaction_next;
    bowie_dht_info_hash_t    announce_hash;
    uint16_t                 announce_port;
    bowie_mtime_t            last_announce_ms;
    bowie_dht_config_t       config;
    bowie_dht_node_id_t      local_id;
    bowie_dht_routing_t      routing;
    bowie_dht_storage_t      storage;
    bowie_dht_token_state_t  token_state;
    bowie_dht_security_t     security;
    bowie_mtime_t            last_refresh_ms;
    int                      initialized;

    /*
     * The background thread and the socket it owns.
     * A caller must not touch these fields; they are
     * used by the engine's thread.
     */
    int                      socket_fd;
    pthread_t                thread;
    int                      running;
    int                      stop_requested;

    /*
     * The arenas used by the thread. They are stored in
     * the engine so that two engines in the same process
     * do not share buffers.
     *
     * The bencode arena holds the decoded tree of the
     * current packet. The message arena holds the
     * compact node and peer lists.
     */
    bowie_bencode_value_t      benc_values[512];
    bowie_bencode_dict_entry_t benc_entries[256];
    bowie_bencode_arena_t      benc_arena;

    bowie_dht_compact_node_t   msg_nodes[64];
    bowie_dht_compact_peer_t   msg_peers[64];
    bowie_dht_message_arena_t  msg_arena;
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
 * The engine does not open a socket or start a thread in
 * this function. The caller does that with
 * bowie_dht_start().
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
 * Start the DHT background thread.
 *
 * The engine must have been initialized with bowie_dht_init().
 * The function opens a UDP socket on the given port, binds it,
 * and starts a thread that receives packets and handles them.
 *
 * A port of 0 means "let the operating system choose a port".
 * The chosen port is available in the engine's config after
 * the call.
 *
 * The thread is the DHT's message loop. It calls
 * bowie_dht_handle_message() for every packet and sends the
 * response, if any. The caller does not see the socket.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht is NULL.
 * Returns BOWIE_ERR_INVAL if the engine is not initialized.
 * Returns BOWIE_ERR_STATE if the engine is already running.
 * Returns BOWIE_ERR_NETWORK if the socket cannot be opened.
 * Returns BOWIE_ERR_INTERNAL if the thread cannot be
 *   created.
 */
bowie_error_t bowie_dht_start(bowie_dht_t *dht, uint16_t port);

/* Set the peer identity and signaling port this node should announce. */
bowie_error_t bowie_dht_set_announce(bowie_dht_t *dht,
                                     const bowie_dht_info_hash_t *info_hash,
                                     uint16_t signal_port);

/*
 * Stop the DHT background thread.
 *
 * The function asks the thread to stop, waits for it to
 * exit, and closes the socket.
 *
 * Passing NULL is a no-op.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not running.
 */
bowie_error_t bowie_dht_stop(bowie_dht_t *dht);

/*
 * Shut down a DHT engine.
 *
 * The thread is stopped first. The state is cleared. The
 * arrays are not freed; the caller owns them.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_shutdown(bowie_dht_t *dht);

/*
 * Reset the engine's state without changing the config.
 *
 * The routing table, the storage, and the security rate
 * table are cleared. The config and the local ID are kept.
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
 * ping query, both are ignored. For an announce_peer query,
 * the info_hash is required and the caller fills the port
 * and the token in the returned message.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht or out is NULL, or if
 *   a required field for the query type is NULL.
 * Returns BOWIE_ERR_INVAL if the engine is not initialized,
 *   or if the query type is unknown.
 * Returns BOWIE_ERR_TOO_LARGE if the transaction id is
 *   longer than BOWIE_DHT_MSG_TID_MAX.
 * Returns a CRYPTO-class error if a random transaction id
 *   cannot be generated.
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
 * SEND QUERY
 * ============================================================================
 *
 * Send a built DHT query to a peer over the DHT socket.
 *
 * The DHT background thread owns the socket. This function
 * sends on that socket without going through the thread; a
 * UDP send is atomic, so a send from the caller's thread and
 * a send from the DHT thread do not interleave.
 *
 * The message is serialized into a local buffer, then sent
 * to the given address. The address must be IPv4.
 *
 * The caller builds the message with bowie_dht_make_query()
 * and fills the transaction id. The caller is also the one
 * that tracks the query for the search state; this function
 * does not update any search state.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if dht, to, or msg is NULL.
 * Returns BOWIE_ERR_STATE if the DHT is not running.
 * Returns BOWIE_ERR_INVAL if the address is not IPv4.
 * Returns BOWIE_ERR_TOO_LARGE if the serialized message does
 *   not fit the packet buffer.
 * Returns BOWIE_ERR_NETWORK if the send fails.
 */
bowie_error_t bowie_dht_send_query(bowie_dht_t               *dht,
                                    const bowie_addr_t        *to,
                                    const bowie_dht_message_t *msg);


/*
 * ============================================================================
 * MESSAGE HANDLING
 * ============================================================================
 */

/*
 * Handle an incoming message.
 *
 * The message has already been parsed by the message layer.
 * The sender's address is given. The current time is given
 * for the rate-limit check and the routing timestamps.
 *
 * The arena holds the arrays that the handler writes for a
 * response. The arena is the same type that the message
 * layer uses. The caller owns the arena.
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
 *   - The response's token, if any, is stored for the
 *     sender.
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
    bowie_mtime_t               now_ms,
    bowie_dht_message_arena_t  *arena,
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
 * The refresh query is a find_node query for a random ID in
 * the range of the stalest bucket. The query is written
 * through out_refresh when it is time to refresh. The caller
 * sends it.
 *
 * The out_has_refresh flag is set to 1 when a refresh query
 * was produced.
 *
 * Passing NULL for out_refresh or out_has_refresh means the
 * caller does not want the refresh query; the refresh
 * timestamp is still updated so that the next tick does not
 * repeat the same interval.
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
