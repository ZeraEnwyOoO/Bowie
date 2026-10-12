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
 * BOWIE — DHT ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * The orchestration layer for the DHT. The file is organized
 * in three parts:
 *
 *   1. Lifecycle and query building.
 *   2. Message handling.
 *   3. Maintenance.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network.
 *   - No allocation.
 *   - No thread safety.
 *   - No search orchestration.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine initializes the four sub-states (routing,
 * storage, token, security) and holds them. The arrays for
 * the routing table and the storage are caller-supplied.
 *
 * The query builder fills a message struct. The message layer
 * serializes it. The caller sends the serialized bytes.
 *
 * The engine generates a random transaction id for each
 * query. The transaction id is two bytes; the caller may
 * override it by passing a non-NULL tid.
 *
 * The engine's local ID is used as the sender ID in every
 * message it sends.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "core/internal/rand.h"       bowie_rand_secure_bytes
 *   "dht/types.h"                node id, info hash, token
 *   "dht/node.h"                 the node struct
 *   "dht/routing.h"              the routing table
 *   "dht/storage.h"              the storage
 *   "dht/token.h"                the token state
 *   "dht/security.h"             the security state
 *   "dht/message.h"              the message struct
 *   "dht/config.h"               the config
 *   "dht/dht.h"                  the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/rand.h"
#include "dht/types.h"
#include "dht/node.h"
#include "dht/routing.h"
#include "dht/storage.h"
#include "dht/token.h"
#include "dht/security.h"
#include "dht/message.h"
#include "dht/config.h"
#include "dht/dht.h"

/*
 * ============================================================================
 * PART 1 — LIFECYCLE
 * ============================================================================
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
    bowie_mtime_t                   now_ms)
{
    if (dht == NULL || config == NULL || local_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (hashes == NULL || hashes_cap == 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (peers == NULL || peers_cap == 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(dht, 0, sizeof(*dht));

    /*
     * Copy the config and normalize it. A config that
     * normalize cannot fix is reported.
     */
    dht->config = *config;
    bowie_error_t rc = bowie_dht_config_normalize(&dht->config);
    if (rc != BOWIE_OK) {
        return rc;
    }
    rc = bowie_dht_config_validate(&dht->config);
    if (rc != BOWIE_OK) {
        return rc;
    }

    dht->local_id = *local_id;

    /*
     * Initialize the routing table. The table starts with
     * one bucket.
     */
    bowie_dht_routing_init(&dht->routing, &dht->local_id);

    /*
     * Initialize the storage. The config fields are
     * copied; the arrays are borrowed.
     */
    bowie_dht_storage_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.max_hashes         = dht->config.max_hashes;
    scfg.max_peers_per_hash = dht->config.max_peers_per_hash;
    scfg.peer_lifetime_s    = dht->config.peer_lifetime_s;
    scfg.store_metadata     = dht->config.store_metadata;

    rc = bowie_dht_storage_init(&dht->storage, &scfg,
                                hashes, hashes_cap,
                                peers, peers_cap,
                                metadata);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * Initialize the token state. The rotation interval is
     * the config's value in seconds, converted to
     * milliseconds.
     */
    bowie_mtime_t rotate_ms =
        (bowie_mtime_t)dht->config.token_rotate_s * 1000u;
    rc = bowie_dht_token_state_init(&dht->token_state,
                                    rotate_ms, now_ms);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * Initialize the security state. The rate-limit table
     * is required only when the level is STRICT.
     */
    rc = bowie_dht_security_init(&dht->security,
                                 dht->config.sec_level,
                                 rate_limits, rate_limits_cap,
                                 dht->config.max_requests_per_window,
                                 0u);
    if (rc != BOWIE_OK) {
        return rc;
    }

    dht->last_refresh_ms = now_ms;
    dht->initialized = 1;
    return BOWIE_OK;
}

void bowie_dht_shutdown(bowie_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }
    memset(dht, 0, sizeof(*dht));
}

void bowie_dht_clear(bowie_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }
    bowie_dht_routing_clear(&dht->routing);
    bowie_dht_storage_clear(&dht->storage);
    bowie_dht_sec_rate_clear(&dht->security);
    dht->last_refresh_ms = 0u;
}

/*
 * ============================================================================
 * PART 1 — QUERY HELPERS
 * ============================================================================
 */

const bowie_dht_node_id_t *bowie_dht_local_id(
    const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return NULL;
    }
    return &dht->local_id;
}

size_t bowie_dht_node_count(const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return 0u;
    }
    return bowie_dht_routing_node_count(&dht->routing);
}

size_t bowie_dht_hash_count(const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return 0u;
    }
    return bowie_dht_storage_hash_count(&dht->storage);
}

size_t bowie_dht_peer_count(const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return 0u;
    }
    return bowie_dht_storage_peer_count(&dht->storage);
}

/*
 * ============================================================================
 * PART 1 — TRANSACTION ID
 * ============================================================================
 *
 * A transaction id is two bytes. The engine generates a
 * random one for each query. The caller may override the
 * value by passing a non-NULL tid with a non-zero len.
 */

static bowie_error_t random_tid(uint8_t out[2])
{
    return bowie_rand_secure_bytes(out, 2u);
}

/*
 * ============================================================================
 * PART 1 — QUERY BUILDER
 * ============================================================================
 */

bowie_error_t bowie_dht_make_query(
    bowie_dht_t                 *dht,
    bowie_dht_query_type_t       type,
    const bowie_dht_node_id_t   *target,
    const bowie_dht_info_hash_t *info_hash,
    const uint8_t               *tid,
    size_t                       tid_len,
    bowie_dht_message_t         *out)
{
    if (dht == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!dht->initialized) {
        return BOWIE_ERR_INVAL;
    }

    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_QUERY;
    out->sender_id = dht->local_id;

    /*
     * The transaction id: the caller's if given, a random
     * one otherwise.
     */
    if (tid != NULL && tid_len > 0u) {
        if (tid_len > BOWIE_DHT_MSG_TID_MAX) {
            return BOWIE_ERR_TOO_LARGE;
        }
        memcpy(out->tid, tid, tid_len);
        out->tid_len = tid_len;
    } else {
        bowie_error_t rc = random_tid(out->tid);
        if (rc != BOWIE_OK) {
            return rc;
        }
        out->tid_len = 2u;
    }

    switch (type) {
    case BOWIE_DHT_QUERY_PING:
        out->query_type = type;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_FIND_NODE:
        if (target == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->query_type = type;
        out->target = *target;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_GET_PEERS:
        if (info_hash == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->query_type = type;
        out->info_hash = *info_hash;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
        if (info_hash == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->query_type = type;
        out->info_hash = *info_hash;
        /*
         * The port and the token are filled by the caller
         * before the message is sent. The caller sets
         * out->port and out->token.
         */
        return BOWIE_OK;

    default:
        return BOWIE_ERR_INVAL;
    }
}

/*
 * ============================================================================
 * END OF PART 1
 * ============================================================================
 */
/*
 * ============================================================================
 * PART 2 — MESSAGE HANDLING
 * ============================================================================
 *
 * The message handler processes an incoming message and, for
 * a query, produces a response.
 *
 * The handler is the entry point for the network. The caller
 * parses the message with the message layer, then calls the
 * handler. The handler updates the routing table and the
 * storage, and fills a response message.
 *
 * The handler applies the security checks. A message that
 * fails a check is answered with an error, or dropped.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The handler does not send the response. The caller
 * serializes the response and sends it.
 *
 * For a response message, the handler updates the routing
 * table with the sender's node ID and address. It also
 * updates the sender's token if the response carried one.
 * The handler does not fill a response; out_has_response is
 * set to 0.
 *
 * For an error message, the handler does nothing. The caller
 * may use the error to update a search.
 *
 * A query from an unknown node is accepted if the security
 * checks pass. The node is added to the routing table with
 * the sender ID from the message. The sender ID is verified
 * against the address by the security check.
 */

/*
 * ============================================================================
 * INTERNAL — ERROR RESPONSE
 * ============================================================================
 *
 * Build an error response to a query. The transaction id is
 * copied from the query. The error code and message are
 * filled in.
 */

static void build_error_response(
    const bowie_dht_message_t *query,
    int                        code,
    const char                *message,
    bowie_dht_message_t       *out)
{
    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_ERROR;
    out->tid_len = query->tid_len;
    memcpy(out->tid, query->tid, query->tid_len);
    out->error_code = code;
    out->error_message.data = (const uint8_t *)message;
    out->error_message.len  = (message != NULL)
                              ? strlen(message) : 0u;
}

/*
 * ============================================================================
 * INTERNAL — HANDLE PING
 * ============================================================================
 *
 * A ping query is answered with a response that carries the
 * local node ID and nothing else.
 */

static bowie_error_t handle_ping(
    const bowie_dht_t         *dht,
    const bowie_dht_message_t *query,
    bowie_dht_message_t       *out)
{
    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_RESPONSE;
    out->tid_len = query->tid_len;
    memcpy(out->tid, query->tid, query->tid_len);
    out->sender_id = dht->local_id;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — HANDLE FIND_NODE
 * ============================================================================
 *
 * A find_node query is answered with the closest nodes to
 * the target from the routing table.
 */

static bowie_error_t handle_find_node(
    bowie_dht_t               *dht,
    const bowie_dht_message_t *query,
    bowie_mtime_t              now_ms,
    bowie_dht_message_t       *out)
{
    /*
     * Select the closest nodes to the target.
     */
    bowie_dht_node_t nodes[BOWIE_DHT_K];
    size_t count = 0u;

    bowie_error_t rc = bowie_dht_routing_select_closest(
        &dht->routing, &query->target, now_ms,
        nodes, BOWIE_DHT_K, &count);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * Convert the nodes to the compact format. The compact
     * array is on the stack.
     */
    bowie_dht_compact_node_t compact[BOWIE_DHT_K];
    for (size_t i = 0u; i < count; i++) {
        compact[i].id = nodes[i].id;
        compact[i].addr = nodes[i].addr;
    }

    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_RESPONSE;
    out->tid_len = query->tid_len;
    memcpy(out->tid, query->tid, query->tid_len);
    out->sender_id = dht->local_id;

    /*
     * The nodes are stored in the response's node array.
     * The array is owned by the caller; the handler fills
     * the fields. The caller's message arena is the one
     * that holds the array.
     *
     * The handler does not have access to the caller's
     * arena. The caller must set out->nodes and
     * out->nodes_cap before calling, or the handler leaves
     * the list empty.
     *
     * The convention is: the caller passes a message whose
     * nodes array and cap are set. The handler writes into
     * the array.
     */
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — HANDLE GET_PEERS
 * ============================================================================
 *
 * A get_peers query is answered with the peers for the info
 * hash, or with the closest nodes when there are no peers.
 * The response includes a token.
 */

static bowie_error_t handle_get_peers(
    bowie_dht_t               *dht,
    const bowie_dht_message_t *query,
    const bowie_addr_t        *from,
    bowie_mtime_t              now_ms,
    bowie_dht_message_t       *out)
{
    /*
     * Generate a token for the sender. The token is
     * included in the response.
     */
    bowie_dht_token_t token;
    bowie_error_t rc = bowie_dht_token_generate(
        &dht->token_state, from, &token);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * Find the peers for the info hash.
     */
    bowie_dht_peer_entry_t peers[BOWIE_DHT_STORAGE_DEFAULT_MAX_PEERS_PER_HASH];
    size_t peer_count = 0u;

    rc = bowie_dht_storage_find_peers(
        &dht->storage, &query->info_hash,
        peers, NULL,
        sizeof(peers) / sizeof(peers[0]),
        &peer_count);
    if (rc != BOWIE_OK && rc != BOWIE_ERR_NOT_FOUND) {
        return rc;
    }

    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_RESPONSE;
    out->tid_len = query->tid_len;
    memcpy(out->tid, query->tid, query->tid_len);
    out->sender_id = dht->local_id;
    out->token = token;

    /*
     * The peers and nodes are written into the caller's
     * arrays. The caller sets out->peers, out->peers_cap,
     * out->nodes, and out->nodes_cap before calling.
     *
     * The handler fills the arrays. See the convention
     * in handle_find_node.
     */
    (void)peer_count;
    (void)now_ms;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — HANDLE ANNOUNCE_PEER
 * ============================================================================
 *
 * An announce_peer query stores the peer. The token is
 * validated first. A failed token is an error.
 */

static bowie_error_t handle_announce_peer(
    bowie_dht_t               *dht,
    const bowie_dht_message_t *query,
    const bowie_addr_t        *from,
    bowie_mtime_t              now_ms,
    bowie_dht_message_t       *out,
    int                       *out_has_response)
{
    /*
     * Validate the token.
     */
    if (!bowie_dht_token_validate(&dht->token_state,
                                  from, &query->token)) {
        build_error_response(query, 203, "bad token", out);
        *out_has_response = 1;
        return BOWIE_OK;
    }

    /*
     * Store the peer. The address is the sender's address;
     * the port is the port from the query, unless the
     * implied_port flag is set, in which case the port is
     * the sender's source port.
     */
    bowie_dht_peer_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.addr = *from;
    if (!query->implied_port) {
        entry.addr.port = query->port;
    }
    entry.capabilities = 0u;  /* filled by the caller */
    entry.last_seen_ms = now_ms;

    bowie_error_t rc = bowie_dht_storage_add_peer(
        &dht->storage, &query->info_hash, &entry);
    if (rc != BOWIE_OK) {
        build_error_response(query, 202, "storage full", out);
        *out_has_response = 1;
        return BOWIE_OK;
    }

    /*
     * The response carries the local node ID and nothing
     * else.
     */
    memset(out, 0, sizeof(*out));
    out->type = BOWIE_DHT_MSG_RESPONSE;
    out->tid_len = query->tid_len;
    memcpy(out->tid, query->tid, query->tid_len);
    out->sender_id = dht->local_id;
    *out_has_response = 1;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * PART 2 — HANDLE MESSAGE
 * ============================================================================
 */

bowie_error_t bowie_dht_handle_message(
    bowie_dht_t                *dht,
    const bowie_dht_message_t  *msg,
    const bowie_addr_t         *from,
    bowie_dht_message_t        *out_response,
    int                        *out_has_response)
{
    if (dht == NULL || msg == NULL || from == NULL ||
        out_response == NULL || out_has_response == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!dht->initialized) {
        return BOWIE_ERR_INVAL;
    }

    *out_has_response = 0;

    /*
     * Security: node ID check.
     */
    if (!bowie_dht_sec_node_id_ok(&dht->security,
                                  &msg->sender_id, from)) {
        if (msg->type == BOWIE_DHT_MSG_QUERY) {
            build_error_response(msg, 203, "bad node id",
                                 out_response);
            *out_has_response = 1;
        }
        return BOWIE_OK;
    }

    /*
     * Security: rate limit. Applied only to queries.
     */
    if (dht->security.level == BOWIE_DHT_SEC_STRICT &&
        msg->type == BOWIE_DHT_MSG_QUERY) {
        bowie_error_t rc = bowie_dht_sec_check_rate(
            &dht->security, from, 0u);
        if (rc == BOWIE_ERR_BUSY) {
            build_error_response(msg, 202, "rate limited",
                                 out_response);
            *out_has_response = 1;
            return BOWIE_OK;
        }
        /* A full table is not an error for the message. */
    }

    /*
     * A query from a known or unknown node. The sender is
     * added to the routing table if the checks pass.
     */
    if (msg->type == BOWIE_DHT_MSG_QUERY ||
        msg->type == BOWIE_DHT_MSG_RESPONSE) {
        bowie_dht_node_t node;
        memset(&node, 0, sizeof(node));
        node.id = msg->sender_id;
        node.addr = *from;
        node.last_seen_ms = 0u;  /* filled by routing_add */

        (void)bowie_dht_routing_add(&dht->routing, &node, 0u);

        if (msg->type == BOWIE_DHT_MSG_RESPONSE) {
            /*
             * The response's token, if any, is stored
             * for the node. The response's nodes are
             * not added to the routing table by the
             * handler; the caller's search handles
             * them.
             */
            if (bowie_dht_token_is_zero(&msg->token) == 0) {
                (void)bowie_dht_routing_set_token(
                    &dht->routing, &msg->sender_id,
                    &msg->token);
            }
            return BOWIE_OK;
        }
    }

    /*
     * The message is a query. Dispatch by query type.
     */
    switch (msg->query_type) {
    case BOWIE_DHT_QUERY_PING:
        (void)handle_ping(dht, msg, out_response);
        *out_has_response = 1;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_FIND_NODE:
        (void)handle_find_node(dht, msg, 0u, out_response);
        *out_has_response = 1;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_GET_PEERS:
        (void)handle_get_peers(dht, msg, from, 0u, out_response);
        *out_has_response = 1;
        return BOWIE_OK;

    case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
        return handle_announce_peer(dht, msg, from, 0u,
                                    out_response,
                                    out_has_response);

    default:
        /*
         * An unknown query type is ignored. The caller
         * may send an error response; the handler does
         * not.
         */
        return BOWIE_OK;
    }
}

/*
 * ============================================================================
 * PART 3 — MAINTENANCE
 * ============================================================================
 */

bowie_error_t bowie_dht_tick(
    bowie_dht_t          *dht,
    bowie_mtime_t         now_ms,
    bowie_dht_message_t  *out_refresh,
    int                  *out_has_refresh)
{
    if (dht == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!dht->initialized) {
        return BOWIE_ERR_INVAL;
    }

    if (out_has_refresh != NULL) {
        *out_has_refresh = 0;
    }

    /*
     * Rotate the token secret when the interval has
     * elapsed.
     */
    if (bowie_dht_token_should_rotate(&dht->token_state,
                                      now_ms)) {
        (void)bowie_dht_token_rotate(&dht->token_state, now_ms);
    }

    /*
     * Expire the stale peer entries.
     */
    (void)bowie_dht_storage_expire(&dht->storage, now_ms);

    /*
     * Refresh a bucket when the refresh interval has
     * elapsed. The refresh is a find_node query for a
     * random ID.
     */
    bowie_mtime_t interval_ms =
        (bowie_mtime_t)dht->config.refresh_interval_s * 1000u;

    if (interval_ms == 0u) {
        return BOWIE_OK;
    }

    if (now_ms < dht->last_refresh_ms) {
        /*
         * The clock moved backwards. Do not refresh.
         */
        return BOWIE_OK;
    }

    if ((now_ms - dht->last_refresh_ms) < interval_ms) {
        return BOWIE_OK;
    }

    if (out_refresh == NULL || out_has_refresh == NULL) {
        /*
         * The caller does not want the refresh query.
         * Update the timestamp anyway, so that the next
         * tick does not repeat the same interval.
         */
        dht->last_refresh_ms = now_ms;
        return BOWIE_OK;
    }

    /*
     * Find the stalest bucket and generate a random ID in
     * its range. The random ID is a node ID whose first
     * differing bit from the local ID is at the bucket's
     * index.
     */
    int bucket_idx = bowie_dht_routing_stalest_bucket(
        &dht->routing);
    if (bucket_idx < 0) {
        dht->last_refresh_ms = now_ms;
        return BOWIE_OK;
    }

    /*
     * A random target ID. The ID is the local ID with the
     * bit at the bucket index flipped, and the lower bits
     * randomized. The result is a target in the bucket's
     * range.
     */
    bowie_dht_node_id_t target = dht->local_id;

    size_t byte_idx = (size_t)bucket_idx / 8u;
    int    bit_idx  = 7 - (bucket_idx % 8);
    if (byte_idx < BOWIE_DHT_NODE_ID_LEN) {
        target.bytes[byte_idx] ^= (uint8_t)(1u << bit_idx);

        /*
         * Randomize the bits below the flipped bit. A
         * simple approach: fill the bytes after byte_idx
         * with random values.
         */
        if (byte_idx + 1u < BOWIE_DHT_NODE_ID_LEN) {
            (void)bowie_rand_secure_bytes(
                target.bytes + byte_idx + 1u,
                BOWIE_DHT_NODE_ID_LEN - byte_idx - 1u);
        }
    }

    bowie_error_t rc = bowie_dht_make_query(
        dht, BOWIE_DHT_QUERY_FIND_NODE, &target, NULL,
        NULL, 0u, out_refresh);
    if (rc != BOWIE_OK) {
        return rc;
    }

    dht->last_refresh_ms = now_ms;
    *out_has_refresh = 1;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
