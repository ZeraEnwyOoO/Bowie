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
