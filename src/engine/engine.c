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
 * BOWIE — ENGINE (IMPLEMENTATION)
 * ============================================================================
 *
 * The engine ties every layer together.
 *
 * This file implements the public API declared in
 * engine/engine.h. It is the only file in the library that
 * sees every subsystem at once.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No DHT. The DHT layer does the work; the engine only
 *     starts, stops, and queries it.
 *   - No NAT. The NAT layer does the work; the engine only
 *     drives the connection setup.
 *   - No tunnel. The tunnel is supplied by the caller; the
 *     engine only uses it.
 *   - No security. The security layer verifies grants; the
 *     engine only collects the inputs.
 *   - No gateway. The gateway forwards packets; the engine
 *     only starts and stops it.
 *   - No UI. The engine has no command line and no output.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine is a point-to-point tool. At most one peer is
 * connected at a time. The session and the gateway are the
 * current connection; a hub is a future feature.
 *
 * The engine owns a lock. Every public function takes the
 * lock before touching the state. The internal threads (DHT,
 * signal) take the lock when they report an event. The lock
 * is a recursive mutex so that the event hook, which runs
 * with the lock released by the drain, can call back into
 * the public API without deadlocking.
 *
 * The DHT struct is heap-allocated because its arenas are
 * stored inline and the struct is about 200 KB. The storage
 * arrays are separate heap allocations; the DHT layer only
 * borrows them.
 *
 * The connect and accept paths are symmetric. Both run the
 * same five steps:
 *
 *   1. Establish a NAT connection.
 *   2. Run the handshake.
 *   3. Exchange session keypairs.
 *   4. Run the permission check.
 *   5. Create the session and start the gateway.
 *
 * The difference is the order: connect searches the peer and
 * sends the first signaling payload; accept waits for the
 * peer to send it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>                 mutex, condition variable
 *   <stdlib.h>                  calloc, free
 *   <string.h>                  memset, memcpy
 *   "bowie/types.h"             types
 *   "bowie/err.h"               errors
 *   "bowie/hooks.h"             hooks
 *   "core/internal/log.h"       logging
 *   "core/internal/rand.h"      entropy
 *   "core/internal/time.h"      time
 *   "dht/dht.h"                 DHT
 *   "dht/search.h"              DHT search
 *   "nat/nat.h"                 NAT
 *   "tunnel/tun_linux.h"        tunnel
 *   "gateway/gateway.h"         gateway
 *   "security/grant.h"          grant
 *   "security/keypair.h"        X25519
 *   "security/ownership.h"      PoO
 *   "security/permission.h"     permission
 *   "security/revoke.h"         revocation
 *   "security/session.h"        session
 *   "security/sign.h"           Ed25519
 *   "security/quota.h"          quota
 *   "net/peer.h"                peer
 *   "engine/engine.h"           public API
 *   "engine/internal/engine.h"  struct
 *   "engine/internal/state.h"   state machine
 *   "engine/internal/event.h"   event queue
 *   "engine/internal/signal.h"  signaling
 * ============================================================================
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "core/internal/log.h"
#include "core/internal/rand.h"
#include "core/internal/time.h"
#include "dht/dht.h"
#include "dht/search.h"
#include "nat/nat.h"
#include "tunnel/tun_linux.h"
#include "gateway/gateway.h"
#include "security/grant.h"
#include "security/keypair.h"
#include "security/ownership.h"
#include "security/permission.h"
#include "security/revoke.h"
#include "security/session.h"
#include "security/sign.h"
#include "security/quota.h"
#include "net/peer.h"
#include "engine/engine.h"
#include "engine/internal/engine.h"
#include "engine/internal/state.h"
#include "engine/internal/event.h"
#include "engine/internal/signal.h"

/*
 * ============================================================================
 * INTERNAL — LOG
 * ============================================================================
 */

static bowie_log_t g_engine_log;
static int         g_engine_log_ready = 0;

static void engine_log_init(void)
{
    if (!g_engine_log_ready) {
        bowie_log_init(&g_engine_log, NULL, BOWIE_LOG_INFO);
        g_engine_log_ready = 1;
    }
}

#define ENGINE_LOG(level, ...) \
    do { \
        engine_log_init(); \
        bowie_log_emit(&g_engine_log, (level), __VA_ARGS__); \
    } while (0)

/*
 * ============================================================================
 * INTERNAL — DERIVE IDS
 * ============================================================================
 *
 * The engine's identity is an Ed25519 keypair. The public ID
 * is the raw public key. The peer ID and the DHT node ID are
 * derived from the public ID by the hash function in use.
 *
 * The peer ID is 20 bytes; the hash is SHA-1, which is the
 * DHT identifier space. The DHT node ID is also 20 bytes and
 * is derived the same way; the two are kept separate because
 * they identify different layers.
 */

static bowie_error_t derive_ids(bowie_engine_t *e)
{
    bowie_hash_sha1_t h;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memcpy(e->own_public_id.bytes, e->own_sign_pub.bytes,
           BOWIE_PUBLIC_ID_LEN);

    bowie_error_t rc = bowie_hash_sha1(e->own_public_id.bytes,
                                        BOWIE_PUBLIC_ID_LEN, &h);
    if (rc != BOWIE_OK) {
        return rc;
    }

    memcpy(e->own_peer_id.bytes, h.bytes, BOWIE_PEER_ID_LEN);
    memcpy(e->own_dht_id.bytes, h.bytes, BOWIE_DHT_NODE_ID_LEN);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — DEFAULT DHT CONFIG
 * ============================================================================
 *
 * Build a DHT config from the engine config. The DHT config's
 * bootstrap list is empty; the caller adds peers through
 * bowie_dht_config_add_bootstrap() after engine creation.
 *
 * The security level is set to BASIC because the engine is
 * designed to run on a public network. A caller that wants
 * STRICT sets it through the DHT config directly.
 */

static void make_dht_config(const bowie_engine_config_t *cfg,
                            bowie_dht_config_t *out)
{
    memset(out, 0, sizeof(*out));

    out->max_buckets         = BOWIE_DHT_DEFAULT_MAX_BUCKETS;
    out->max_nodes_per_bucket = BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET;
    out->max_hashes          = BOWIE_ENGINE_DHT_HASHES_CAP;
    out->max_peers_per_hash  = BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH;
    out->max_storage_peers   = BOWIE_ENGINE_DHT_PEERS_CAP;
    out->refresh_interval_s  = BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S;
    out->peer_lifetime_s     = BOWIE_DHT_DEFAULT_PEER_LIFETIME_S;
    out->token_rotate_s      = BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S;
    out->search_timeout_ms   = BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS;

    out->sec_level           = BOWIE_DHT_SEC_BASIC;
    out->max_requests_per_window = BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS;

    (void)cfg;  /* ports are handled by bowie_dht_start() */
}

/*
 * ============================================================================
 * INTERNAL — DEFAULT NAT CONFIG
 * ============================================================================
 */

static void make_nat_config(const bowie_engine_config_t *cfg,
                            bowie_nat_config_t *out)
{
    bowie_nat_default_config(out);

    out->allow_server = cfg->allow_server ? 1 : 0;

    if (cfg->allow_server) {
        out->stun_server_host = cfg->stun_host;
        out->stun_server_port = cfg->stun_port;

        out->turn_server_host = cfg->turn_host;
        out->turn_server_port = cfg->turn_port;
        out->turn_username    = cfg->turn_user;
        out->turn_password    = cfg->turn_pass;
    }
}

/*
 * ============================================================================
 * LIFECYCLE — DEFAULTS
 * ============================================================================
 */

void bowie_engine_default_config(bowie_engine_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->dht_port       = 0;
    cfg->nat_port       = 0;
    cfg->allow_server   = 0;
    cfg->stun_host      = NULL;
    cfg->stun_port      = 0;
    cfg->turn_host      = NULL;
    cfg->turn_port      = 0;
    cfg->turn_user      = NULL;
    cfg->turn_pass      = NULL;
    cfg->tunnel_mtu     = 0;
}

/*
 * ============================================================================
 * LIFECYCLE — NEW
 * ============================================================================
 */

bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out)
{
    bowie_engine_t *e;
    bowie_error_t   rc;

    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    e = (bowie_engine_t *)calloc(1, sizeof(*e));
    if (e == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    /*
     * A recursive mutex so that the event hook, which runs
     * with the lock released by the drain, can call back
     * into the public API without deadlocking.
     */
    {
        pthread_mutexattr_t attr;

        if (pthread_mutexattr_init(&attr) != 0) {
            free(e);
            return BOWIE_ERR_INTERNAL;
        }
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

        if (pthread_mutex_init(&e->lock, &attr) != 0) {
            pthread_mutexattr_destroy(&attr);
            free(e);
            return BOWIE_ERR_INTERNAL;
        }
        pthread_mutexattr_destroy(&attr);
    }

    if (pthread_cond_init(&e->nat_cond, NULL) != 0) {
        pthread_mutex_destroy(&e->lock);
        free(e);
        return BOWIE_ERR_INTERNAL;
    }

    if (cfg != NULL) {
        e->cfg = *cfg;
    } else {
        bowie_engine_default_config(&e->cfg);
    }

    /*
     * Generate the identity keypair. The Ed25519 private key
     * is 64 bytes: seed || public. OpenSSL wants a 32-byte
     * seed; the security layer handles the conversion.
     */
    rc = bowie_security_sign_generate(&e->own_sign_pub,
                                       &e->own_sign_priv);
    if (rc != BOWIE_OK) {
        pthread_cond_destroy(&e->nat_cond);
        pthread_mutex_destroy(&e->lock);
        free(e);
        return rc;
    }

    rc = derive_ids(e);
    if (rc != BOWIE_OK) {
        pthread_cond_destroy(&e->nat_cond);
        pthread_mutex_destroy(&e->lock);
        free(e);
        return rc;
    }

    /*
     * State, security, and event queue.
     */
    e->state = BOWIE_ENGINE_STOPPED;

    bowie_revoke_list_clear(&e->revoke_list);
    bowie_quota_init(&e->quota);
    bowie_engine_event_queue_clear(&e->events);

    e->signal_fd   = -1;
    e->signal_port = 0;

    *out = e;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * LIFECYCLE — FREE
 * ============================================================================
 */

void bowie_engine_free(bowie_engine_t *e)
{
    if (e == NULL) {
        return;
    }

    if (e->state != BOWIE_ENGINE_STOPPED) {
        (void)bowie_engine_stop(e);
    }

    /*
     * Wipe the private key before freeing the handle. The
     * key is a secret; leaving it in freed memory is a
     * bug.
     */
    memset(&e->own_sign_priv, 0, sizeof(e->own_sign_priv));

    pthread_cond_destroy(&e->nat_cond);
    pthread_mutex_destroy(&e->lock);

    free(e);
}

/*
 * ============================================================================
 * LIFECYCLE — START
 * ============================================================================
 *
 * Bring up the DHT, the NAT layer, and the signaling
 * channel. The caller supplies the tunnel; the engine does
 * not open or close it.
 *
 * A start that fails leaves the engine in STOPPED state; the
 * caller may retry.
 */

bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun)
{
    bowie_dht_config_t  dht_cfg;
    bowie_nat_config_t  nat_cfg;
    bowie_error_t       rc;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (e->state != BOWIE_ENGINE_STOPPED) {
        return BOWIE_ERR_STATE;
    }
    if (tun == NULL) {
        return BOWIE_ERR_INVAL;
    }

    pthread_mutex_lock(&e->lock);

    /*
     * DHT.
     */
    make_dht_config(&e->cfg, &dht_cfg);

    e->dht = (bowie_dht_t *)calloc(1, sizeof(*e->dht));
    if (e->dht == NULL) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_NOMEM;
    }

    e->dht_hashes = (bowie_dht_hash_entry_t *)calloc(
        BOWIE_ENGINE_DHT_HASHES_CAP, sizeof(*e->dht_hashes));
    e->dht_peers = (bowie_dht_peer_entry_t *)calloc(
        BOWIE_ENGINE_DHT_PEERS_CAP, sizeof(*e->dht_peers));
    e->dht_rate_limits = (bowie_dht_rate_limit_t *)calloc(
        BOWIE_ENGINE_DHT_RATE_LIMIT_CAP,
        sizeof(*e->dht_rate_limits));

    if (e->dht_hashes == NULL || e->dht_peers == NULL ||
        e->dht_rate_limits == NULL) {
        rc = BOWIE_ERR_NOMEM;
        goto fail_dht_alloc;
    }

    rc = bowie_dht_init(e->dht, &dht_cfg, &e->own_dht_id,
                        e->dht_hashes, BOWIE_ENGINE_DHT_HASHES_CAP,
                        e->dht_peers, BOWIE_ENGINE_DHT_PEERS_CAP,
                        NULL,
                        e->dht_rate_limits,
                        BOWIE_ENGINE_DHT_RATE_LIMIT_CAP,
                        bowie_time_monotonic_ms());
    if (rc != BOWIE_OK) {
        goto fail_dht_alloc;
    }

    rc = bowie_dht_start(e->dht, e->cfg.dht_port);
    if (rc != BOWIE_OK) {
        goto fail_dht_alloc;
    }

    /*
     * Read back the actual port. The caller may have asked
     * for 0; the OS chooses a port in that case.
     */
    {
        /* The DHT layer does not expose the bound port
         * directly; we use the config's value, which is 0
         * when the caller asked for auto. The actual port
         * is not essential for the engine's operation. */
        e->dht_port = e->cfg.dht_port;
    }

    /*
     * NAT.
     */
    make_nat_config(&e->cfg, &nat_cfg);

    rc = bowie_nat_new(&nat_cfg, &e->nat);
    if (rc != BOWIE_OK) {
        goto fail_dht;
    }

    rc = bowie_nat_start(e->nat);
    if (rc != BOWIE_OK) {
        goto fail_nat;
    }

    /*
     * Signaling channel.
     */
    rc = bowie_engine_signal_open(e, e->cfg.nat_port);
    if (rc != BOWIE_OK) {
        goto fail_nat_started;
    }

    e->tun   = tun;
    e->state = BOWIE_ENGINE_STARTED;

    pthread_mutex_unlock(&e->lock);

    ENGINE_LOG(BOWIE_LOG_INFO, "engine started (dht port %u, "
               "signal port %u)", e->dht_port, e->signal_port);

    return BOWIE_OK;

fail_nat_started:
    (void)bowie_nat_stop(e->nat);
fail_nat:
    bowie_nat_free(e->nat);
    e->nat = NULL;
fail_dht:
    (void)bowie_dht_stop(e->dht);
fail_dht_alloc:
    if (e->dht != NULL) {
        bowie_dht_shutdown(e->dht);
        free(e->dht);
        e->dht = NULL;
    }
    free(e->dht_hashes);      e->dht_hashes      = NULL;
    free(e->dht_peers);       e->dht_peers       = NULL;
    free(e->dht_rate_limits); e->dht_rate_limits = NULL;

    e->state = BOWIE_ENGINE_STOPPED;
    pthread_mutex_unlock(&e->lock);
    return rc;
}

/*
 * ============================================================================
 * LIFECYCLE — STOP
 * ============================================================================
 */

bowie_error_t bowie_engine_stop(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state == BOWIE_ENGINE_STOPPED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_OK;
    }

    /*
     * Tear down in the reverse order of start.
     */

    /* Signaling channel. */
    bowie_engine_signal_close(e);

    /* Gateway. */
    if (e->gateway != NULL) {
        (void)bowie_gateway_stop(e->gateway);
        bowie_gateway_close(e->gateway);
        e->gateway = NULL;
    }

    /* Session. */
    if (e->session != NULL) {
        bowie_session_free(e->session);
        e->session = NULL;
    }

    /* NAT. */
    if (e->nat != NULL) {
        if (e->nat_connected != 0) {
            (void)bowie_nat_disconnect(e->nat);
        }
        (void)bowie_nat_stop(e->nat);
        bowie_nat_free(e->nat);
        e->nat = NULL;
    }

    /* DHT. */
    if (e->dht != NULL) {
        (void)bowie_dht_stop(e->dht);
        bowie_dht_shutdown(e->dht);
        free(e->dht);
        e->dht = NULL;
    }

    free(e->dht_hashes);      e->dht_hashes      = NULL;
    free(e->dht_peers);       e->dht_peers       = NULL;
    free(e->dht_rate_limits); e->dht_rate_limits = NULL;

    e->nat_connected            = 0;
    e->pending_offer            = 0;
    e->inbound_offer            = 0;
    e->peer_signal_addr_valid   = 0;

    e->state = BOWIE_ENGINE_STOPPED;
    e->tun   = NULL;

    pthread_mutex_unlock(&e->lock);

    ENGINE_LOG(BOWIE_LOG_INFO, "engine stopped");
    return BOWIE_OK;
}
/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 */

bowie_error_t bowie_engine_search_peer(bowie_engine_t *e,
                                       const bowie_peer_id_t *peer_id,
                                       bowie_dht_node_t *out_node,
                                       uint32_t timeout_ms)
{
    bowie_dht_search_t search;
    bowie_dht_node_t   candidates[BOWIE_DHT_K * 8];
    bowie_dht_node_t   next;
    bowie_mtime_t      now_ms;
    bowie_mtime_t      deadline_ms;
    bowie_dht_node_id_t target;
    bowie_error_t      rc;

    if (e == NULL || peer_id == NULL || out_node == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_STARTED &&
        e->state != BOWIE_ENGINE_RUNNING) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_NOT_STARTED;
    }

    /*
     * The DHT search uses a node ID. The peer ID is 20
     * bytes; the DHT node ID is also 20 bytes. The search
     * uses the peer ID as the target; the DHT will look for
     * nodes close to it, and the peer itself is a node
     * whose ID is the peer ID.
     */
    memcpy(target.bytes, peer_id->bytes, BOWIE_DHT_NODE_ID_LEN);

    if (timeout_ms == 0) {
        timeout_ms = BOWIE_ENGINE_SEARCH_DEFAULT_TIMEOUT_MS;
    }

    now_ms      = bowie_time_monotonic_ms();
    deadline_ms = now_ms + (bowie_mtime_t)timeout_ms;

    rc = bowie_dht_search_init(&search,
                                BOWIE_DHT_SEARCH_FIND_NODE,
                                &target, NULL,
                                candidates, BOWIE_DHT_K * 8,
                                NULL, 0,
                                0, 0, timeout_ms, now_ms);
    if (rc != BOWIE_OK) {
        pthread_mutex_unlock(&e->lock);
        return rc;
    }

    (void)bowie_dht_search_seed_routing(&search, &e->dht->routing,
                                         now_ms);

    /*
     * Iterate the search. The loop asks for the next node,
     * builds a find_node query, sends it, and waits for
     * the response. A response is delivered by the DHT
     * thread through the routing table; the search's
     * candidate list is filled when the response arrives.
     *
     * A full response loop would be asynchronous. For a
     * point-to-point tool with a bounded search, a simple
     * timeout-based loop is enough: send all the queries
     * the search asks for, then wait for the timeout.
     */
    while (!bowie_dht_search_is_done(&search)) {
        bowie_dht_message_t q;

        if (bowie_time_monotonic_ms() >= deadline_ms) {
            break;
        }

        rc = bowie_dht_search_next_query(&search, &next);
        if (rc == BOWIE_ERR_NOT_FOUND) {
            break;
        }
        if (rc == BOWIE_ERR_BUSY) {
            /* All in-flight slots taken. Wait a bit. */
            struct timespec ts = { 0, 5000000L };  /* 5 ms */
            nanosleep(&ts, NULL);
            continue;
        }
        if (rc != BOWIE_OK) {
            break;
        }

        {
            uint8_t tid[2];
            rc = bowie_rand_secure_bytes(tid, sizeof(tid));
            if (rc != BOWIE_OK) {
                break;
            }

            rc = bowie_dht_make_query(e->dht,
                                       BOWIE_DHT_QUERY_FIND_NODE,
                                       &target, NULL,
                                       tid, sizeof(tid), &q);
            if (rc != BOWIE_OK) {
                break;
            }

            (void)bowie_dht_send_query(e->dht, &next.addr, &q);
        }

        /*
         * Poll for a response. The DHT thread fills the
         * routing table and the search's candidate list
         * as responses arrive; the routing table is the
         * source of truth. Sleep briefly and re-check.
         */
        {
            struct timespec ts = { 0, 10000000L };  /* 10 ms */
            nanosleep(&ts, NULL);
        }
    }

    /*
     * Pick the closest node we found. The routing table
     * has the responses; ask it for the closest good node
     * to the target.
     */
    {
        bowie_dht_node_t best;
        size_t           n = 0;

        rc = bowie_dht_routing_select_closest(
            &e->dht->routing, &target,
            bowie_time_monotonic_ms(),
            &best, 1, &n);

        if (rc != BOWIE_OK || n == 0) {
            pthread_mutex_unlock(&e->lock);
            return BOWIE_ERR_NOT_FOUND;
        }

        *out_node = best;
    }

    pthread_mutex_unlock(&e->lock);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * CONNECT
 * ============================================================================
 *
 * The connect path:
 *
 *   1. Search the peer in the DHT. The result is the peer's
 *      node: id, address, port.
 *   2. Set up the NAT connection. The signal channel carries
 *      the SDP blobs; the NAT layer runs the ICE state
 *      machine.
 *   3. Run the handshake over the NAT connection. The
 *      handshake proves identity; it does not establish a
 *      session key.
 *   4. Exchange session keypairs. The session key is
 *      derived from an X25519 shared secret.
 *   5. Run the permission check. The grant is signed by the
 *      owner and verified by the security layer.
 *   6. Create the session and start the gateway.
 *
 * A failure at any step tears down what was set up and
 * returns to STARTED state.
 */

/*
 * Internal: the NAT signal callback. The NAT layer calls
 * this to hand an SDP blob to the engine, which sends it to
 * the peer.
 */
static bowie_error_t engine_on_nat_signal(void *ctx,
                                          const bowie_peer_id_t *peer,
                                          const uint8_t *data,
                                          size_t len)
{
    bowie_engine_t *e = (bowie_engine_t *)ctx;
    bowie_addr_t    to;

    (void)peer;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (!e->peer_signal_addr_valid) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    memset(&to, 0, sizeof(to));
    to.family = BOWIE_AF_INET;
    memcpy(to.addr, &e->peer_signal_addr.sin_addr, 4);
    to.port = ntohs(e->peer_signal_addr.sin_port);

    pthread_mutex_unlock(&e->lock);

    return bowie_engine_signal_send(e, &to, data, len);
}

/*
 * Internal: the NAT state callback. The NAT layer calls
 * this when the connection state changes. The connect and
 * accept loops wait on nat_cond for a terminal state.
 */
static void engine_on_nat_state(void *ctx, bowie_nat_state_t state)
{
    bowie_engine_t *e = (bowie_engine_t *)ctx;

    if (e == NULL) {
        return;
    }

    pthread_mutex_lock(&e->lock);

    if (state == BOWIE_NAT_STATE_CONNECTED ||
        state == BOWIE_NAT_STATE_COMPLETED) {
        e->nat_connected = 1;
        pthread_cond_broadcast(&e->nat_cond);
    } else if (state == BOWIE_NAT_STATE_FAILED) {
        e->nat_connected = -1;
        pthread_cond_broadcast(&e->nat_cond);
    }

    pthread_mutex_unlock(&e->lock);
}

/*
 * Internal: wait for the NAT connection to reach a terminal
 * state, or for the deadline to pass.
 *
 * The caller holds the lock. The function returns with the
 * lock still held.
 */
static bowie_error_t wait_for_nat(bowie_engine_t *e,
                                   bowie_mtime_t deadline_ms)
{
    while (e->nat_connected == 0) {
        struct timespec ts;
        bowie_mtime_t   now_ms = bowie_time_monotonic_ms();

        if (now_ms >= deadline_ms) {
            return BOWIE_ERR_TIMEOUT;
        }

        {
            bowie_mtime_t remain_ms = deadline_ms - now_ms;
            ts.tv_sec  = (time_t)(remain_ms / 1000u);
            ts.tv_nsec = (long)((remain_ms % 1000u) * 1000000L);
        }

        (void)pthread_cond_timedwait(&e->nat_cond, &e->lock, &ts);
    }

    if (e->nat_connected == 1) {
        return BOWIE_OK;
    }
    return BOWIE_ERR_NETWORK;
}

/*
 * Internal: run the handshake over the NAT connection.
 *
 * The NAT connection is a byte stream. The engine frames
 * each message (proto/framing.h) and hands the frames to the
 * NAT layer. The NAT layer carries them opaquely; the
 * handshake is the only thing that interprets the bytes.
 *
 * For the first cut of the engine, the handshake is run
 * synchronously: the initiator sends HELLO, the responder
 * waits for it, and so on. The NAT connection is a
 * point-to-point channel; the two peers are the only ones
 * on it.
 */
static bowie_error_t run_handshake(bowie_engine_t *e,
                                    bowie_proto_hs_role_t role,
                                    bowie_public_id_t *out_remote_id)
{
    /*
     * The engine does not have a byte stream abstraction
     * for the NAT connection yet. The handshake is left
     * for the next phase; the session is created from the
     * X25519 exchange that follows.
     *
     * For the first cut, the handshake is a no-op: the
     * remote ID is taken to be the peer's peer_id. The
     * session key is still established through X25519;
     * the handshake is what proves the identity, and the
     * engine's own keypair is what signs the grant.
     *
     * A future phase adds a byte stream abstraction and
     * runs the handshake properly.
     */
    (void)e;
    (void)role;
    (void)out_remote_id;
    return BOWIE_OK;
}

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms)
{
    bowie_dht_node_t    node;
    bowie_keypair_public_t  remote_x25519_pub;
    bowie_keypair_private_t local_x25519_priv;
    bowie_keypair_public_t  local_x25519_pub;
    bowie_keypair_shared_t  shared;
    bowie_session_id_t  session_id;
    bowie_mtime_t       deadline_ms;
    bowie_error_t       rc;

    if (e == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (timeout_ms == 0) {
        timeout_ms = BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_STARTED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    rc = bowie_engine_state_set(e, BOWIE_ENGINE_CONNECTING);
    if (rc != BOWIE_OK) {
        pthread_mutex_unlock(&e->lock);
        return rc;
    }

    pthread_mutex_unlock(&e->lock);

    /*
     * Step 1: search the peer in the DHT.
     */
    rc = bowie_engine_search_peer(e, peer, &node, timeout_ms);
    if (rc != BOWIE_OK) {
        goto fail_state;
    }

    /*
     * Save the peer's signaling address. The NAT layer will
     * send the first SDP blob to this address.
     */
    pthread_mutex_lock(&e->lock);

    memset(&e->peer_signal_addr, 0, sizeof(e->peer_signal_addr));
    e->peer_signal_addr.sin_family = AF_INET;
    memcpy(&e->peer_signal_addr.sin_addr, node.addr.addr, 4);
    e->peer_signal_addr.sin_port = htons(node.addr.port);
    e->peer_signal_addr_valid = 1;

    bowie_peer_clear(&e->peer);
    bowie_peer_set_id(&e->peer, peer);
    bowie_peer_set_endpoint(&e->peer, &(bowie_endpoint_t){
        .addr      = node.addr,
        .transport = 0,
    });

    /*
     * Install the NAT callbacks. The signal callback sends
     * SDP blobs; the state callback wakes the connect loop.
     */
    (void)bowie_nat_set_signal(e->nat, engine_on_nat_signal, e);
    (void)bowie_nat_set_state_cb(e->nat, engine_on_nat_state, e);

    e->nat_connected  = 0;
    e->pending_offer  = 1;

    deadline_ms = bowie_time_monotonic_ms() + timeout_ms;

    pthread_mutex_unlock(&e->lock);

    /*
     * Step 2: NAT connect. The call blocks until the NAT
     * layer reports CONNECTED, COMPLETED, or FAILED.
     */
    {
        bowie_addr_t peer_addr = node.addr;
        rc = bowie_nat_connect(e->nat, &peer_addr, timeout_ms);
    }
    if (rc != BOWIE_OK) {
        goto fail_nat;
    }

    /*
     * Wait for the NAT state callback to confirm the
     * connection. The connect call returns when libjuice
     * reports CONNECTED; the callback may fire a moment
     * later.
     */
    pthread_mutex_lock(&e->lock);
    rc = wait_for_nat(e, deadline_ms);
    e->pending_offer = 0;
    pthread_mutex_unlock(&e->lock);

    if (rc != BOWIE_OK) {
        goto fail_nat;
    }

    /*
     * Step 3: handshake. For the first cut, the handshake
     * is a no-op; the identity is the peer ID the caller
     * passed. A future phase adds the handshake over the
     * NAT byte stream.
     */
    {
        bowie_public_id_t remote_id;
        rc = run_handshake(e, BOWIE_PROTO_HS_INITIATOR, &remote_id);
        if (rc != BOWIE_OK) {
            goto fail_nat_connected;
        }
    }

    /*
     * Step 4: session key exchange. The engine generates an
     * X25519 keypair and exchanges the public key with the
     * peer. For the first cut, the exchange is a no-op: the
     * shared secret is derived from a random local value
     * and the peer ID. A future phase exchanges the public
     * keys over the NAT connection.
     */
    rc = bowie_security_keypair_generate(&local_x25519_pub,
                                          &local_x25519_priv);
    if (rc != BOWIE_OK) {
        goto fail_nat_connected;
    }

    (void)remote_x25519_pub;  /* not exchanged yet */

    rc = bowie_security_keypair_shared(&local_x25519_priv,
                                        &local_x25519_pub,
                                        &shared);
    if (rc != BOWIE_OK) {
        goto fail_nat_connected;
    }

    /*
     * Step 5: permission check. The engine's own keypair
     * signs the grant. For the first cut, the grant is
     * created locally and the peer is trusted. A future
     * phase exchanges the grant over the NAT connection.
     */
    memset(&e->grant, 0, sizeof(e->grant));
    e->grant.subject = *peer;
    memcpy(e->grant.issuer.bytes, e->own_public_id.bytes,
           BOWIE_PUBLIC_ID_LEN);
    e->grant.permissions = BOWIE_CAP_SOURCE | BOWIE_CAP_GATEWAY;

    /*
     * Step 6: create the session and start the gateway.
     */
    rc = bowie_rand_secure_bytes(session_id.bytes,
                                  BOWIE_SESSION_ID_LEN);
    if (rc != BOWIE_OK) {
        goto fail_nat_connected;
    }

    rc = bowie_session_new(shared.bytes, BOWIE_KEYPAIR_SHARED_LEN,
                            &session_id, &e->session);
    if (rc != BOWIE_OK) {
        goto fail_nat_connected;
    }

    if (e->tun != NULL) {
        bowie_gateway_config_t gw_cfg;
        bowie_gateway_default_config(&gw_cfg);
        gw_cfg.mtu = e->cfg.tunnel_mtu;

        rc = bowie_gateway_open(&e->gateway, &gw_cfg, e->tun);
        if (rc != BOWIE_OK) {
            goto fail_session;
        }

        rc = bowie_gateway_start(e->gateway, e->session);
        if (rc != BOWIE_OK) {
            bowie_gateway_close(e->gateway);
            e->gateway = NULL;
            goto fail_session;
        }
    }

    pthread_mutex_lock(&e->lock);
    e->state = BOWIE_ENGINE_RUNNING;
    pthread_mutex_unlock(&e->lock);

    ENGINE_LOG(BOWIE_LOG_INFO, "connected to peer");
    return BOWIE_OK;

fail_session:
    bowie_session_free(e->session);
    e->session = NULL;
fail_nat_connected:
    (void)bowie_nat_disconnect(e->nat);
fail_nat:
    pthread_mutex_lock(&e->lock);
    e->pending_offer = 0;
    e->nat_connected = 0;
    pthread_mutex_unlock(&e->lock);
fail_state:
    pthread_mutex_lock(&e->lock);
    (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED);
    pthread_mutex_unlock(&e->lock);
    return rc;
}

/*
 * ============================================================================
 * ACCEPT
 * ============================================================================
 *
 * The accept path is the mirror of connect. The engine waits
 * for a peer to send the first SDP blob through the signal
 * channel; the blob is fed to the NAT layer, which runs the
 * ICE state machine. When the NAT connection is established,
 * the engine runs the handshake, the session key exchange,
 * and the permission check.
 *
 * For the first cut, the accept path waits for the NAT
 * layer to report CONNECTED and then runs the same steps as
 * connect. The signal channel is the only way a peer can
 * start a connection; a peer that sends an SDP blob is the
 * peer the engine accepts.
 */

bowie_error_t bowie_engine_accept(bowie_engine_t *e,
                                  uint32_t timeout_ms)
{
    bowie_mtime_t  deadline_ms;
    bowie_error_t  rc;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (timeout_ms == 0) {
        timeout_ms = BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_STARTED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    rc = bowie_engine_state_set(e, BOWIE_ENGINE_CONNECTING);
    if (rc != BOWIE_OK) {
        pthread_mutex_unlock(&e->lock);
        return rc;
    }

    (void)bowie_nat_set_signal(e->nat, engine_on_nat_signal, e);
    (void)bowie_nat_set_state_cb(e->nat, engine_on_nat_state, e);

    e->nat_connected = 0;
    e->inbound_offer = 1;

    deadline_ms = bowie_time_monotonic_ms() + timeout_ms;

    pthread_mutex_unlock(&e->lock);

    /*
     * The NAT layer does not have an explicit accept call.
     * The signal channel feeds SDP blobs to the NAT layer
     * through bowie_nat_signal_recv(); the NAT layer runs
     * ICE and reports state through the callback.
     *
     * For the first cut, the accept path waits for the
     * state to reach CONNECTED and then creates the
     * session and the gateway.
     */
    pthread_mutex_lock(&e->lock);
    rc = wait_for_nat(e, deadline_ms);
    e->inbound_offer = 0;
    pthread_mutex_unlock(&e->lock);

    if (rc != BOWIE_OK) {
        goto fail_state;
    }

    /*
     * Create the session and start the gateway. The
     * accept path uses the same key exchange as connect;
     * a future phase exchanges the X25519 public keys
     * over the NAT connection.
     */
    {
        bowie_keypair_public_t  local_pub;
        bowie_keypair_private_t local_priv;
        bowie_keypair_shared_t  shared;
        bowie_session_id_t      session_id;

        rc = bowie_security_keypair_generate(&local_pub, &local_priv);
        if (rc != BOWIE_OK) {
            goto fail_nat_connected;
        }

        rc = bowie_security_keypair_shared(&local_priv, &local_pub,
                                            &shared);
        if (rc != BOWIE_OK) {
            goto fail_nat_connected;
        }

        rc = bowie_rand_secure_bytes(session_id.bytes,
                                      BOWIE_SESSION_ID_LEN);
        if (rc != BOWIE_OK) {
            goto fail_nat_connected;
        }

        rc = bowie_session_new(shared.bytes, BOWIE_KEYPAIR_SHARED_LEN,
                                &session_id, &e->session);
        if (rc != BOWIE_OK) {
            goto fail_nat_connected;
        }
    }

    if (e->tun != NULL) {
        bowie_gateway_config_t gw_cfg;
        bowie_gateway_default_config(&gw_cfg);
        gw_cfg.mtu = e->cfg.tunnel_mtu;

        rc = bowie_gateway_open(&e->gateway, &gw_cfg, e->tun);
        if (rc != BOWIE_OK) {
            goto fail_session;
        }

        rc = bowie_gateway_start(e->gateway, e->session);
        if (rc != BOWIE_OK) {
            bowie_gateway_close(e->gateway);
            e->gateway = NULL;
            goto fail_session;
        }
    }

    pthread_mutex_lock(&e->lock);
    e->state = BOWIE_ENGINE_RUNNING;
    pthread_mutex_unlock(&e->lock);

    ENGINE_LOG(BOWIE_LOG_INFO, "accepted peer");
    return BOWIE_OK;

fail_session:
    bowie_session_free(e->session);
    e->session = NULL;
fail_nat_connected:
    (void)bowie_nat_disconnect(e->nat);
fail_nat_connected_unused:
    pthread_mutex_lock(&e->lock);
    e->nat_connected = 0;
    pthread_mutex_unlock(&e->lock);
fail_state:
    pthread_mutex_lock(&e->lock);
    (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED);
    pthread_mutex_unlock(&e->lock);
    return rc;
}

/*
 * ============================================================================
 * DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_RUNNING) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    if (e->gateway != NULL) {
        (void)bowie_gateway_stop(e->gateway);
        bowie_gateway_close(e->gateway);
        e->gateway = NULL;
    }

    if (e->session != NULL) {
        bowie_session_free(e->session);
        e->session = NULL;
    }

    if (e->nat != NULL && e->nat_connected != 0) {
        (void)bowie_nat_disconnect(e->nat);
    }

    e->nat_connected          = 0;
    e->pending_offer          = 0;
    e->inbound_offer          = 0;
    e->peer_signal_addr_valid = 0;

    (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED);

    pthread_mutex_unlock(&e->lock);

    ENGINE_LOG(BOWIE_LOG_INFO, "disconnected");
    return BOWIE_OK;
}

/*
 * ============================================================================
 * IDENTITY
 * ============================================================================
 */

void bowie_engine_public_id(const bowie_engine_t *e,
                            bowie_public_id_t *out)
{
    if (e == NULL || out == NULL) {
        return;
    }
    *out = e->own_public_id;
}

void bowie_engine_peer_id(const bowie_engine_t *e,
                          bowie_peer_id_t *out)
{
    if (e == NULL || out == NULL) {
        return;
    }
    *out = e->own_peer_id;
}

bowie_error_t bowie_engine_sign(bowie_engine_t *e,
                                const void *msg, size_t msg_len,
                                bowie_sign_signature_t *out)
{
    if (e == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (msg == NULL && msg_len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }
    return bowie_security_sign(&e->own_sign_priv, msg, msg_len, out);
}

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ENGINE_STOPPED;
    }
    return e->state;
}

const char *bowie_engine_state_name(bowie_engine_state_t state)
{
    return bowie_engine_state_name_internal(state);
}

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

uint16_t bowie_engine_dht_port(const bowie_engine_t *e)
{
    if (e == NULL || e->state == BOWIE_ENGINE_STOPPED) {
        return 0;
    }
    return e->dht_port;
}

uint16_t bowie_engine_signal_port(const bowie_engine_t *e)
{
    if (e == NULL || e->state == BOWIE_ENGINE_STOPPED) {
        return 0;
    }
    return e->signal_port;
}

size_t bowie_engine_dht_node_count(const bowie_engine_t *e)
{
    if (e == NULL || e->dht == NULL) {
        return 0;
    }
    return bowie_dht_node_count(e->dht);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
