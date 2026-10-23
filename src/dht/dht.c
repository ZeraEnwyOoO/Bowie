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
 * BOWIE — DHT ENGINE (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the DHT engine declared in dht/dht.h.
 *
 * The engine owns a background thread. The thread reads
 * packets from a UDP socket, parses them, handles them, and
 * sends responses. The caller drives the engine through the
 * public functions; the thread runs on its own.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation of the routing or storage arrays. The
 *     caller supplies them.
 *   - No search orchestration. The search state machine is
 *     in search.h.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The background thread is a simple loop:
 *
 *   1. poll() on the socket with a timeout
 *   2. recvfrom() if the socket is readable
 *   3. parse the packet into a message
 *   4. call bowie_dht_handle_message()
 *   5. if a response is produced, serialize and send it
 *   6. run the periodic tick
 *   7. check the stop flag
 *
 * The arenas used by the thread are stored in the engine,
 * not as static variables. This allows two DHT engines to
 * run in the same process without sharing buffers.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>                   errno
 *   <poll.h>                    poll, POLLIN
 *   <pthread.h>                 pthread_create, pthread_join
 *   <stdlib.h>                  calloc, free, rand
 *   <string.h>                  memset, memcpy
 *   <sys/socket.h>              socket, bind, recvfrom, sendto
 *   <netinet/in.h>              sockaddr_in, INADDR_ANY
 *   <arpa/inet.h>               htonl, htons, ntohs
 *   <unistd.h>                  close
 *   "bowie/types.h"             types
 *   "bowie/err.h"               errors
 *   "core/internal/time.h"      bowie_time_monotonic_ms
 *   "dht/dht.h"                 declarations
 * ============================================================================
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/rand.h"
#include "core/internal/time.h"
#include "dht/dht.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

#define BOWIE_DHT_PACKET_MAX     1500
#define BOWIE_DHT_POLL_TIMEOUT   100   /* ms */
#define BOWIE_DHT_TICK_INTERVAL  1000  /* ms */

static bowie_error_t send_get_peers(bowie_dht_t *dht,
                                    const bowie_addr_t *peer,
                                    const bowie_dht_info_hash_t *hash)
{
    uint8_t tid[BOWIE_DHT_MSG_TID_MAX];
    bowie_dht_message_t query;
    bowie_error_t rc = bowie_rand_secure_bytes(tid, sizeof(tid));
    if (rc != BOWIE_OK) return rc;
    rc = bowie_dht_make_query(dht, BOWIE_DHT_QUERY_GET_PEERS, NULL,
                              hash, tid, sizeof(tid), &query);
    if (rc != BOWIE_OK) return rc;
    return bowie_dht_send_query(dht, peer, &query);
}

static void send_announce_get_peers(bowie_dht_t *dht,
                                    const bowie_dht_info_hash_t *hash)
{
    for (size_t i = 0u; i < dht->config.bootstrap_count; i++) {
        struct addrinfo hints;
        struct addrinfo *result = NULL;
        char service[6];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        (void)snprintf(service, sizeof(service), "%u",
                       (unsigned)dht->config.bootstrap[i].port);
        if (getaddrinfo(dht->config.bootstrap[i].host, service,
                        &hints, &result) != 0) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)result->ai_addr;
        bowie_addr_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.family = BOWIE_AF_INET;
        memcpy(peer.addr, &sin->sin_addr, 4u);
        peer.port = ntohs(sin->sin_port);
        (void)send_get_peers(dht, &peer, hash);
        freeaddrinfo(result);
    }
}

/* Called under state_lock for responses parsed by the DHT worker. */
static void process_query_response(bowie_dht_t *dht,
                                   const bowie_dht_message_t *response,
                                   const bowie_addr_t *from,
                                   bowie_mtime_t now_ms)
{
    bowie_dht_transaction_t transaction;
    bowie_dht_info_hash_t announce_hash;
    uint16_t announce_port;
    int matched = 0;

    memset(&transaction, 0, sizeof(transaction));
    pthread_mutex_lock(&dht->transaction_lock);
    for (size_t i = 0u; i < BOWIE_DHT_TRANSACTION_CAP; i++) {
        bowie_dht_transaction_t *entry = &dht->transactions[i];
        if (entry->used && entry->tid_len == response->tid_len &&
            memcmp(entry->tid, response->tid, response->tid_len) == 0) {
            transaction = *entry;
            entry->used = 0;
            matched = 1;
            break;
        }
    }
    announce_hash = dht->announce_hash;
    announce_port = dht->announce_port;
    pthread_mutex_unlock(&dht->transaction_lock);

    if (!matched || transaction.query_type != BOWIE_DHT_QUERY_GET_PEERS) return;

    for (size_t i = 0u; i < response->peers_count; i++) {
        bowie_dht_peer_entry_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.addr = response->peers[i].addr;
        peer.last_seen_ms = now_ms;
        peer.expires_at_ms = now_ms +
            (bowie_mtime_t)dht->config.peer_lifetime_s * 1000u;
        (void)bowie_dht_storage_add_peer(&dht->storage,
                                          &transaction.info_hash, &peer);
    }

    /* Publish our signal endpoint to any DHT node that returns a token. */
    if (announce_port != 0u && !bowie_dht_token_is_zero(&response->token)) {
        uint8_t tid[BOWIE_DHT_MSG_TID_MAX];
        bowie_dht_message_t announce;
        if (bowie_rand_secure_bytes(tid, sizeof(tid)) == BOWIE_OK &&
            bowie_dht_make_query(dht, BOWIE_DHT_QUERY_ANNOUNCE_PEER,
                                 NULL, &announce_hash, tid, sizeof(tid),
                                 &announce) == BOWIE_OK) {
            announce.port = announce_port;
            announce.token = response->token;
            (void)bowie_dht_send_query(dht, from, &announce);
        }
    }
}

/*
 * ============================================================================
 * INTERNAL — THREAD
 * ============================================================================
 */

static void *dht_thread_main(void *arg)
{
    bowie_dht_t *dht = (bowie_dht_t *)arg;
    uint8_t      buf[BOWIE_DHT_PACKET_MAX];
    bowie_mtime_t last_tick_ms = 0;
    struct pollfd pfd;

    pfd.fd     = dht->socket_fd;
    pfd.events = POLLIN;

    while (!dht->stop_requested) {
        int rc;

        rc = poll(&pfd, 1, BOWIE_DHT_POLL_TIMEOUT);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (rc > 0 && (pfd.revents & POLLIN)) {
            struct sockaddr_storage from;
            socklen_t from_len = sizeof(from);
            ssize_t   n;
            bowie_addr_t from_addr;
            bowie_span_t input;
            bowie_dht_message_t msg;
            bowie_dht_message_t response;
            int has_response = 0;

            n = recvfrom(dht->socket_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &from_len);

            if (n <= 0) {
                continue;
            }

            /* Reset the arenas for the new packet. */
            dht->benc_arena.values_used  = 0;
            dht->benc_arena.entries_used = 0;
            dht->benc_arena.lenient_used = 0;
            dht->msg_arena.nodes_used    = 0;
            dht->msg_arena.peers_used    = 0;

            memset(&msg, 0, sizeof(msg));
            memset(&response, 0, sizeof(response));

            input.data = buf;
            input.len  = (size_t)n;

            memset(&from_addr, 0, sizeof(from_addr));

            if (from.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&from;
                memcpy(from_addr.addr, &sin->sin_addr, 4);
                from_addr.port   = ntohs(sin->sin_port);
                from_addr.family = BOWIE_AF_INET;
            } else if (from.ss_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&from;
                memcpy(from_addr.addr, &sin6->sin6_addr, 16);
                from_addr.port   = ntohs(sin6->sin6_port);
                from_addr.family = BOWIE_AF_INET6;
            } else {
                continue;
            }

            rc = bowie_dht_message_parse(input, &dht->benc_arena,
                                          &dht->msg_arena, &msg);

            if (rc != BOWIE_OK) {
                continue;
            }

            pthread_mutex_lock(&dht->state_lock);
            rc = bowie_dht_handle_message(dht, &msg, &from_addr,
                                           bowie_time_monotonic_ms(),
                                           &dht->msg_arena,
                                           &response,
                                           &has_response);
            if (rc == BOWIE_OK && msg.type == BOWIE_DHT_MSG_RESPONSE) {
                process_query_response(dht, &msg, &from_addr,
                                       bowie_time_monotonic_ms());
            }
            pthread_mutex_unlock(&dht->state_lock);

            if (rc == BOWIE_OK && has_response) {
                bowie_bencode_writer_t writer;
                uint8_t out[BOWIE_DHT_PACKET_MAX];

                bowie_bencode_writer_init(&writer, out, sizeof(out));

                rc = bowie_dht_message_serialize(&response, &writer);

                if (rc == BOWIE_OK) {
                    int address_family = from_addr.family == BOWIE_AF_INET6
                        ? AF_INET6 : AF_INET;
                    size_t address_length = address_family == AF_INET6 ? 16u : 4u;
                    if (dht->config.prepare_underlay_address != NULL &&
                        !dht->config.prepare_underlay_address(
                            dht->config.underlay_context, address_family,
                            from_addr.addr, address_length))
                        continue;
                    sendto(dht->socket_fd, out, writer.pos, 0,
                           (struct sockaddr *)&from, from_len);
                }
            }
        }

        /* Periodic tick. */
        {
            bowie_mtime_t now_ms = bowie_time_monotonic_ms();

            if (now_ms - last_tick_ms >= BOWIE_DHT_TICK_INTERVAL) {
                pthread_mutex_lock(&dht->state_lock);
                bowie_dht_tick(dht, now_ms, NULL, NULL);
                pthread_mutex_unlock(&dht->state_lock);
                last_tick_ms = now_ms;
            }

            bowie_dht_info_hash_t announce_hash;
            int refresh_announce = 0;
            pthread_mutex_lock(&dht->transaction_lock);
            bowie_mtime_t refresh_ms =
                (bowie_mtime_t)dht->config.peer_lifetime_s * 500u;
            if (dht->announce_port != 0u && refresh_ms != 0u &&
                now_ms - dht->last_announce_ms >= refresh_ms) {
                announce_hash = dht->announce_hash;
                dht->last_announce_ms = now_ms;
                refresh_announce = 1;
            }
            pthread_mutex_unlock(&dht->transaction_lock);
            if (refresh_announce) send_announce_get_peers(dht, &announce_hash);
        }
    }

    return NULL;
}

/*
 * ============================================================================
 * LIFECYCLE
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
    bowie_error_t rc;

    if (dht == NULL || config == NULL || local_id == NULL ||
        hashes == NULL || peers == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (config->store_metadata && metadata == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (config->sec_level == BOWIE_DHT_SEC_STRICT &&
        rate_limits == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(dht, 0, sizeof(*dht));

    /* Normalize the config. */
    dht->config = *config;
    rc = bowie_dht_config_normalize(&dht->config);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /* Validate the config. */
    rc = bowie_dht_config_validate(&dht->config);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /* Copy the local ID. */
    dht->local_id = *local_id;

    /* Initialize the routing table. */
    bowie_dht_routing_init(&dht->routing, &dht->local_id);

    /* Initialize the storage. */
    {
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
    }

    /* Initialize the token state. */
    {
        bowie_mtime_t rotate_ms =
            (bowie_mtime_t)dht->config.token_rotate_s * 1000;

        rc = bowie_dht_token_state_init(&dht->token_state,
                                         rotate_ms, now_ms);
        if (rc != BOWIE_OK) {
            return rc;
        }
    }

    /* Initialize the security state. */
    {
        rc = bowie_dht_security_init(&dht->security,
                                      dht->config.sec_level,
                                      rate_limits, rate_limits_cap,
                                      dht->config.max_requests_per_window,
                                      0);
        if (rc != BOWIE_OK) {
            return rc;
        }
    }

    if (pthread_mutex_init(&dht->state_lock, NULL) != 0) {
        return BOWIE_ERR_INTERNAL;
    }
    dht->state_lock_ready = 1;
    if (pthread_mutex_init(&dht->transaction_lock, NULL) != 0) {
        pthread_mutex_destroy(&dht->state_lock);
        dht->state_lock_ready = 0;
        return BOWIE_ERR_INTERNAL;
    }
    dht->transaction_lock_ready = 1;

    dht->last_refresh_ms = now_ms;
    dht->initialized     = 1;
    dht->socket_fd       = -1;
    dht->running         = 0;
    dht->stop_requested  = 0;

    /* Set up the arenas (they are stored in the engine). */
    dht->benc_arena.values      = dht->benc_values;
    dht->benc_arena.values_cap  = 512;
    dht->benc_arena.entries     = dht->benc_entries;
    dht->benc_arena.entries_cap = 256;

    dht->msg_arena.nodes     = dht->msg_nodes;
    dht->msg_arena.nodes_cap = 64;
    dht->msg_arena.peers     = dht->msg_peers;
    dht->msg_arena.peers_cap = 64;

    return BOWIE_OK;
}

bowie_error_t bowie_dht_start(bowie_dht_t *dht, uint16_t port)
{
    struct sockaddr_in addr;

    if (dht == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!dht->initialized) {
        return BOWIE_ERR_INVAL;
    }

    if (dht->running) {
        return BOWIE_ERR_STATE;
    }

    /* Create the UDP socket. */
    dht->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (dht->socket_fd < 0) {
        return BOWIE_ERR_NETWORK;
    }

    /* Bind the socket. */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    if (bind(dht->socket_fd, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
        close(dht->socket_fd);
        dht->socket_fd = -1;
        return BOWIE_ERR_NETWORK;
    }

    dht->stop_requested = 0;

    /* Start the thread. */
    if (pthread_create(&dht->thread, NULL, dht_thread_main, dht) != 0) {
        close(dht->socket_fd);
        dht->socket_fd = -1;
        return BOWIE_ERR_INTERNAL;
    }

    dht->running = 1;

    /* Seed the routing table by pinging configured bootstrap nodes. */
    for (size_t i = 0u; i < dht->config.bootstrap_count; i++) {
        struct addrinfo hints;
        struct addrinfo *result = NULL;
        char service[6];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        (void)snprintf(service, sizeof(service), "%u",
                       (unsigned)dht->config.bootstrap[i].port);
        if (getaddrinfo(dht->config.bootstrap[i].host, service,
                        &hints, &result) == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)result->ai_addr;
            bowie_addr_t peer;
            uint8_t tid[BOWIE_DHT_MSG_TID_MAX];
            bowie_dht_message_t ping;
            memset(&peer, 0, sizeof(peer));
            peer.family = BOWIE_AF_INET;
            memcpy(peer.addr, &sin->sin_addr, 4u);
            peer.port = ntohs(sin->sin_port);
            if (bowie_rand_secure_bytes(tid, sizeof(tid)) == BOWIE_OK &&
                bowie_dht_make_query(dht, BOWIE_DHT_QUERY_PING,
                                     NULL, NULL, tid, sizeof(tid),
                                     &ping) == BOWIE_OK) {
                (void)bowie_dht_send_query(dht, &peer, &ping);
            }
            freeaddrinfo(result);
        }
    }

    return BOWIE_OK;
}

bowie_error_t bowie_dht_set_announce(bowie_dht_t *dht,
                                     const bowie_dht_info_hash_t *info_hash,
                                     uint16_t signal_port)
{
    if (dht == NULL || info_hash == NULL) return BOWIE_ERR_NULL_ARG;
    if (signal_port == 0u) return BOWIE_ERR_INVAL;
    if (!dht->running) return BOWIE_ERR_NOT_STARTED;

    pthread_mutex_lock(&dht->transaction_lock);
    dht->announce_hash = *info_hash;
    dht->announce_port = signal_port;
    dht->last_announce_ms = bowie_time_monotonic_ms();
    pthread_mutex_unlock(&dht->transaction_lock);

    /* Ask each configured bootstrap node for a token; its response triggers
     * a token-authenticated announce_peer from the DHT receive thread. */
    send_announce_get_peers(dht, info_hash);
    return BOWIE_OK;
}

bowie_error_t bowie_dht_stop(bowie_dht_t *dht)
{
    if (dht == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!dht->running) {
        return BOWIE_ERR_NOT_STARTED;
    }

    dht->stop_requested = 1;

    pthread_join(dht->thread, NULL);

    if (dht->socket_fd >= 0) {
        close(dht->socket_fd);
        dht->socket_fd = -1;
    }

    dht->running = 0;

    return BOWIE_OK;
}

void bowie_dht_shutdown(bowie_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }

    if (dht->running) {
        (void)bowie_dht_stop(dht);
    }

    if (dht->state_lock_ready) {
        pthread_mutex_destroy(&dht->state_lock);
    }
    if (dht->transaction_lock_ready) {
        pthread_mutex_destroy(&dht->transaction_lock);
    }
    memset(dht, 0, sizeof(*dht));
    dht->socket_fd = -1;
}

void bowie_dht_clear(bowie_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }

    bowie_dht_routing_clear(&dht->routing);
    bowie_dht_storage_clear(&dht->storage);
    bowie_dht_sec_rate_clear(&dht->security);
}

/*
 * ============================================================================
 * QUERY
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

    if (tid_len > BOWIE_DHT_MSG_TID_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    memset(out, 0, sizeof(*out));

    out->type       = BOWIE_DHT_MSG_QUERY;
    out->query_type = type;
    out->sender_id  = dht->local_id;

    if (tid != NULL && tid_len > 0) {
        memcpy(out->tid, tid, tid_len);
        out->tid_len = tid_len;
    }

    switch (type) {
    case BOWIE_DHT_QUERY_PING:
        break;

    case BOWIE_DHT_QUERY_FIND_NODE:
        if (target == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->target = *target;
        break;

    case BOWIE_DHT_QUERY_GET_PEERS:
        if (info_hash == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->info_hash = *info_hash;
        break;

    case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
        if (info_hash == NULL) {
            return BOWIE_ERR_NULL_ARG;
        }
        out->info_hash = *info_hash;
        break;

    default:
        return BOWIE_ERR_INVAL;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * MESSAGE HANDLING
 * ============================================================================
 */

bowie_error_t bowie_dht_handle_message(
    bowie_dht_t                *dht,
    const bowie_dht_message_t  *msg,
    const bowie_addr_t         *from,
    bowie_mtime_t               now_ms,
    bowie_dht_message_arena_t  *arena,
    bowie_dht_message_t        *out_response,
    int                        *out_has_response)
{
    if (dht == NULL || msg == NULL || from == NULL ||
        arena == NULL || out_response == NULL ||
        out_has_response == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!dht->initialized) {
        return BOWIE_ERR_INVAL;
    }

    *out_has_response = 0;

    switch (msg->type) {
    case BOWIE_DHT_MSG_QUERY:
        /* Check the node ID. */
        if (!bowie_dht_sec_node_id_ok(&dht->security,
                                       &msg->sender_id, from)) {
            memset(out_response, 0, sizeof(*out_response));
            out_response->type       = BOWIE_DHT_MSG_ERROR;
            out_response->error_code = 203;
            *out_has_response = 1;
            return BOWIE_OK;
        }

        /* Rate limit. */
        if (bowie_dht_sec_check_rate(&dht->security, from,
                                      now_ms) != BOWIE_OK) {
            memset(out_response, 0, sizeof(*out_response));
            out_response->type       = BOWIE_DHT_MSG_ERROR;
            out_response->error_code = 202;
            *out_has_response = 1;
            return BOWIE_OK;
        }

        /* Update the routing table. */
        {
            bowie_dht_node_t node;
            memset(&node, 0, sizeof(node));
            node.id           = msg->sender_id;
            node.addr         = *from;
            node.last_seen_ms = now_ms;
            bowie_dht_routing_add(&dht->routing, &node, now_ms);
        }

        /* Handle the query type. */
        switch (msg->query_type) {
        case BOWIE_DHT_QUERY_PING:
            memset(out_response, 0, sizeof(*out_response));
            out_response->type      = BOWIE_DHT_MSG_RESPONSE;
            out_response->sender_id = dht->local_id;
            memcpy(out_response->tid, msg->tid, msg->tid_len);
            out_response->tid_len = msg->tid_len;
            *out_has_response = 1;
            break;

        case BOWIE_DHT_QUERY_FIND_NODE:
            memset(out_response, 0, sizeof(*out_response));
            out_response->type      = BOWIE_DHT_MSG_RESPONSE;
            out_response->sender_id = dht->local_id;
            memcpy(out_response->tid, msg->tid, msg->tid_len);
            out_response->tid_len = msg->tid_len;
            out_response->nodes       = arena->nodes;
            out_response->nodes_count = 0;

            {
                bowie_dht_node_t closest[8];
                size_t count = 0;
                size_t i;

                bowie_dht_routing_select_closest(
                    &dht->routing, &msg->target, now_ms,
                    closest, 8, &count);

                for (i = 0; i < count && i < 8; i++) {
                    arena->nodes[i].id   = closest[i].id;
                    arena->nodes[i].addr = closest[i].addr;
                }
                out_response->nodes_count = count;
            }

            *out_has_response = 1;
            break;

        case BOWIE_DHT_QUERY_GET_PEERS:
            memset(out_response, 0, sizeof(*out_response));
            out_response->type      = BOWIE_DHT_MSG_RESPONSE;
            out_response->sender_id = dht->local_id;
            memcpy(out_response->tid, msg->tid, msg->tid_len);
            out_response->tid_len = msg->tid_len;

            /* Generate a token. */
            bowie_dht_token_generate(&dht->token_state, from,
                                      &out_response->token);

            /* Find peers. */
            {
                bowie_dht_peer_entry_t found[16];
                size_t count = 0;
                size_t i;

                bowie_dht_storage_find_peers(
                    &dht->storage, &msg->info_hash,
                    found, NULL, 16, &count);

                out_response->peers       = arena->peers;
                out_response->peers_count = 0;

                for (i = 0; i < count && i < 16; i++) {
                    arena->peers[i].addr = found[i].addr;
                }
                out_response->peers_count = count;
            }

            *out_has_response = 1;
            break;

        case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
            /* Validate the token. */
            if (!bowie_dht_token_validate(&dht->token_state, from,
                                           &msg->token)) {
                memset(out_response, 0, sizeof(*out_response));
                out_response->type       = BOWIE_DHT_MSG_ERROR;
                out_response->error_code = 203;
                *out_has_response = 1;
                break;
            }

            /* Store the peer. */
            {
                bowie_dht_peer_entry_t peer;
                memset(&peer, 0, sizeof(peer));
                peer.addr          = *from;
                if (msg->implied_port) {
                    peer.addr.port = from->port;
                } else if (msg->port != 0u) {
                    peer.addr.port = msg->port;
                } else {
                    memset(out_response, 0, sizeof(*out_response));
                    out_response->type = BOWIE_DHT_MSG_ERROR;
                    out_response->error_code = 203;
                    *out_has_response = 1;
                    break;
                }
                peer.capabilities  = 0;
                peer.last_seen_ms  = now_ms;
                peer.expires_at_ms = now_ms +
                    (bowie_mtime_t)dht->config.peer_lifetime_s * 1000;

                bowie_dht_storage_add_peer(&dht->storage,
                                            &msg->info_hash, &peer);
            }

            memset(out_response, 0, sizeof(*out_response));
            out_response->type      = BOWIE_DHT_MSG_RESPONSE;
            out_response->sender_id = dht->local_id;
            memcpy(out_response->tid, msg->tid, msg->tid_len);
            out_response->tid_len = msg->tid_len;
            *out_has_response = 1;
            break;

        default:
            break;
        }
        break;

    case BOWIE_DHT_MSG_RESPONSE:
        /* Update the routing table. */
        {
            bowie_dht_node_t node;
            memset(&node, 0, sizeof(node));
            node.id           = msg->sender_id;
            node.addr         = *from;
            node.last_seen_ms = now_ms;
            bowie_dht_routing_add(&dht->routing, &node, now_ms);

            /* Store the token if present. */
            if (!bowie_dht_token_is_zero(&msg->token)) {
                bowie_dht_routing_set_token(&dht->routing,
                                             &msg->sender_id,
                                             &msg->token);
            }

            /* A find_node response is also a routing-table seed. */
            for (size_t i = 0u; i < msg->nodes_count; i++) {
                uint8_t compact[BOWIE_DHT_COMPACT_NODE_LEN];
                size_t compact_len = 0u;
                bowie_span_t encoded;
                bowie_dht_node_t advertised;
                if (bowie_dht_compact_nodes_encode(&msg->nodes[i], 1u,
                        compact, sizeof(compact), &compact_len) != BOWIE_OK)
                    continue;
                encoded.data = compact;
                encoded.len = compact_len;
                if (bowie_dht_node_from_compact(encoded, &advertised) != BOWIE_OK)
                    continue;
                advertised.last_seen_ms = now_ms;
                (void)bowie_dht_routing_add(&dht->routing, &advertised, now_ms);
            }
        }
        break;

    case BOWIE_DHT_MSG_ERROR:
        /* Ignore. */
        break;

    default:
        break;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * MAINTENANCE
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

    /* Rotate the token secret. */
    if (bowie_dht_token_should_rotate(&dht->token_state, now_ms)) {
        bowie_dht_token_rotate(&dht->token_state, now_ms);
    }

    /* Expire the stale peers. */
    bowie_dht_storage_expire(&dht->storage, now_ms);

    /* Build a refresh query if it is time. */
    {
        bowie_mtime_t interval_ms =
            (bowie_mtime_t)dht->config.refresh_interval_s * 1000;

        if (now_ms - dht->last_refresh_ms >= interval_ms) {
            dht->last_refresh_ms = now_ms;

            if (out_refresh != NULL && out_has_refresh != NULL) {
                int idx = bowie_dht_routing_stalest_bucket(&dht->routing);

                if (idx >= 0) {
                    bowie_dht_node_id_t target;
                    size_t i;

                    for (i = 0; i < BOWIE_DHT_NODE_ID_LEN; i++) {
                        target.bytes[i] = (uint8_t)(rand() & 0xFF);
                    }

                    bowie_dht_make_query(dht, BOWIE_DHT_QUERY_FIND_NODE,
                                          &target, NULL, NULL, 0,
                                          out_refresh);
                    *out_has_refresh = 1;
                }
            }
        }
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * QUERY
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
        return 0;
    }

    return bowie_dht_routing_node_count(&dht->routing);
}

size_t bowie_dht_hash_count(const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return 0;
    }

    return bowie_dht_storage_hash_count(&dht->storage);
}

size_t bowie_dht_peer_count(const bowie_dht_t *dht)
{
    if (dht == NULL) {
        return 0;
    }

    return bowie_dht_storage_peer_count(&dht->storage);
}


bowie_error_t bowie_dht_send_query(
    bowie_dht_t               *dht,
    const bowie_addr_t        *to,
    const bowie_dht_message_t *msg)
{
    uint8_t                buf[BOWIE_DHT_PACKET_MAX];
    bowie_bencode_writer_t writer;
    struct sockaddr_in     sin;
    bowie_error_t          rc;
    ssize_t                sent;

    if (dht == NULL || to == NULL || msg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!dht->running || dht->socket_fd < 0) {
        return BOWIE_ERR_STATE;
    }
    if (to->family != BOWIE_AF_INET) {
        return BOWIE_ERR_INVAL;
    }
    if (dht->config.prepare_underlay_address != NULL &&
        !dht->config.prepare_underlay_address(dht->config.underlay_context,
                                               AF_INET, to->addr, 4u))
        return BOWIE_ERR_NETWORK;

    bowie_bencode_writer_init(&writer, buf, sizeof(buf));

    rc = bowie_dht_message_serialize(msg, &writer);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (writer.pos == 0u) {
        return BOWIE_ERR_INTERNAL;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, to->addr, 4);
    sin.sin_port = htons(to->port);

    size_t transaction_slot = BOWIE_DHT_TRANSACTION_CAP;
    if (msg->query_type == BOWIE_DHT_QUERY_GET_PEERS && msg->tid_len > 0u) {
        pthread_mutex_lock(&dht->transaction_lock);
        transaction_slot = dht->transaction_next++ % BOWIE_DHT_TRANSACTION_CAP;
        bowie_dht_transaction_t *entry = &dht->transactions[transaction_slot];
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->tid, msg->tid, msg->tid_len);
        entry->tid_len = msg->tid_len;
        entry->query_type = msg->query_type;
        entry->info_hash = msg->info_hash;
        entry->used = 1;
        pthread_mutex_unlock(&dht->transaction_lock);
    }

    sent = sendto(dht->socket_fd, buf, writer.pos, 0,
                  (struct sockaddr *)&sin, sizeof(sin));

    if (sent < 0) {
        if (transaction_slot < BOWIE_DHT_TRANSACTION_CAP) {
            pthread_mutex_lock(&dht->transaction_lock);
            dht->transactions[transaction_slot].used = 0;
            pthread_mutex_unlock(&dht->transaction_lock);
        }
        return BOWIE_ERR_NETWORK;
    }
    if ((size_t)sent != writer.pos) {
        if (transaction_slot < BOWIE_DHT_TRANSACTION_CAP) {
            pthread_mutex_lock(&dht->transaction_lock);
            dht->transactions[transaction_slot].used = 0;
            pthread_mutex_unlock(&dht->transaction_lock);
        }
        return BOWIE_ERR_NETWORK;
    }

    return BOWIE_OK;
}
/*
 * ============================================================================
 * END OF DHT ENGINE IMPLEMENTATION
 * ============================================================================
 */
