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
 * BOWIE — ENGINE INTERNAL STATE
 * ============================================================================
 *
 * The private layout of struct bowie_engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed. Only src/engine.c
 * includes it.
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_ENGINE_H
#define BOWIE_ENGINE_INTERNAL_ENGINE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "dht/dht.h"
#include "nat/nat.h"
#include "tunnel/tun_linux.h"
#include "gateway/gateway.h"
#include "security/sign.h"
#include "security/session.h"
#include "security/revoke.h"
#include "security/quota.h"
#include "net/peer.h"
#include "engine/internal/event.h" /* For bowie_engine_event_queue_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

#define BOWIE_ENGINE_DHT_HASHES_CAP       256u
#define BOWIE_ENGINE_DHT_PEERS_CAP       4096u
#define BOWIE_ENGINE_DHT_RATE_LIMIT_CAP    64u

#define BOWIE_ENGINE_SIGNAL_BUF_MAX \
    (BOWIE_PROTO_FRAME_HEADER_LEN + BOWIE_PROTO_MAX_PAYLOAD)

#define BOWIE_ENGINE_SIGNAL_POLL_MS 200u

#define BOWIE_ENGINE_SEARCH_DEFAULT_TIMEOUT_MS 15000u
#define BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS 30000u

/*
 * ============================================================================
 * ENGINE STRUCT
 * ============================================================================
 */

struct bowie_engine {
    /*
     * ----------------------------------------------------------------
     * Synchronization
     * ----------------------------------------------------------------
     */
    pthread_mutex_t     lock;
    pthread_cond_t      nat_cond;

    /*
     * ----------------------------------------------------------------
     * State and configuration
     * ----------------------------------------------------------------
     */
    bowie_engine_state_t state;
    bowie_engine_config_t cfg;

    /*
     * ----------------------------------------------------------------
     * Identity
     * ----------------------------------------------------------------
     */
    bowie_sign_private_t own_sign_priv;
    bowie_sign_public_t  own_sign_pub;
    bowie_public_id_t    own_public_id;
    bowie_peer_id_t      own_peer_id;
    bowie_dht_node_id_t  own_dht_id;

    /*
     * ----------------------------------------------------------------
     * DHT
     * ----------------------------------------------------------------
     */
    bowie_dht_t                  *dht;
    bowie_dht_hash_entry_t       *dht_hashes;
    bowie_dht_peer_entry_t       *dht_peers;
    bowie_dht_peer_metadata_t    *dht_metadata;      /* may be NULL */
    bowie_dht_rate_limit_t       *dht_rate_limits;   /* may be NULL */
    uint16_t                      dht_port;          /* actual port */

    /*
     * ----------------------------------------------------------------
     * NAT
     * ----------------------------------------------------------------
     */
    bowie_nat_t *nat;
    int          nat_connected; /* 0=pending, 1=ok, -1=fail */

    /*
     * ----------------------------------------------------------------
     * Tunnel (borrowed)
     * ----------------------------------------------------------------
     */
    bowie_tun_t *tun;

    /*
     * ----------------------------------------------------------------
     * Gateway
     * ----------------------------------------------------------------
     */
    bowie_gateway_t *gateway;

    /*
     * ----------------------------------------------------------------
     * Security
     * ----------------------------------------------------------------
     */
    bowie_revoke_list_t revoke_list;
    bowie_quota_t       quota;

    /*
     * ----------------------------------------------------------------
     * Current connection
     * ----------------------------------------------------------------
     */
    bowie_peer_t    peer;
    bowie_session_t *session;
    bowie_grant_t   grant;

    /*
     * ----------------------------------------------------------------
     * Signaling channel
     * ----------------------------------------------------------------
     */
    int              signal_fd;
    uint16_t         signal_port;
    pthread_t        signal_thread;
    int              signal_running;
    int              signal_stop;

    struct sockaddr_in peer_signal_addr;
    int                peer_signal_addr_valid;

    /*
     * ----------------------------------------------------------------
     * Connection flags
     * ----------------------------------------------------------------
     */
    int pending_offer;
    int inbound_offer;
    bowie_peer_id_t inbound_peer_id;

    /*
     * ----------------------------------------------------------------
     * Events
     * ----------------------------------------------------------------
     * (Must be here so engine.c can access it)
     */
    bowie_engine_event_queue_t events;
};

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_ENGINE_H */
