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
 * BOWIE — ENGINE
 * ============================================================================
 *
 * The engine ties every layer together.
 *
 * The engine owns the DHT, the NAT layer, the tunnel, the
 * security layer, the gateway, and the quota. It starts them
 * in the right order, stops them in the reverse order, and
 * routes calls between them.
 *
 * A caller uses the engine through this header. The engine
 * itself is opaque; the caller never sees its layout.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No DHT. The engine starts the DHT; the DHT module does
 *     the work.
 *   - No NAT. The engine starts the NAT layer; the NAT module
 *     does the work.
 *   - No tunnel. The engine opens the tunnel; the tunnel
 *     module does the work.
 *   - No security. The engine creates the session; the
 *     security module does the work.
 *   - No gateway. The engine starts the gateway; the gateway
 *     module does the work.
 *   - No quota. The engine holds the quota; the quota module
 *     does the work.
 *   - No UI. The engine has no command line, no menu, and no
 *     output. A caller that wants a UI builds it on top.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine has three states: stopped, started, and running.
 * A stopped engine has no resources. A started engine has its
 * DHT and NAT layer ready. A running engine has at least one
 * active session.
 *
 * The engine is not thread-safe. A caller that shares an
 * engine between threads must serialize every call. The
 * engine runs its own internal threads for the gateway and
 * the DHT; those threads do not call back into the public API.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_engine_t, bowie_peer_id_t,
 *                           bowie_addr_t, bowie_tun_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_ENGINE_H
#define BOWIE_ENGINE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 */

typedef struct bowie_engine_config {
    uint16_t    dht_port;
    uint16_t    nat_port;
    int         allow_server;

    const char *stun_host;
    uint16_t    stun_port;

    const char *turn_host;
    uint16_t    turn_port;
    const char *turn_user;
    const char *turn_pass;

    uint32_t    tunnel_mtu;
} bowie_engine_config_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_engine_default_config(bowie_engine_config_t *cfg);

bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out);

void bowie_engine_free(bowie_engine_t *e);

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun);

bowie_error_t bowie_engine_stop(bowie_engine_t *e);

/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 */

/*
 * Search for a peer by ID using the DHT.
 *
 * The function runs the full DHT search workflow: it seeds
 * the search from the routing table, sends queries, collects
 * responses, and returns when the search is done or fails.
 *
 * The result is the closest node found. The caller uses the
 * node's address to connect.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or peer_id or out_node is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_NOT_FOUND if no node is found.
 * Returns BOWIE_ERR_TIMEOUT if the search times out.
 */
bowie_error_t bowie_engine_search_peer(bowie_engine_t *e,
                                       const bowie_peer_id_t *peer_id,
                                       bowie_dht_node_t *out_node,
                                       uint32_t timeout_ms);

/*
 * ============================================================================
 * CONNECT / DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

typedef enum bowie_engine_state {
    BOWIE_ENGINE_STOPPED = 0,
    BOWIE_ENGINE_STARTED = 1,
    BOWIE_ENGINE_RUNNING = 2
} bowie_engine_state_t;

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

const char *bowie_engine_state_name(bowie_engine_state_t state);

/*
 * ============================================================================
 * END OF ENGINE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_ENGINE_H */
