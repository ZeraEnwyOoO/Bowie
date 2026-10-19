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

#ifndef BOWIE_ENGINE_ENGINE_H
#define BOWIE_ENGINE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "bowie/config.h"     /* For bowie_config_t */
#include "dht/node.h"         /* For bowie_dht_node_t */
#include "security/sign.h"    /* For bowie_sign_signature_t */

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
 * HOOKS
 * ============================================================================
 *
 * Install the hook set (Log, Event, Storage).
 *
 * The engine copies the hook set. The caller may free the set
 * after the call returns. The hook set must be installed before
 * bowie_engine_start().
 */
bowie_error_t bowie_engine_set_hooks(bowie_engine_t *e,
                                     const bowie_hooks_t *hooks);

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

bowie_error_t bowie_engine_search_peer(bowie_engine_t *e,
                                       const bowie_peer_id_t *peer_id,
                                       bowie_dht_node_t *out_node,
                                       uint32_t timeout_ms);

/*
 * ============================================================================
 * CONNECT / ACCEPT / DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);

bowie_error_t bowie_engine_accept(bowie_engine_t *e,
                                  uint32_t timeout_ms);

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);

/*
 * ============================================================================
 * BOOTSTRAP
 * ============================================================================
 *
 * Add a DHT bootstrap node. The host is a string (e.g., "1.2.3.4")
 * and the port is the DHT port (e.g., 6881). The engine copies
 * the host string.
 */
bowie_error_t bowie_engine_add_bootstrap(bowie_engine_t *e,
                                         const char *host,
                                         uint16_t port);

/*
 * ============================================================================
 * IDENTITY
 * ============================================================================
 */

void bowie_engine_public_id(const bowie_engine_t *e,
                            bowie_public_id_t *out);

void bowie_engine_peer_id(const bowie_engine_t *e,
                          bowie_peer_id_t *out);

bowie_error_t bowie_engine_sign(bowie_engine_t *e,
                                const void *msg, size_t msg_len,
                                bowie_sign_signature_t *out);

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

typedef enum bowie_engine_state {
    BOWIE_ENGINE_STOPPED    = 0,
    BOWIE_ENGINE_STARTED    = 1,
    BOWIE_ENGINE_CONNECTING = 2,
    BOWIE_ENGINE_RUNNING    = 3
} bowie_engine_state_t;

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e);

const char *bowie_engine_state_name(bowie_engine_state_t state);

/*
 * ============================================================================
 * EVENTS
 * ============================================================================
 */

void bowie_engine_drain_events(bowie_engine_t *e);

int bowie_engine_poll_event(bowie_engine_t *e,
                            bowie_event_record_t *out);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

uint16_t bowie_engine_dht_port(const bowie_engine_t *e);

uint16_t bowie_engine_signal_port(const bowie_engine_t *e);

size_t bowie_engine_dht_node_count(const bowie_engine_t *e);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_ENGINE_H */
