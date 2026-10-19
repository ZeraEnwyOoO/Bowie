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
 * The engine has four states:
 *
 *   STOPPED      no resources, no threads, no sockets
 *   STARTED      DHT and NAT are up; no peer is connected
 *   CONNECTING   a connect or accept is in progress
 *   RUNNING      at least one session is active; gateway
 *                is forwarding
 *
 * The transitions are:
 *
 *   STOPPED    → STARTED    (bowie_engine_start)
 *   STARTED    → CONNECTING (bowie_engine_connect / bowie_engine_accept)
 *   CONNECTING → RUNNING    (handshake + permission done)
 *   CONNECTING → STARTED    (connect failed)
 *   RUNNING    → STARTED    (bowie_engine_disconnect)
 *   any        → STOPPED    (bowie_engine_stop)
 *
 * The engine is not thread-safe. A caller that shares an
 * engine between threads must serialize every call. The
 * engine runs its own internal threads for the DHT, for the
 * signaling channel, and for the gateway; those threads do
 * not call back into the public API.
 *
 * A caller that wants multiple engines in one process creates
 * multiple handles with bowie_engine_new(). There is no
 * process-wide state beyond what the DHT, NAT, and the
 * signaling socket allocate per instance.
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
 *   "bowie/hooks.h"         bowie_hooks_t, bowie_event_record_t
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_ENGINE_H
#define BOWIE_ENGINE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "dht/node.h"         /* Fix: For bowie_dht_node_t */
#include "security/sign.h"    /* Fix: For bowie_sign_signature_t */

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
 * HOOKS (Log, Event, Storage)
 * ============================================================================
 *
 * The engine forwards its log lines, its events, and its
 * storage requests to the caller through a hook set. The hook
 * set is the same one declared in bowie/hooks.h.
 *
 * The hook set is installed after the engine is created and
 * before it is started. A hook set that is not installed is
 * treated as "no hooks": log lines and events are dropped,
 * and storage requests use the platform storage.
 */

/*
 * Install the hook set.
 *
 * The engine copies the set. The caller may free the set
 * after the call returns.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or hooks is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not STOPPED.
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
 *
 * The engine records structured events as it runs. The
 * caller drains them with bowie_engine_drain_events().
 */

/*
 * Drain the event queue through the installed event hook.
 *
 * The engine calls the event hook once per queued event. The
 * queue is emptied. The hook runs without the engine lock
 * held, so it may call back into the public API.
 *
 * Passing NULL for e is a no-op.
 */
void bowie_engine_drain_events(bowie_engine_t *e);

/*
 * Poll one event from the queue.
 *
 * The function pops the oldest event and copies it into the
 * caller's record. A caller that wants to drain the queue
 * without a hook calls this function in a loop until it
 * returns 0.
 *
 * Returns 1 when an event was copied, 0 when the queue is
 * empty.
 *
 * Passing NULL for e or out is a no-op and returns 0.
 */
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

/*
 * ============================================================================
 * END OF ENGINE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_ENGINE_H */
