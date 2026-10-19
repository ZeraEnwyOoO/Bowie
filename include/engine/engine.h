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
 *   "bowie/config.h"        bowie_log_level_t, bowie_cap_t
 *   "bowie/hooks.h"         bowie_hooks_t
 *   "dht/types.h"           bowie_dht_node_t
 *   "security/sign.h"       bowie_sign_signature_t
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_ENGINE_H
#define BOWIE_ENGINE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/config.h"
#include "bowie/hooks.h"
#include "dht/types.h"
#include "security/sign.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 *
 * The engine config carries the fields the engine needs from
 * the caller. The DHT config and the NAT config are built
 * from these values by bowie_engine_new().
 *
 * A zeroed config is valid and means "use library defaults
 * everywhere". The helper bowie_engine_default_config()
 * returns a sane starting point.
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

    /* Log level for the engine. */
    bowie_log_level_t log_level;
} bowie_engine_config_t;

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

bowie_error_t bowie_engine_set_hooks(bowie_engine_t *e,
                                     const bowie_hooks_t *hooks);

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Fill a config with default values.
 *
 * Defaults: every port zero (OS chooses), allow_server 0,
 * every server field NULL, tunnel_mtu 0 (use tunnel default).
 * The log level defaults to BOWIE_LOG_INFO.
 *
 * Passing NULL is a no-op.
 */
void bowie_engine_default_config(bowie_engine_config_t *cfg);

/*
 * Create an engine handle.
 *
 * The config is copied. String fields are borrowed: the
 * caller must keep every non-NULL string alive for the
 * lifetime of the engine.
 *
 * On success, *out points to the new engine handle. The
 * engine is in STOPPED state and owns no threads or sockets.
 * The caller must call bowie_engine_free() on it when done.
 *
 * On failure, *out is set to NULL.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_INVAL if the config is inconsistent.
 * Returns a CRYPTO-class error if the identity keypair cannot
 *   be generated.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out);

/*
 * Free an engine handle.
 *
 * If the engine is running, it is stopped first. The config
 * strings are not freed; they belong to the caller.
 *
 * Passing NULL is a no-op.
 */
void bowie_engine_free(bowie_engine_t *e);

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

/*
 * Start the engine.
 *
 * The tunnel is supplied by the caller. The engine does not
 * own the tunnel; the caller must keep it open for the
 * lifetime of the engine.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not STOPPED.
 * Returns BOWIE_ERR_INVAL if the tunnel is NULL.
 * Returns BOWIE_ERR_NETWORK if the DHT or signaling socket
 *   cannot be opened.
 */
bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun);

/*
 * Stop the engine.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 */
bowie_error_t bowie_engine_stop(bowie_engine_t *e);

/*
 * ============================================================================
 * BOOTSTRAP
 * ============================================================================
 */

/*
 * Add a bootstrap node to the DHT and send a PING to kickstart it.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or ip is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not STARTED.
 * Returns BOWIE_ERR_INVAL if the IP string is invalid.
 * Returns BOWIE_ERR_NETWORK if the PING could not be sent.
 */
bowie_error_t bowie_engine_add_bootstrap(bowie_engine_t *e,
                                         const char *ip,
                                         uint16_t port);

/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 */

/*
 * Search for a peer by ID using the DHT.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e, peer_id, or out_node is NULL.
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
 * CONNECT / ACCEPT / DISCONNECT
 * ============================================================================
 */

/*
 * Connect to a peer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or peer is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_STATE if the engine is not in STARTED state.
 * Returns BOWIE_ERR_NOT_FOUND if the peer cannot be found.
 * Returns BOWIE_ERR_TIMEOUT if the connection times out.
 * Returns BOWIE_ERR_NETWORK if the NAT layer fails.
 * Returns BOWIE_ERR_SIGN_INVALID if the handshake fails.
 */
bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);

/*
 * Accept a connection from a peer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_STATE if the engine is not in STARTED state.
 * Returns BOWIE_ERR_TIMEOUT if no peer connects in time.
 * Returns BOWIE_ERR_NETWORK if the NAT layer fails.
 */
bowie_error_t bowie_engine_accept(bowie_engine_t *e,
                                  uint32_t timeout_ms);

/*
 * Disconnect from the current peer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not RUNNING.
 */
bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);

/*
 * ============================================================================
 * EVENTS
 * ============================================================================
 */

/*
 * Drain the event queue through the installed event hook.
 */
void bowie_engine_drain_events(bowie_engine_t *e);

/*
 * Poll one event from the queue.
 *
 * Returns 1 when an event was copied, 0 when the queue is empty.
 */
int bowie_engine_poll_event(bowie_engine_t *e,
                            bowie_event_record_t *out);

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
