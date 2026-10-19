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
 * The engine is created with bowie_engine_new() and freed
 * with bowie_engine_free(). A caller that forgets to free it
 * leaks the DHT and the NAT layer. The DHT and the NAT layer
 * are the only resources the engine allocates; the tunnel and
 * the gateway are supplied by the caller.
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
 *
 * The config is a plain value struct. It is copied by
 * bowie_engine_new(); the caller may free the struct after
 * the call returns.
 *
 * Zero-init the struct, then override the fields you need.
 * bowie_engine_default_config() returns a sane starting
 * point.
 *
 * dht_port
 *     The UDP port the DHT listens on. Zero means use the
 *     module default.
 *
 * nat_port
 *     The UDP port the NAT layer listens on. Zero means use
 *     the module default.
 *
 * allow_server
 *     If 1, the NAT layer may use STUN and TURN servers.
 *     If 0, it uses only local candidates.
 *
 * stun_host / stun_port
 *     The STUN server to use. Ignored if allow_server is 0.
 *
 * turn_host / turn_port / turn_user / turn_pass
 *     The TURN server to use. Ignored if allow_server is 0 or
 *     if turn_host is NULL.
 *
 * tunnel_mtu
 *     The MTU of the tunnel. Zero means use the tunnel
 *     default.
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

/*
 * Fill a config with default values.
 *
 * Defaults: dht_port = 0, nat_port = 0, allow_server = 0,
 * all hosts NULL, all ports 0, tunnel_mtu = 0.
 *
 * Passing NULL is a no-op.
 */
void bowie_engine_default_config(bowie_engine_config_t *cfg);

/*
 * Create an engine.
 *
 * The engine starts in the stopped state. Call
 * bowie_engine_start() to bring up the DHT and the NAT layer.
 *
 * On success, *out points to the new engine handle.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if cfg or out is NULL.
 * Returns BOWIE_ERR_INVAL if the config is inconsistent.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out);

/*
 * Free an engine.
 *
 * If the engine is running, it is stopped first. The tunnel
 * and the gateway are not closed; the caller owns them.
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
 * The DHT and the NAT layer are brought up. The DHT starts
 * listening on its port; the NAT layer starts gathering
 * candidates.
 *
 * The tunnel is supplied at start time. It must remain valid
 * for the lifetime of the engine; the engine does not close
 * it.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or tun is NULL.
 * Returns BOWIE_ERR_STATE if the engine is already started.
 * Returns BOWIE_ERR_INTERNAL if a layer fails to start.
 */
bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun);

/*
 * Stop the engine.
 *
 * Any active session is torn down. The gateway is stopped
 * first, then the NAT layer, then the DHT. The tunnel is not
 * closed.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 */
bowie_error_t bowie_engine_stop(bowie_engine_t *e);

/*
 * ============================================================================
 * CONNECT / DISCONNECT
 * ============================================================================
 */

/*
 * Connect to a peer.
 *
 * The call runs the full sequence: DHT lookup, NAT
 * connection, protocol handshake, security check, session
 * creation, gateway start.
 *
 * On success, the engine is in the running state and the
 * peer's traffic is forwarded through the tunnel.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or peer is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_BUSY if a connection is already in
 *   progress.
 * Returns BOWIE_ERR_TIMEOUT if the peer does not answer.
 * Returns BOWIE_ERR_PERMISSION if the peer is not authorized.
 * Returns BOWIE_ERR_NETWORK if a layer reports a failure.
 */
bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);

/*
 * Disconnect from the current peer.
 *
 * The gateway is stopped, the session is freed, the NAT
 * connection is closed.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if no connection is active.
 */
bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

/*
 * The engine's state. The names mirror the lifecycle:
 *
 * STOPPED  — created but not started.
 * STARTED  — DHT and NAT layer up, no active session.
 * RUNNING  — at least one active session.
 */

typedef enum bowie_engine_state {
    BOWIE_ENGINE_STOPPED = 0,
    BOWIE_ENGINE_STARTED = 1,
    BOWIE_ENGINE_RUNNING = 2
} bowie_engine_state_t;

/*
 * Return the engine's current state.
 *
 * Passing NULL returns BOWIE_ENGINE_STOPPED.
 */
bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

/*
 * Return a human-readable name for an engine state.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
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
