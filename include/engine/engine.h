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
 * The engine config carries the fields the engine needs from
 * the caller. The DHT config and the NAT config are built
 * from these values by bowie_engine_new().
 *
 * A zeroed config is valid and means "use library defaults
 * everywhere". The helper bowie_engine_default_config()
 * returns a sane starting point.
 *
 * dht_port
 *     The UDP port the DHT listens on. Zero means "let the
 *     operating system choose". The chosen port is available
 *     from bowie_engine_dht_port() after bowie_engine_start().
 *
 * nat_port
 *     The UDP port the NAT signaling channel listens on. Zero
 *     means "let the operating system choose".
 *
 * allow_server
 *     1 if the NAT layer may use STUN and TURN servers, 0
 *     for server-less mode.
 *
 * stun_host / stun_port
 *     The STUN server. Ignored when allow_server is 0.
 *
 * turn_host / turn_port / turn_user / turn_pass
 *     The TURN server. Ignored when allow_server is 0 or when
 *     turn_host is NULL.
 *
 * tunnel_mtu
 *     The MTU the engine sets on the tunnel device. Zero
 *     means use the tunnel default (BOWIE_TUN_MTU_TUNNEL).
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
 * Defaults: every port zero (OS chooses), allow_server 0,
 * every server field NULL, tunnel_mtu 0 (use tunnel default).
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
 *
 * A stopped engine has no resources. bowie_engine_start()
 * brings up the DHT, the NAT layer, and the signaling
 * channel. bowie_engine_stop() tears them down in the
 * reverse order.
 *
 * A start or stop that fails leaves the engine in STOPPED
 * state; the caller may retry.
 */

/*
 * Start the engine.
 *
 * The tunnel is supplied by the caller. The engine does not
 * own the tunnel; the caller must keep it open for the
 * lifetime of the engine.
 *
 * On success, the engine is in STARTED state. The DHT is
 * running, the NAT layer is ready to connect, and the
 * signaling socket is listening.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not STOPPED.
 * Returns BOWIE_ERR_INVAL if the tunnel is NULL.
 * Returns BOWIE_ERR_NETWORK if the DHT or signaling socket
 *   cannot be opened.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun);

/*
 * Stop the engine.
 *
 * Any active session is torn down. The DHT, the NAT layer,
 * and the signaling socket are stopped and freed. The tunnel
 * is not closed; it belongs to the caller.
 *
 * Passing NULL is a no-op.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 */
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
 * CONNECT / ACCEPT / DISCONNECT
 * ============================================================================
 */

/*
 * Connect to a peer.
 *
 * The function runs the full connection workflow:
 *
 *   1. Search the peer in the DHT.
 *   2. Exchange signaling payloads through the signaling
 *      channel to establish a NAT connection.
 *   3. Run the handshake over the NAT connection.
 *   4. Exchange session keypairs.
 *   5. Run the permission check.
 *   6. Create the session.
 *   7. Start the gateway.
 *
 * On success, the engine is in RUNNING state and the gateway
 * is forwarding packets between the tunnel and the peer.
 *
 * The call blocks until the connection is established or
 * the timeout elapses.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or peer is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_STATE if the engine is not in STARTED
 *   state (already connecting, running, or stopped).
 * Returns BOWIE_ERR_NOT_FOUND if the peer cannot be found in
 *   the DHT.
 * Returns BOWIE_ERR_TIMEOUT if the connection times out.
 * Returns BOWIE_ERR_NETWORK if the NAT layer fails.
 * Returns BOWIE_ERR_SIGN_INVALID if the handshake fails.
 * Returns a PERMISSION-class error if the peer is not
 *   allowed to connect.
 */
bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);

/*
 * Accept a connection from a peer.
 *
 * This is the passive counterpart to bowie_engine_connect().
 * The function waits for a peer to establish a NAT connection
 * through the signaling channel, then runs the handshake, the
 * session keypair exchange, and the permission check.
 *
 * On success, the engine is in RUNNING state and the gateway
 * is forwarding packets between the tunnel and the peer.
 *
 * The call blocks until a peer connects or the timeout
 * elapses.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the engine is not started.
 * Returns BOWIE_ERR_STATE if the engine is not in STARTED
 *   state.
 * Returns BOWIE_ERR_TIMEOUT if no peer connects in time.
 * Returns BOWIE_ERR_NETWORK if the NAT layer fails.
 * Returns BOWIE_ERR_SIGN_INVALID if the handshake fails.
 * Returns a PERMISSION-class error if the peer is not
 *   allowed to connect.
 */
bowie_error_t bowie_engine_accept(bowie_engine_t *e,
                                  uint32_t timeout_ms);

/*
 * Disconnect from the current peer.
 *
 * The gateway is stopped, the session is freed, and the NAT
 * connection is torn down. The engine returns to STARTED
 * state.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the engine is not RUNNING.
 */
bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);

/*
 * ============================================================================
 * IDENTITY
 * ============================================================================
 *
 * The engine owns an Ed25519 keypair generated at
 * bowie_engine_new(). The public ID is derived from the
 * keypair; the peer ID is derived from the public ID with
 * the hash function in use.
 *
 * The owner's keypair is not exposed. A caller that needs to
 * sign a grant uses bowie_engine_sign() below.
 */

/*
 * Return the engine's public ID.
 *
 * The ID is copied into the caller's struct.
 *
 * Passing NULL for e or out is a no-op.
 */
void bowie_engine_public_id(const bowie_engine_t *e,
                            bowie_public_id_t *out);

/*
 * Return the engine's peer ID.
 *
 * The ID is copied into the caller's struct.
 *
 * Passing NULL for e or out is a no-op.
 */
void bowie_engine_peer_id(const bowie_engine_t *e,
                          bowie_peer_id_t *out);

/*
 * Sign a message with the engine's private key.
 *
 * The signature is written through out. The message is
 * signed as-is; the caller is responsible for the format.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or out is NULL, or if msg
 *   is NULL with a non-zero length.
 * Returns a CRYPTO-class error if signing fails.
 */
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

/*
 * Return the current engine state.
 *
 * Returns BOWIE_ENGINE_STOPPED for NULL.
 */
bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e);

/*
 * Return a human-readable name for a state.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL, even for an unknown state.
 */
const char *bowie_engine_state_name(bowie_engine_state_t state);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

/*
 * Return the UDP port the DHT is listening on.
 *
 * This is the port the caller passed to bowie_engine_start()
 * when the DHT was started, or the port the operating system
 * chose when the caller passed zero. It is available only
 * while the engine is not STOPPED.
 *
 * Returns 0 for NULL or for a stopped engine.
 */
uint16_t bowie_engine_dht_port(const bowie_engine_t *e);

/*
 * Return the UDP port the signaling channel is listening on.
 *
 * Same shape as bowie_engine_dht_port().
 */
uint16_t bowie_engine_signal_port(const bowie_engine_t *e);

/*
 * Return the number of live nodes in the DHT routing table.
 *
 * Returns 0 for NULL or for a stopped engine.
 */
size_t bowie_engine_dht_node_count(const bowie_engine_t *e);
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
 *
 * The engine takes a copy of the hook set. The caller may
 * free the set after the call returns.
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
 * EVENTS
 * ============================================================================
 *
 * The engine records structured events as it runs. The
 * caller drains them with bowie_engine_drain_events().
 *
 * The drain function calls the event hook for each event in
 * the queue. A caller that does not want events does not
 * install an event hook; the events are recorded but
 * dropped.
 *
 * A caller that wants to inspect the events without a hook
 * uses bowie_engine_poll_event() one at a time. The two
 * functions are mutually exclusive: a caller uses one or the
 * other.
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
 * END OF ENGINE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_ENGINE_H */
