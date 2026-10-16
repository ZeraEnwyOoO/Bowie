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
 * BOWIE — NAT
 * ============================================================================
 *
 * NAT traversal for Bowie peers.
 *
 * This header declares the NAT interface. The interface is a
 * thin contract: it names the lifecycle, the connection
 * operations, the data operations, the signaling channel, and
 * the capability report. The implementation lives in a backend
 * selected at build time.
 *
 * The only backend in v1 is libjuice, an ICE library. The
 * interface is written so that a future backend (for example
 * Xury) can be added without changing this header.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. Nothing here opens a socket or sends a packet.
 *     The implementation does that; the header only declares
 *     the contract.
 *   - No signaling channel. This header declares the callback
 *     type, but the channel itself (offer, answer, candidates)
 *     is carried by the Protocol layer. NAT never talks to
 *     Protocol directly; the Engine wires them together.
 *   - No session or permission. NAT is a transport concern.
 *     Whether a peer is allowed to use the tunnel is a Session
 *     concern (Layer 7).
 *   - No tunnel. NAT produces a connection; the Tunnel layer
 *     (Layer 6) turns that connection into a tun device.
 *   - No server management. STUN and TURN are external; the
 *     caller supplies their addresses through the config.
 *   - No policy. Whether to allow a STUN or TURN server is a
 *     config flag, not a decision made here.
 *   - No string ownership. String fields in the config are
 *     borrowed, not copied. See the config section below.
 *   - No pull recv guarantee. The interface declares a pull
 *     recv function, but a callback-based backend may not
 *     support it. See the recv section below.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The NAT handle is opaque. The caller owns it, never sees its
 * layout, and frees it with bowie_nat_free().
 *
 * The config is a plain value struct. It is copied by
 * bowie_nat_new(), but its string fields are borrowed: the
 * caller must keep any string alive for the lifetime of the
 * NAT handle. This matches the rest of the library, which
 * copies values and borrows buffers.
 *
 * The signaling channel is a callback, not a function pointer
 * to a Protocol function. This keeps NAT below Protocol in the
 * dependency graph: NAT knows nothing about Protocol, and
 * Protocol knows nothing about NAT. The Engine is the only
 * component that sees both.
 *
 * The recv channel is also a callback. libjuice delivers data
 * through a callback, so the interface exposes that shape. A
 * caller that prefers a pull model can supply a queue-backed
 * callback; the interface does not impose one model.
 *
 * The state enum mirrors libjuice's ICE state machine. A
 * future backend that does not have an ICE state machine is
 * expected to map its own states onto this enum. The enum is
 * the contract; the backend is the adapter.
 *
 * The capabilities struct is a value report, not a
 * negotiation. It tells the caller what the backend actually
 * does, so the caller can decide whether to trust the
 * connection. A backend that performs no NAT traversal
 * reports performs_nat_traversal = 0.
 *
 * ----------------------------------------------------------------------------
 * Backend notes
 * ----------------------------------------------------------------------------
 *
 * The interface is deliberately narrow, and the libjuice
 * backend does not implement every part of it in the obvious
 * way. Two points are worth stating up front, because they
 * affect how a caller writes code against this header:
 *
 *   - Peer address is a hint. libjuice uses SDP signaling,
 *     not a direct address, to establish a connection. The
 *     peer address passed to bowie_nat_connect() is treated
 *     as an initial remote candidate hint. A backend that
 *     does not use it may ignore it. The signaling channel
 *     is the real mechanism.
 *
 *   - Pull recv may return 0. libjuice delivers data through
 *     the recv callback. The pull recv function exists for
 *     symmetry and for backends that queue data, but the
 *     libjuice backend always returns 0 from it. A caller
 *     that wants to receive data through the libjuice
 *     backend installs a recv callback.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>          uint32_t, uint16_t, uint8_t
 *   <stddef.h>          size_t
 *   "bowie/types.h"     bowie_addr_t, bowie_peer_id_t, bowie_nat_t
 *   "bowie/err.h"       bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_NAT_NAT_H
#define BOWIE_NAT_NAT_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * STATE
 * ============================================================================
 *
 * The state of a NAT connection. The names mirror the ICE state
 * machine; a backend that does not implement ICE maps its own
 * states onto these.
 *
 * DISCONNECTED  — no connection in progress.
 * GATHERING     — collecting local candidates.
 * CONNECTING    — exchanging candidates with the peer.
 * CONNECTED     — at least one candidate pair works.
 * COMPLETED     — the best candidate pair is selected.
 * FAILED        — no candidate pair worked.
 */

typedef enum bowie_nat_state {
    BOWIE_NAT_STATE_DISCONNECTED = 0,
    BOWIE_NAT_STATE_GATHERING    = 1,
    BOWIE_NAT_STATE_CONNECTING   = 2,
    BOWIE_NAT_STATE_CONNECTED    = 3,
    BOWIE_NAT_STATE_COMPLETED    = 4,
    BOWIE_NAT_STATE_FAILED       = 5
} bowie_nat_state_t;

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 *
 * Configuration for a NAT instance.
 *
 * The struct is copied by bowie_nat_new(). The string fields
 * are borrowed, not copied: the caller must keep every
 * non-NULL string alive for the lifetime of the NAT handle. A
 * caller that builds a config on the stack must not let its
 * strings go out of scope while the handle is alive.
 *
 * Zero-init the struct, then override the fields you need.
 * bowie_nat_default_config() returns a sane starting point.
 *
 * stun_server_host / stun_server_port
 *     The STUN server to use. If allow_server is 0, ignored.
 *     A NULL host disables STUN. A NULL host with a non-zero
 *     port is a caller bug; the port is ignored.
 *
 * turn_server_host / turn_server_port / turn_username / turn_password
 *     The TURN server to use. If allow_server is 0, or if the
 *     host is NULL, ignored. A TURN server is optional; a
 *     connection that succeeds through STUN does not need it.
 *     turn_username and turn_password may be NULL for a TURN
 *     server that does not require credentials.
 *
 * allow_server
 *     If 0, no STUN or TURN server is used. Only local
 *     candidates are gathered. This is the "no-server" mode.
 *     If 1, the configured servers are used.
 *
 * connect_timeout_ms
 *     How long bowie_nat_connect() may wait for a usable
 *     connection before returning BOWIE_ERR_TIMEOUT. Zero
 *     means use the backend's default.
 *
 * keepalive_ms
 *     How often the backend sends a keepalive on a connected
 *     channel. Zero means the backend chooses.
 */

typedef struct bowie_nat_config {
    const char *stun_server_host;
    uint16_t    stun_server_port;

    const char *turn_server_host;
    uint16_t    turn_server_port;
    const char *turn_username;
    const char *turn_password;

    uint32_t    connect_timeout_ms;
    uint32_t    keepalive_ms;

    int         allow_server;
} bowie_nat_config_t;

/*
 * ============================================================================
 * CAPABILITIES
 * ============================================================================
 *
 * What the backend actually does. A report, not a promise.
 *
 * name
 *     A short identifier for the backend. Static string; do
 *     not free.
 *
 * performs_nat_traversal
 *     1 if the backend really crosses NATs, 0 if it only
 *     gathers local candidates.
 *
 * uses_server
 *     1 if the backend talks to a STUN or TURN server, 0 if
 *     it is fully server-less.
 *
 * can_relay
 *     1 if the backend can relay through a TURN server when
 *     direct traversal fails, 0 otherwise.
 */

typedef struct bowie_nat_caps {
    const char *name;
    int         performs_nat_traversal;
    int         uses_server;
    int         can_relay;
} bowie_nat_caps_t;

/*
 * ============================================================================
 * CALLBACKS
 * ============================================================================
 *
 * signaling send
 *     The backend calls this to hand a signaling payload to
 *     the Engine, which forwards it through the Protocol
 *     layer to the peer. The data buffer is owned by the
 *     backend and is only valid for the duration of the
 *     call; the Engine must copy if it needs to keep it.
 *
 * recv
 *     The backend calls this when data arrives on a connected
 *     channel. The data buffer is owned by the backend and is
 *     only valid for the duration of the call; the caller
 *     must copy if it needs to keep it.
 *
 * state
 *     The backend calls this when the connection state
 *     changes. The callback may be NULL; if so, the caller
 *     polls with bowie_nat_get_state().
 *
 * Every callback receives the ctx pointer that was supplied
 * when the callback was installed.
 */

typedef bowie_error_t (*bowie_nat_signal_send_fn)(
    void                  *ctx,
    const bowie_peer_id_t *peer,
    const uint8_t         *data,
    size_t                 len);

typedef void (*bowie_nat_recv_fn)(
    void          *ctx,
    const uint8_t *data,
    size_t         len);

typedef void (*bowie_nat_state_fn)(
    void              *ctx,
    bowie_nat_state_t  state);

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Fill a config with default values.
 *
 * The defaults describe a device behind a home NAT with no
 * STUN and no TURN server. A caller that has a server sets
 * the server fields and the allow_server flag afterward.
 *
 * The connect timeout is 10 seconds. A shorter timeout may
 * fail on a slow link; a longer one delays failure. The
 * keepalive interval is left to the backend.
 *
 * Passing NULL is a no-op.
 */
void bowie_nat_default_config(bowie_nat_config_t *cfg);

/*
 * Create a NAT instance.
 *
 * The config is copied. String fields are borrowed; the
 * caller must keep them alive for the lifetime of the handle.
 * The instance starts in the DISCONNECTED state. Call
 * bowie_nat_start() before bowie_nat_connect().
 *
 * On success, *out points to the new instance. On failure,
 * *out is set to NULL.
 *
 * Returns BOWIE_ERR_NULL_ARG if cfg or out is NULL.
 * Returns BOWIE_ERR_INVAL if the config is inconsistent.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if no backend is linked.
 */
bowie_error_t bowie_nat_new(const bowie_nat_config_t *cfg,
                            bowie_nat_t             **out);

/*
 * Start a NAT instance.
 *
 * The instance begins gathering candidates. It is an error to
 * start an instance that is already started, or to connect
 * before starting.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 * Returns BOWIE_ERR_STATE if the instance is already started.
 * Returns BOWIE_ERR_INTERNAL if the backend fails to start.
 */
bowie_error_t bowie_nat_start(bowie_nat_t *nat);

/*
 * Stop a NAT instance.
 *
 * Any active connection is torn down. The instance returns to
 * the DISCONNECTED state. It may be started again.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the instance is not started.
 */
bowie_error_t bowie_nat_stop(bowie_nat_t *nat);

/*
 * Free a NAT instance.
 *
 * If the instance is started, it is stopped first. The
 * borrowed config strings are not freed. Passing NULL is a
 * no-op.
 */
void bowie_nat_free(bowie_nat_t *nat);

/*
 * ============================================================================
 * CONNECTION
 * ============================================================================
 */

/*
 * Connect to a peer.
 *
 * The peer address is used as an initial remote candidate
 * hint. A backend that uses SDP signaling rather than direct
 * addressing may ignore it. The signaling channel is the real
 * mechanism: signaling payloads produced by the backend are
 * handed to the signal_send callback, and payloads received
 * from the peer are fed in through bowie_nat_signal_recv().
 *
 * The call blocks until the connection reaches CONNECTED,
 * COMPLETED, or FAILED, or until connect_timeout_ms elapses.
 *
 * If no signal_send callback is installed, the connection
 * cannot proceed and the call fails with
 * BOWIE_ERR_NOT_INITIALIZED.
 *
 * Returns BOWIE_OK on CONNECTED or COMPLETED.
 * Returns BOWIE_ERR_NULL_ARG if nat or peer is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the instance is not started.
 * Returns BOWIE_ERR_NOT_INITIALIZED if no signal callback is set.
 * Returns BOWIE_ERR_BUSY if a connection is already in progress.
 * Returns BOWIE_ERR_TIMEOUT if no connection is made in time.
 * Returns BOWIE_ERR_NETWORK if the backend reports a failure.
 */
bowie_error_t bowie_nat_connect(bowie_nat_t        *nat,
                                const bowie_addr_t *peer,
                                uint32_t            timeout_ms);

/*
 * Disconnect from the current peer.
 *
 * The instance returns to the DISCONNECTED state. It may be
 * connected again.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 * Returns BOWIE_ERR_STATE if no connection is in progress.
 */
bowie_error_t bowie_nat_disconnect(bowie_nat_t *nat);

/*
 * ============================================================================
 * DATA
 * ============================================================================
 */

/*
 * Send data on the connected channel.
 *
 * This function requires an established connection. Calling
 * it before connect, or after disconnect, is a state error.
 *
 * Returns the number of bytes accepted on success.
 * Returns a negative bowie_error_t cast to long on failure.
 * A caller that wants the error code casts the return value
 * back to bowie_error_t. For example:
 *
 *     long n = bowie_nat_send(nat, buf, len);
 *     if (n < 0) {
 *         bowie_error_t err = (bowie_error_t)n;
 *         // handle err
 *     }
 *
 * Returns BOWIE_ERR_NULL_ARG if nat or buf is NULL.
 * Returns BOWIE_ERR_INVAL if len is zero.
 * Returns BOWIE_ERR_STATE if the connection is not in a state
 * that can send.
 * Returns BOWIE_ERR_AGAIN if the backend's send buffer is full
 * and the caller should retry later.
 * Returns BOWIE_ERR_NETWORK if the backend reports a failure.
 */
long bowie_nat_send(bowie_nat_t *nat,
                    const void  *buf,
                    size_t       len);

/*
 * Receive data from the connected channel.
 *
 * This function is a pull-model wrapper. A callback-based
 * backend may not queue data, in which case this function
 * always returns 0 and the caller must use a recv callback
 * instead. The libjuice backend is callback-based: it always
 * returns 0 from this function.
 *
 * This function may be called at any time. It does not
 * require an established connection: a backend that has
 * queued data before a disconnect must still be able to drain
 * it. This is deliberate, and is the reason this function
 * does not check the connection state the way send does.
 *
 * Returns the number of bytes read on success.
 * Returns 0 if no data is available.
 * Returns a negative bowie_error_t cast to long on failure.
 * A caller that wants the error code casts the return value
 * back to bowie_error_t.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat or buf is NULL.
 * Returns BOWIE_ERR_INVAL if cap is zero.
 */
long bowie_nat_recv(bowie_nat_t *nat,
                    void        *buf,
                    size_t       cap);

/*
 * Install the receive callback.
 *
 * Passing NULL removes the callback. The ctx pointer is passed
 * to the callback on every call.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 */
bowie_error_t bowie_nat_set_recv(bowie_nat_t      *nat,
                                 bowie_nat_recv_fn recv,
                                 void             *ctx);

/*
 * ============================================================================
 * SIGNALING
 * ============================================================================
 */

/*
 * Install the signaling send callback.
 *
 * The callback is how the backend hands signaling payloads to
 * the Engine. Without it, bowie_nat_connect() fails with
 * BOWIE_ERR_NOT_INITIALIZED.
 *
 * Passing NULL removes the callback. The ctx pointer is passed
 * to the callback on every call.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 */
bowie_error_t bowie_nat_set_signal(bowie_nat_t             *nat,
                                   bowie_nat_signal_send_fn send,
                                   void                    *ctx);

/*
 * Feed a signaling payload received from the peer into the
 * backend.
 *
 * The Engine calls this when the Protocol layer delivers a
 * signaling message. The payload format is defined by the
 * backend; the Engine treats it as opaque.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat or data is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the instance is not started.
 * Returns BOWIE_ERR_FORMAT if the payload is not valid for the
 * backend.
 * Returns BOWIE_ERR_INTERNAL if the backend rejects the
 * payload.
 */
bowie_error_t bowie_nat_signal_recv(bowie_nat_t   *nat,
                                    const uint8_t *data,
                                    size_t         len);

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

/*
 * Return the current connection state.
 *
 * Returns BOWIE_NAT_STATE_DISCONNECTED if nat is NULL.
 */
bowie_nat_state_t bowie_nat_get_state(const bowie_nat_t *nat);

/*
 * Install the state-change callback.
 *
 * Passing NULL removes the callback. The ctx pointer is passed
 * to the callback on every call.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 */
bowie_error_t bowie_nat_set_state_cb(bowie_nat_t       *nat,
                                     bowie_nat_state_fn state_cb,
                                     void              *ctx);

/*
 * ============================================================================
 * CAPABILITIES
 * ============================================================================
 */

/*
 * Report what the backend actually does.
 *
 * The report is filled from static backend data; it does not
 * depend on the state of the instance.
 *
 * Returns BOWIE_ERR_NULL_ARG if nat or out is NULL.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if no backend is linked.
 */
bowie_error_t bowie_nat_capabilities(const bowie_nat_t *nat,
                                     bowie_nat_caps_t  *out);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

/*
 * Return a human-readable name for a NAT state.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL, even for an unknown state.
 */
const char *bowie_nat_state_name(bowie_nat_state_t state);

/*
 * ============================================================================
 * END OF NAT
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_NAT_NAT_H */
