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
 * BOWIE — NAT (INTERNAL)
 * ============================================================================
 *
 * Internal interface between the NAT core and its backends.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * The public header (include/nat/nat.h) declares the contract
 * that callers use. This header declares the contract that the
 * NAT core uses to talk to a backend, and the contract that a
 * backend uses to talk back to the core.
 *
 * The two contracts are separated on purpose. A caller never
 * sees a backend. A backend never sees a caller. The core is
 * the only component that sees both.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. Nothing here opens a socket or sends a packet.
 *   - No backend selection. The backend is chosen at build
 *     time by the Makefile. This header declares the table that
 *     the chosen backend fills in; it does not choose one.
 *   - No policy. Whether to allow STUN or TURN is a config
 *     flag, not a decision made here.
 *   - No session or permission. NAT is a transport concern.
 *   - No public API. This header must not be included by
 *     anything outside src/nat/.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The NAT handle is opaque to callers but transparent here.
 * The struct bowie_nat is defined in this header because both
 * the core (nat.c) and the backend (nat_libjuice.c) need to
 * see its layout. Callers see only the forward declaration in
 * bowie/types.h.
 *
 * The backend is an operations table, not a vtable on the
 * handle. The core holds a pointer to a const table and a
 * pointer to the backend's private state. The two are
 * separate so that the table can be shared and the state can
 * be per-instance.
 *
 * The backend is chosen at build time. There is exactly one
 * symbol with external linkage that names a backend table:
 * bowie_nat_libjuice_ops. The Makefile selects which source
 * file provides that symbol. A runtime backend selector is
 * possible but is not part of this interface.
 *
 * The three internal helpers (set_state, deliver, signal) are
 * the only way a backend is allowed to call back into the
 * core. The backend never touches the handle's fields
 * directly; it calls a helper. This keeps the handle's layout
 * free to change without touching every backend.
 *
 * The started flag is a boolean, not a state. The state enum
 * tracks the connection; the flag tracks whether the instance
 * has been started. The two are independent: a started
 * instance may be disconnected, and a stopped instance is
 * always disconnected.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t, uint16_t, uint32_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_addr_t, bowie_peer_id_t,
 *                           bowie_nat_t
 *   "bowie/err.h"           bowie_error_t
 *   "nat/nat.h"             bowie_nat_state_t,
 *                           bowie_nat_config_t,
 *                           bowie_nat_caps_t,
 *                           bowie_nat_signal_send_fn,
 *                           bowie_nat_recv_fn,
 *                           bowie_nat_state_fn
 * ============================================================================
 */

#ifndef BOWIE_NAT_INTERNAL_NAT_H
#define BOWIE_NAT_INTERNAL_NAT_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "nat/nat.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FORWARD DECLARATION
 * ============================================================================
 *
 * The backend operations table is referenced by the NAT handle
 * before it is defined. The forward declaration lets the
 * handle name the type without a circular include.
 */

typedef struct bowie_nat_backend_ops bowie_nat_backend_ops_t;

/*
 * ============================================================================
 * NAT HANDLE
 * ============================================================================
 *
 * The full layout of a NAT instance.
 *
 * The handle is opaque to callers. It is transparent here
 * because the core and the backend both need its layout. The
 * two halves of the implementation are:
 *
 *   - the core (nat.c): owns the handle, validates input,
 *     dispatches to the backend, and invokes the caller's
 *     callbacks.
 *
 *   - the backend (nat_libjuice.c): owns the private backend
 *     state, fills in the operations table, and calls the
 *     internal helpers when it needs to notify the core.
 *
 * The handle owns a copy of the config. A caller may free any
 * strings it passed to bowie_nat_new() as soon as that call
 * returns.
 *
 * The signal_send and recv pointers are the caller's
 * callbacks. The core invokes them; the backend never sees
 * them directly. The state_cb pointer is also the caller's;
 * the core invokes it when the backend reports a state change
 * through bowie_nat_internal_set_state().
 *
 * The backend pointer is the backend's private state. The core
 * never dereferences it. The ops pointer is the backend's
 * operations table. The core dispatches through it.
 *
 * The started flag is set by bowie_nat_start() and cleared by
 * bowie_nat_stop(). It is not the same as the state enum: a
 * started instance may be disconnected.
 */

struct bowie_nat {
    /* Serializes callback replacement against backend callback delivery. */
    pthread_mutex_t                     callback_lock;
    bowie_nat_config_t                   cfg;
    bowie_nat_state_t                    state;

    const bowie_nat_backend_ops_t       *ops;
    void                                *backend;

    bowie_nat_signal_send_fn             signal_send;
    void                                *signal_ctx;

    bowie_nat_recv_fn                    recv;
    void                                *recv_ctx;

    bowie_nat_state_fn                   state_cb;
    void                                *state_ctx;

    int                                  started;
};

/*
 * ============================================================================
 * BACKEND OPERATIONS
 * ============================================================================
 *
 * The operations a backend must provide. The core dispatches
 * through this table; it never calls a backend function by
 * name.
 *
 * Every function receives the handle. The backend may read the
 * config from nat->cfg and may read or write its own private
 * state through nat->backend. The backend must not touch the
 * callback fields; it uses the internal helpers instead.
 *
 * A function that can fail returns bowie_error_t. A function
 * that returns a length returns a non-negative count on
 * success and a negative bowie_error_t on failure, following
 * the long convention in this library.
 */

struct bowie_nat_backend_ops {
    /*
     * Create the backend's private state.
     *
     * Called once, from bowie_nat_new(), after the handle has
     * been allocated and the config has been copied.
     *
     * On success, nat->backend points to the backend's state.
     * On failure, nat->backend is NULL.
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
     * Returns BOWIE_ERR_NOMEM if allocation fails.
     */
    bowie_error_t (*create)(bowie_nat_t *nat,
                            const bowie_nat_config_t *cfg);

    /*
     * Start the backend.
     *
     * Called from bowie_nat_start(). After this call the
     * backend may begin gathering candidates.
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
     * Returns BOWIE_ERR_STATE if the backend is already
     * started.
     * Returns BOWIE_ERR_INTERNAL if the backend fails.
     */
    bowie_error_t (*start)(bowie_nat_t *nat);

    /*
     * Stop the backend.
     *
     * Called from bowie_nat_stop(). Any active connection is
     * torn down. The backend remains usable.
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
     * Returns BOWIE_ERR_NOT_STARTED if the backend is not
     * started.
     */
    bowie_error_t (*stop)(bowie_nat_t *nat);

    /*
     * Free the backend's private state.
     *
     * Called from bowie_nat_free(). The backend must not
     * assume that stop has been called first; the core calls
     * stop if the instance is started.
     *
     * Passing nat == NULL is a no-op. Passing a handle with
     * nat->backend == NULL is a no-op.
     */
    void (*free)(bowie_nat_t *nat);

    /*
     * Connect to a peer.
     *
     * Called from bowie_nat_connect(). The backend uses the
     * signal_send callback through bowie_nat_internal_signal()
     * to exchange signaling payloads, and reports state
     * changes through bowie_nat_internal_set_state().
     *
     * The call blocks until the connection is established or
     * the timeout elapses.
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat or peer is NULL.
     * Returns BOWIE_ERR_TIMEOUT if no connection is made.
     * Returns BOWIE_ERR_NETWORK if the backend reports a
     * failure.
     */
    bowie_error_t (*connect)(bowie_nat_t *nat,
                             const bowie_addr_t *peer,
                             uint32_t timeout_ms);

    /*
     * Disconnect from the current peer.
     *
     * Called from bowie_nat_disconnect().
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
     * Returns BOWIE_ERR_STATE if no connection is in progress.
     */
    bowie_error_t (*disconnect)(bowie_nat_t *nat);

    /*
     * Send data on the connected channel.
     *
     * Called from bowie_nat_send().
     *
     * Returns the number of bytes accepted, or a negative
     * bowie_error_t on failure.
     */
    long (*send)(bowie_nat_t *nat,
                 const void *buf,
                 size_t len);

    /*
     * Receive data from the connected channel.
     *
     * Called from bowie_nat_recv(). The backend drains any
     * queued data into the caller's buffer.
     *
     * Returns the number of bytes read, 0 if no data is
     * available, or a negative bowie_error_t on failure.
     */
    long (*recv)(bowie_nat_t *nat,
                 void *buf,
                 size_t cap);

    /*
     * Feed a signaling payload received from the peer into
     * the backend.
     *
     * Called from bowie_nat_signal_recv().
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat or data is NULL.
     * Returns BOWIE_ERR_FORMAT if the payload is not valid.
     */
    bowie_error_t (*signal_recv)(bowie_nat_t *nat,
                                 const uint8_t *data,
                                 size_t len);

    /*
     * Report what the backend actually does.
     *
     * Called from bowie_nat_capabilities(). The report does
     * not depend on the state of the instance.
     *
     * Returns BOWIE_OK on success.
     * Returns BOWIE_ERR_NULL_ARG if nat or out is NULL.
     */
    bowie_error_t (*capabilities)(const bowie_nat_t *nat,
                                  bowie_nat_caps_t *out);

    bowie_error_t (*add_turn_server)(bowie_nat_t *nat, const char *host,
                                     uint16_t port, const char *username,
                                     const char *password);
};

/*
 * ============================================================================
 * BACKEND REGISTRATION
 * ============================================================================
 *
 * Exactly one backend table is linked into the library. The
 * Makefile selects which source file provides it. The core
 * refers to the symbol by name; there is no lookup.
 *
 * The symbol has external linkage so that the core can refer
 * to it across translation units. It is not declared in any
 * public header and is not part of the public API.
 *
 * The libjuice backend is the only backend in v1. A future
 * backend adds a new symbol and a new Makefile choice; it does
 * not change this header.
 */

extern const bowie_nat_backend_ops_t bowie_nat_libjuice_ops;

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 *
 * The only functions a backend may call back into the core
 * with. The backend must not touch the handle's fields
 * directly; it calls one of these.
 *
 * The helpers are declared here, not in the public header,
 * because only a backend uses them.
 */

/*
 * Report a state change.
 *
 * The core updates nat->state and, if a state callback is
 * installed, invokes it with the caller's ctx pointer.
 *
 * Passing nat == NULL is a no-op.
 *
 * A backend must call this whenever the connection state
 * changes. The core does not poll the backend for state.
 */
void bowie_nat_internal_set_state(bowie_nat_t *nat,
                                  bowie_nat_state_t state);

/*
 * Deliver received data.
 *
 * If a recv callback is installed, the core invokes it with
 * the caller's ctx pointer and the data. If no recv callback
 * is installed, the core drops the data.
 *
 * The data pointer is borrowed for the duration of the call.
 * The core does not copy it. A backend that needs to keep the
 * data must copy before calling.
 *
 * Passing nat == NULL or data == NULL is a no-op. Passing
 * len == 0 is a no-op.
 */
void bowie_nat_internal_deliver(bowie_nat_t *nat,
                                const uint8_t *data,
                                size_t len);

/*
 * Send a signaling payload to the peer.
 *
 * The core invokes the caller's signal_send callback with the
 * caller's ctx pointer. The core does not format the payload;
 * the backend owns the format.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if nat is NULL.
 * Returns BOWIE_ERR_NOT_INITIALIZED if no signal callback is
 * installed.
 * Returns whatever the caller's callback returns.
 */
bowie_error_t bowie_nat_internal_signal(bowie_nat_t *nat,
                                        const bowie_peer_id_t *peer,
                                        const uint8_t *data,
                                        size_t len);

/*
 * ============================================================================
 * END OF INTERNAL NAT
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_NAT_INTERNAL_NAT_H */
