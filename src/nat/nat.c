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
 * BOWIE — NAT (CORE)
 * ============================================================================
 *
 * The NAT core. Validates input, dispatches to the backend,
 * and invokes the caller's callbacks.
 *
 * This file implements the public API declared in
 * include/nat/nat.h. It does not implement NAT traversal; it
 * delegates to a backend chosen at build time.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. The core never opens a socket, never sends a
 *     packet, never reads a file.
 *   - No NAT traversal. The core does not know how ICE works,
 *     how candidates are gathered, or how a connection is
 *     established. The backend does.
 *   - No backend selection. The backend is chosen by the
 *     Makefile. The core refers to one symbol by name.
 *   - No session or permission. The core does not check
 *     whether a peer is allowed to connect. That is a Session
 *     concern (Layer 7).
 *   - No tunnel. The core produces a connection; turning that
 *     connection into a tun device is a Tunnel concern
 *     (Layer 6).
 *   - No string ownership. Config string fields are borrowed
 *     from the caller. The core copies the struct, not the
 *     strings.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The core is a thin layer. Its job is to be the only place
 * that knows about both the caller's contract and the
 * backend's contract. Everything else is a pass-through.
 *
 * The core never calls a backend function by name. It calls
 * through nat->ops. This keeps the core independent of the
 * backend: adding a second backend adds a second symbol and a
 * second Makefile choice, but does not touch this file.
 *
 * The core owns the handle. The backend owns its own private
 * state through nat->backend. The two never reach into each
 * other's fields: the core uses the operations table, and the
 * backend uses the internal helpers in nat/internal/nat.h.
 *
 * The config is copied into the handle as a struct, but its
 * string fields are borrowed: the caller must keep every
 * non-NULL string alive for the lifetime of the handle. The
 * backend receives a pointer to the copied struct, not to the
 * caller's original, but the string pointers inside are the
 * caller's.
 *
 * The started flag is a boolean, separate from the state
 * enum. A started instance may be disconnected; a stopped
 * instance is always disconnected. The core refuses to
 * connect an instance that has not been started.
 *
 * Every public function validates its arguments before doing
 * anything else. A NULL argument is always BOWIE_ERR_NULL_ARG,
 * never a crash. A state error is always BOWIE_ERR_STATE or a
 * more specific state code, never a silent no-op.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdlib.h>                  calloc, free
 *   <string.h>                  memset
 *   "bowie/types.h"             bowie_addr_t, bowie_peer_id_t
 *   "bowie/err.h"               bowie_error_t and codes
 *   "nat/nat.h"                 public NAT contract
 *   "nat/internal/nat.h"        internal NAT contract
 * ============================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "nat/nat.h"
#include "nat/internal/nat.h"

/*
 * ============================================================================
 * CONFIG DEFAULTS
 * ============================================================================
 */

void bowie_nat_default_config(bowie_nat_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->stun_server_host = NULL;
    cfg->stun_server_port = 0;

    cfg->turn_server_host = NULL;
    cfg->turn_server_port = 0;
    cfg->turn_username    = NULL;
    cfg->turn_password    = NULL;

    cfg->connect_timeout_ms = 10000;
    cfg->keepalive_ms       = 0;

    cfg->allow_server       = 0;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_nat_new(const bowie_nat_config_t *cfg,
                            bowie_nat_t             **out)
{
    bowie_nat_t  *nat;
    bowie_error_t rc;

    if (cfg == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (cfg->allow_server != 0 && cfg->allow_server != 1) {
        return BOWIE_ERR_INVAL;
    }

    nat = (bowie_nat_t *)calloc(1, sizeof(*nat));

    if (nat == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    nat->cfg     = *cfg;
    nat->state   = BOWIE_NAT_STATE_DISCONNECTED;
    nat->ops     = &bowie_nat_libjuice_ops;
    nat->backend = NULL;
    nat->started = 0;

    nat->signal_send = NULL;
    nat->signal_ctx  = NULL;
    nat->recv        = NULL;
    nat->recv_ctx    = NULL;
    nat->state_cb    = NULL;
    nat->state_ctx   = NULL;

    if (nat->ops == NULL || nat->ops->create == NULL) {
        free(nat);
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    rc = nat->ops->create(nat, &nat->cfg);

    if (rc != BOWIE_OK) {
        free(nat);
        return rc;
    }

    *out = nat;

    return BOWIE_OK;
}

bowie_error_t bowie_nat_start(bowie_nat_t *nat)
{
    bowie_error_t rc;

    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (nat->started) {
        return BOWIE_ERR_STATE;
    }

    if (nat->ops == NULL || nat->ops->start == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    rc = nat->ops->start(nat);

    if (rc != BOWIE_OK) {
        return rc;
    }

    nat->started = 1;

    return BOWIE_OK;
}

bowie_error_t bowie_nat_stop(bowie_nat_t *nat)
{
    bowie_error_t rc;

    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!nat->started) {
        return BOWIE_ERR_NOT_STARTED;
    }

    if (nat->ops == NULL || nat->ops->stop == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    rc = nat->ops->stop(nat);

    if (rc != BOWIE_OK) {
        return rc;
    }

    nat->started = 0;
    nat->state   = BOWIE_NAT_STATE_DISCONNECTED;

    return BOWIE_OK;
}

void bowie_nat_free(bowie_nat_t *nat)
{
    if (nat == NULL) {
        return;
    }

    if (nat->started && nat->ops != NULL && nat->ops->stop != NULL) {
        (void)nat->ops->stop(nat);
        nat->started = 0;
    }

    if (nat->ops != NULL && nat->ops->free != NULL) {
        nat->ops->free(nat);
    }

    /*
     * The config string fields are borrowed from the caller and
     * are not freed here.
     */

    free(nat);
}

/*
 * ============================================================================
 * CONNECTION
 * ============================================================================
 */

bowie_error_t bowie_nat_connect(bowie_nat_t        *nat,
                                const bowie_addr_t *peer,
                                uint32_t            timeout_ms)
{
    if (nat == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!nat->started) {
        return BOWIE_ERR_NOT_STARTED;
    }

    if (nat->signal_send == NULL) {
        return BOWIE_ERR_NOT_INITIALIZED;
    }

    if (nat->state == BOWIE_NAT_STATE_GATHERING ||
        nat->state == BOWIE_NAT_STATE_CONNECTING ||
        nat->state == BOWIE_NAT_STATE_CONNECTED ||
        nat->state == BOWIE_NAT_STATE_COMPLETED) {
        return BOWIE_ERR_BUSY;
    }

    if (nat->ops == NULL || nat->ops->connect == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    if (timeout_ms == 0) {
        timeout_ms = nat->cfg.connect_timeout_ms;
    }

    return nat->ops->connect(nat, peer, timeout_ms);
}

bowie_error_t bowie_nat_disconnect(bowie_nat_t *nat)
{
    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (nat->state == BOWIE_NAT_STATE_DISCONNECTED) {
        return BOWIE_ERR_STATE;
    }

    if (nat->ops == NULL || nat->ops->disconnect == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    return nat->ops->disconnect(nat);
}

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
 * The return value follows the long convention: a non-negative
 * count on success, a negative bowie_error_t cast to long on
 * failure.
 */
long bowie_nat_send(bowie_nat_t *nat,
                    const void  *buf,
                    size_t       len)
{
    if (nat == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (len == 0) {
        return BOWIE_ERR_INVAL;
    }

    if (nat->state != BOWIE_NAT_STATE_CONNECTED &&
        nat->state != BOWIE_NAT_STATE_COMPLETED) {
        return BOWIE_ERR_STATE;
    }

    if (nat->ops == NULL || nat->ops->send == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    return nat->ops->send(nat, buf, len);
}

/*
 * Receive data from the connected channel.
 *
 * This function may be called at any time. It does not check
 * the connection state: a backend that has queued data before
 * a disconnect must still be able to drain it. This is
 * deliberate, and is the reason this function is asymmetric
 * with send.
 *
 * The return value follows the long convention: a non-negative
 * count on success, a negative bowie_error_t cast to long on
 * failure.
 */
long bowie_nat_recv(bowie_nat_t *nat,
                    void        *buf,
                    size_t       cap)
{
    if (nat == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cap == 0) {
        return BOWIE_ERR_INVAL;
    }

    if (nat->ops == NULL || nat->ops->recv == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    return nat->ops->recv(nat, buf, cap);
}

bowie_error_t bowie_nat_set_recv(bowie_nat_t      *nat,
                                 bowie_nat_recv_fn recv,
                                 void             *ctx)
{
    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    nat->recv     = recv;
    nat->recv_ctx = ctx;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * SIGNALING
 * ============================================================================
 */

bowie_error_t bowie_nat_set_signal(bowie_nat_t             *nat,
                                   bowie_nat_signal_send_fn send,
                                   void                    *ctx)
{
    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    nat->signal_send = send;
    nat->signal_ctx  = ctx;

    return BOWIE_OK;
}

bowie_error_t bowie_nat_signal_recv(bowie_nat_t   *nat,
                                    const uint8_t *data,
                                    size_t         len)
{
    if (nat == NULL || data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (len == 0) {
        return BOWIE_ERR_INVAL;
    }

    if (!nat->started) {
        return BOWIE_ERR_NOT_STARTED;
    }

    if (nat->ops == NULL || nat->ops->signal_recv == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    return nat->ops->signal_recv(nat, data, len);
}

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

bowie_nat_state_t bowie_nat_get_state(const bowie_nat_t *nat)
{
    if (nat == NULL) {
        return BOWIE_NAT_STATE_DISCONNECTED;
    }

    return nat->state;
}

bowie_error_t bowie_nat_set_state_cb(bowie_nat_t       *nat,
                                     bowie_nat_state_fn state_cb,
                                     void              *ctx)
{
    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    nat->state_cb  = state_cb;
    nat->state_ctx = ctx;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * CAPABILITIES
 * ============================================================================
 */

bowie_error_t bowie_nat_capabilities(const bowie_nat_t *nat,
                                     bowie_nat_caps_t  *out)
{
    if (nat == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(out, 0, sizeof(*out));

    if (nat->ops == NULL || nat->ops->capabilities == NULL) {
        return BOWIE_ERR_NOT_IMPLEMENTED;
    }

    return nat->ops->capabilities(nat, out);
}

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

const char *bowie_nat_state_name(bowie_nat_state_t state)
{
    switch (state) {
    case BOWIE_NAT_STATE_DISCONNECTED:
        return "DISCONNECTED";
    case BOWIE_NAT_STATE_GATHERING:
        return "GATHERING";
    case BOWIE_NAT_STATE_CONNECTING:
        return "CONNECTING";
    case BOWIE_NAT_STATE_CONNECTED:
        return "CONNECTED";
    case BOWIE_NAT_STATE_COMPLETED:
        return "COMPLETED";
    case BOWIE_NAT_STATE_FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 *
 * The only way a backend may call back into the core. The
 * backend must not touch the handle's fields directly.
 */

void bowie_nat_internal_set_state(bowie_nat_t      *nat,
                                  bowie_nat_state_t state)
{
    if (nat == NULL) {
        return;
    }

    if (nat->state == state) {
        return;
    }

    nat->state = state;

    if (nat->state_cb != NULL) {
        nat->state_cb(nat->state_ctx, state);
    }
}

void bowie_nat_internal_deliver(bowie_nat_t   *nat,
                                const uint8_t *data,
                                size_t         len)
{
    if (nat == NULL || data == NULL || len == 0) {
        return;
    }

    if (nat->recv != NULL) {
        nat->recv(nat->recv_ctx, data, len);
    }
}

bowie_error_t bowie_nat_internal_signal(bowie_nat_t           *nat,
                                        const bowie_peer_id_t *peer,
                                        const uint8_t         *data,
                                        size_t                 len)
{
    if (nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (nat->signal_send == NULL) {
        return BOWIE_ERR_NOT_INITIALIZED;
    }

    return nat->signal_send(nat->signal_ctx, peer, data, len);
}

/*
 * ============================================================================
 * END OF NAT CORE
 * ============================================================================
 */
