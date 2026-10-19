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
 * BOWIE — ENGINE (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine declared in engine/engine.h.
 *
 * The engine ties every layer together. It creates the DHT
 * and the NAT layer, starts them, and routes calls between
 * them and the caller.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No DHT logic. The engine starts the DHT; the DHT module
 *     does the work.
 *   - No NAT logic. The engine starts the NAT layer; the NAT
 *     module does the work.
 *   - No tunnel logic. The engine opens the tunnel; the
 *     tunnel module does the work.
 *   - No security logic. The engine creates the session; the
 *     security module does the work.
 *   - No gateway logic. The engine starts the gateway; the
 *     gateway module does the work.
 *   - No quota logic. The engine holds the quota; the quota
 *     module does the work.
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
 * Every public function locks the engine before it does
 * anything. The lock is per-engine; two engines do not share
 * it.
 *
 * The engine creates the DHT and the NAT layer when it is
 * started. It frees them when it is freed. The tunnel and the
 * gateway are supplied by the caller and are not freed by the
 * engine.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>              pthread_mutex_t
 *   <stdlib.h>               calloc, free
 *   <string.h>               memset
 *   "bowie/types.h"          types
 *   "bowie/err.h"            errors
 *   "engine/engine.h"        public declarations
 *   "engine/internal/engine.h"  internal layout
 * ============================================================================
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "engine/internal/engine.h"

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

const char *bowie_engine_state_str(bowie_engine_state_t state)
{
    switch (state) {
    case BOWIE_ENGINE_STOPPED: return "STOPPED";
    case BOWIE_ENGINE_STARTED: return "STARTED";
    case BOWIE_ENGINE_RUNNING: return "RUNNING";
    default:                   return "UNKNOWN";
    }
}

const char *bowie_engine_state_name(bowie_engine_state_t state)
{
    return bowie_engine_state_str(state);
}

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

void bowie_engine_default_config(bowie_engine_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out)
{
    bowie_engine_t *e;

    if (cfg == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    e = (bowie_engine_t *)calloc(1, sizeof(*e));

    if (e == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    if (pthread_mutex_init(&e->lock, NULL) != 0) {
        free(e);
        return BOWIE_ERR_INTERNAL;
    }

    e->cfg   = *cfg;
    e->state = BOWIE_ENGINE_STOPPED;

    *out = e;

    return BOWIE_OK;
}

void bowie_engine_free(bowie_engine_t *e)
{
    if (e == NULL) {
        return;
    }

    if (e->state != BOWIE_ENGINE_STOPPED) {
        (void)bowie_engine_stop(e);
    }

    pthread_mutex_destroy(&e->lock);
    free(e);
}

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun)
{
    if (e == NULL || tun == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_STOPPED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    e->tun = tun;

    /*
     * Placeholder: the DHT and the NAT layer are created
     * here when their modules are in place. Until then, the
     * engine is in the STARTED state with no layer behind
     * it.
     */

    e->state = BOWIE_ENGINE_STARTED;

    pthread_mutex_unlock(&e->lock);

    return BOWIE_OK;
}

bowie_error_t bowie_engine_stop(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state == BOWIE_ENGINE_STOPPED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_NOT_STARTED;
    }

    /*
     * Placeholder: the gateway, the session, the NAT layer,
     * and the DHT are stopped and freed here, in reverse
     * order of creation.
     */

    e->tun     = NULL;
    e->session = NULL;
    e->gateway = NULL;
    e->dht     = NULL;
    e->nat     = NULL;

    e->state = BOWIE_ENGINE_STOPPED;

    pthread_mutex_unlock(&e->lock);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * CONNECT / DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms)
{
    (void)timeout_ms;

    if (e == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state == BOWIE_ENGINE_STOPPED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_NOT_STARTED;
    }

    if (e->state == BOWIE_ENGINE_RUNNING) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_BUSY;
    }

    /*
     * Placeholder: the DHT lookup, the NAT connection, the
     * protocol handshake, the security check, the session
     * creation, and the gateway start all happen here when
     * their modules are in place.
     */

    e->current_peer = *peer;
    e->state        = BOWIE_ENGINE_RUNNING;

    pthread_mutex_unlock(&e->lock);

    return BOWIE_OK;
}

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);

    if (e->state != BOWIE_ENGINE_RUNNING) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }

    /*
     * Placeholder: the gateway is stopped, the session is
     * freed, and the NAT connection is closed here when
     * their modules are in place.
     */

    e->gateway = NULL;
    e->session = NULL;
    e->state   = BOWIE_ENGINE_STARTED;

    pthread_mutex_unlock(&e->lock);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ENGINE_STOPPED;
    }

    return e->state;
}

/*
 * ============================================================================
 * END OF ENGINE IMPLEMENTATION
 * ============================================================================
 */
