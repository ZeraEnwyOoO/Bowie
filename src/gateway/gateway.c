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
 * BOWIE — GATEWAY (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the gateway declared in gateway/gateway.h.
 *
 * The gateway is a small loop that moves packets between the
 * tunnel and the Internet. The loop runs in its own thread
 * while the gateway is started.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No tunnel. The tunnel is supplied at open time.
 *   - No permission. The caller has already authorized the
 *     session at layer 7.
 *   - No NAT. The host does that.
 *   - No route or conntrack logic. Those are declared in
 *     gateway/route.h and gateway/conntrack.h and will be
 *     implemented in their own files. This file only calls
 *     them.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The gateway is opened once and started for each peer. A
 * single gateway can be started and stopped many times, with a
 * different session each time.
 *
 * The forwarding loop is a thread. It reads from the tunnel,
 * forwards to the Internet, and on the return path reads from
 * the Internet and forwards to the tunnel. The exact shape of
 * the read and write depends on the route and conntrack
 * modules, which this file calls but does not implement.
 *
 * Until route.c and conntrack.c exist, the loop is a no-op
 * that sleeps. This lets the rest of the gateway (open, close,
 * start, stop, stats) work and be tested. A real forwarding
 * loop is added when the other modules are in place.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>              pthread_t, pthread_mutex_t
 *   <stdlib.h>               calloc, free
 *   <string.h>               memset
 *   <unistd.h>               usleep
 *   "bowie/types.h"          types
 *   "bowie/err.h"            errors
 *   "gateway/gateway.h"      declarations
 * ============================================================================
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/gateway.h"

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 */

struct bowie_gateway {
    bowie_gateway_config_t cfg;
    bowie_tun_t           *tun;
    bowie_session_t       *session;

    int                    started;

    pthread_t              thread;
    pthread_mutex_t        lock;
    int                    stop_requested;

    bowie_gateway_stats_t  stats;
};

/*
 * ============================================================================
 * FORWARDING LOOP (placeholder)
 * ============================================================================
 *
 * Until route.c and conntrack.c exist, the loop only sleeps
 * and checks the stop flag. The stats block is not updated;
 * a later version updates it as packets move.
 */

static void *forward_loop(void *arg)
{
    bowie_gateway_t *gw = (bowie_gateway_t *)arg;

    while (1) {
        int stop;

        pthread_mutex_lock(&gw->lock);
        stop = gw->stop_requested;
        pthread_mutex_unlock(&gw->lock);

        if (stop) {
            break;
        }

        /* Placeholder: no packets are moved yet. */
        usleep(100000);
    }

    return NULL;
}

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

void bowie_gateway_default_config(bowie_gateway_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->mtu                 = 0;
    cfg->conntrack_capacity  = 0;
    cfg->allow_private       = 0;
    cfg->allow_ipv6          = 0;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_gateway_open(bowie_gateway_t              **out,
                                  const bowie_gateway_config_t  *cfg,
                                  bowie_tun_t                   *tun)
{
    bowie_gateway_t *gw;

    if (out == NULL || cfg == NULL || tun == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (cfg->allow_private != 0 && cfg->allow_private != 1) {
        return BOWIE_ERR_INVAL;
    }
    if (cfg->allow_ipv6 != 0 && cfg->allow_ipv6 != 1) {
        return BOWIE_ERR_INVAL;
    }

    gw = (bowie_gateway_t *)calloc(1, sizeof(*gw));

    if (gw == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    if (pthread_mutex_init(&gw->lock, NULL) != 0) {
        free(gw);
        return BOWIE_ERR_INTERNAL;
    }

    gw->cfg     = *cfg;
    gw->tun     = tun;
    gw->session = NULL;
    gw->started = 0;
    gw->stop_requested = 0;

    *out = gw;

    return BOWIE_OK;
}

void bowie_gateway_close(bowie_gateway_t *gw)
{
    if (gw == NULL) {
        return;
    }

    if (gw->started) {
        (void)bowie_gateway_stop(gw);
    }

    pthread_mutex_destroy(&gw->lock);
    free(gw);
}

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

bowie_error_t bowie_gateway_start(bowie_gateway_t *gw,
                                   bowie_session_t *session)
{
    if (gw == NULL || session == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (gw->started) {
        return BOWIE_ERR_STATE;
    }

    gw->session        = session;
    gw->stop_requested = 0;

    if (pthread_create(&gw->thread, NULL, forward_loop, gw) != 0) {
        gw->session = NULL;
        return BOWIE_ERR_INTERNAL;
    }

    gw->started = 1;

    return BOWIE_OK;
}

bowie_error_t bowie_gateway_stop(bowie_gateway_t *gw)
{
    if (gw == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!gw->started) {
        return BOWIE_ERR_NOT_STARTED;
    }

    pthread_mutex_lock(&gw->lock);
    gw->stop_requested = 1;
    pthread_mutex_unlock(&gw->lock);

    pthread_join(gw->thread, NULL);

    gw->started = 0;
    gw->session = NULL;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STATISTICS
 * ============================================================================
 */

void bowie_gateway_stats(const bowie_gateway_t *gw,
                         bowie_gateway_stats_t *out)
{
    if (gw == NULL || out == NULL) {
        return;
    }

    *out = gw->stats;
}

/*
 * ============================================================================
 * END OF GATEWAY IMPLEMENTATION
 * ============================================================================
 */
