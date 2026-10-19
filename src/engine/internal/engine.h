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
 * BOWIE — ENGINE (INTERNAL)
 * ============================================================================
 *
 * Internal definitions for the engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No public API. This header must not be included by
 *     anything outside src/engine/.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The struct bowie_engine is defined here, not in the public
 * header, because the caller never sees its layout.
 *
 * The engine owns the DHT, the NAT layer, the session, and
 * the gateway. It borrows the tunnel and the quota.
 *
 * The engine also holds the DHT search state and the
 * handshake state, which are used during connection.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t
 *   <stddef.h>              size_t
 *   <pthread.h>             pthread_mutex_t
 *   "bowie/types.h"         bowie_engine_t, bowie_peer_id_t
 *   "bowie/err.h"           bowie_error_t
 *   "engine/engine.h"       bowie_engine_config_t,
 *                           bowie_engine_state_t
 *   "dht/dht.h"             bowie_dht_t
 *   "dht/search.h"          bowie_dht_search_t
 *   "proto/handshake.h"     bowie_proto_handshake_t
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_ENGINE_H
#define BOWIE_ENGINE_INTERNAL_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "dht/dht.h"
#include "dht/search.h"
#include "proto/handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ENGINE STRUCT
 * ============================================================================
 */

struct bowie_engine {
    bowie_engine_config_t cfg;
    bowie_engine_state_t  state;

    bowie_dht_t           dht;
    bowie_dht_search_t    dht_search;

    bowie_nat_t          *nat;
    bowie_tun_t          *tun;

    bowie_proto_handshake_t handshake;

    bowie_session_t      *session;
    bowie_gateway_t      *gateway;

    bowie_peer_id_t       current_peer;

    bowie_quota_t        *quota;

    pthread_mutex_t       lock;
};

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

const char *bowie_engine_state_str(bowie_engine_state_t state);

/*
 * ============================================================================
 * END OF INTERNAL ENGINE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_ENGINE_H */
