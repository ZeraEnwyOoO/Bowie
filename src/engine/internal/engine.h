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
 * The public header (include/engine/engine.h) declares the
 * contract that callers use. This header declares the full
 * struct that the engine's implementation needs, and the
 * helper functions that the engine's source files share.
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
 * header, because the caller never sees its layout. The
 * caller owns the handle but never reaches into it.
 *
 * The engine holds its layers by pointer. The DHT and the NAT
 * layer are created by the engine and freed by the engine.
 * The tunnel and the gateway are supplied by the caller and
 * are not freed by the engine.
 *
 * The state field mirrors the public state enum. It is updated
 * under the engine's lock.
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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================
 *
 * The engine holds pointers to layers. The layers are
 * forward-declared here; their headers are included by the
 * source files that need them.
 */

typedef struct bowie_dht      bowie_dht_t;
typedef struct bowie_nat      bowie_nat_t;
typedef struct bowie_session  bowie_session_t;
typedef struct bowie_gateway  bowie_gateway_t;
typedef struct bowie_quota    bowie_quota_t;

/*
 * ============================================================================
 * ENGINE STRUCT
 * ============================================================================
 *
 * The full layout of an engine. Callers see only the
 * forward declaration in bowie/types.h.
 *
 * The engine owns:
 *
 *   - the DHT (created by start, freed by free)
 *   - the NAT layer (created by start, freed by free)
 *   - the session (created by connect, freed by disconnect)
 *   - the gateway (created by connect, freed by disconnect)
 *
 * The engine borrows:
 *
 *   - the tunnel (supplied at start, not freed by the engine)
 *   - the quota (supplied by the caller, not freed by the
 *     engine)
 *
 * The lock serializes every public call. The engine is not
 * thread-safe from the caller's point of view; the lock keeps
 * its own internal state consistent.
 */

struct bowie_engine {
    bowie_engine_config_t cfg;
    bowie_engine_state_t  state;

    bowie_dht_t          *dht;
    bowie_nat_t          *nat;
    bowie_tun_t          *tun;

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
 *
 * Small helpers used by engine.c and its siblings. They are
 * declared here, not in the public header, because only the
 * engine uses them.
 */

/*
 * Return a stable, human-readable string for an engine state.
 *
 * The pointer is to a static string and must not be freed.
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
