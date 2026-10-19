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
 * BOWIE — GATEWAY: LIMIT
 * ============================================================================
 *
 * Connection limit for the gateway.
 *
 * The gateway tracks how many connections each peer has open.
 * A peer that exceeds its limit is not allowed to open more.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No rate limiting on packets. That is a shaping concern.
 *   - No persistence.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The limit is a per-peer counter. The gateway calls
 * bowie_limit_acquire() when a connection opens and
 * bowie_limit_release() when it closes. If acquire returns
 * BOWIE_ERR_QUOTA, the gateway refuses the connection.
 *
 * The table is fixed-capacity. A peer that is not in the
 * table has no limit; it can open as many connections as it
 * wants. A caller that wants a global limit adds a special
 * peer entry for "everyone".
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_peer_id_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_GATEWAY_LIMIT_H
#define BOWIE_GATEWAY_LIMIT_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOWIE_LIMIT_CAP 64

typedef struct bowie_limit {
    bowie_peer_id_t peer[BOWIE_LIMIT_CAP];
    uint32_t        max_conn[BOWIE_LIMIT_CAP];
    uint32_t        cur_conn[BOWIE_LIMIT_CAP];
    size_t          count;
} bowie_limit_t;

void bowie_limit_clear(bowie_limit_t *l);

bowie_error_t bowie_limit_set(bowie_limit_t *l,
                              const bowie_peer_id_t *peer,
                              uint32_t max_connections);

bowie_error_t bowie_limit_acquire(bowie_limit_t *l,
                                  const bowie_peer_id_t *peer);

bowie_error_t bowie_limit_release(bowie_limit_t *l,
                                  const bowie_peer_id_t *peer);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_LIMIT_H */
