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
 * BOWIE — PEER IMPLEMENTATION
 * ============================================================================
 *
 * Value operations for the peer struct.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O.
 *   - No connection state.
 *   - No permission.
 *   - No discovery.
 *   - No ownership.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every function is a pure value operation. The struct is
 * copied field by field, using the helpers from bowie/types.h
 * where one exists.
 *
 * The peer ID and the public ID are copied with memcpy()
 * rather than by struct assignment, so that the copy is
 * explicit and does not depend on the struct layout. The two
 * are the same size on every platform Bowie targets, but the
 * explicit copy is clearer.
 *
 * The endpoint is copied with memcpy() for the same reason.
 *
 * The capability mask and the timestamp are plain values and
 * are assigned directly.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              the field types
 *   "bowie/config.h"             bowie_cap_t, BOWIE_CAP_NONE
 *   "net/peer.h"                 the declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/config.h"
#include "net/peer.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_peer_clear(bowie_peer_t *peer)
{
    if (peer == NULL) {
        return;
    }
    memset(peer, 0, sizeof(*peer));
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

int bowie_peer_is_set(const bowie_peer_t *peer)
{
    if (peer == NULL) {
        return 0;
    }
    return bowie_peer_id_is_zero(&peer->peer_id) ? 0 : 1;
}

int bowie_peer_equal(const bowie_peer_t *a, const bowie_peer_t *b)
{
    /*
     * A NULL pointer is treated as an unset peer. Two NULL
     * pointers are equal. A NULL pointer and an unset peer
     * are equal.
     */
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_peer_id_t zero;
    bowie_peer_id_clear(&zero);

    const bowie_peer_id_t *id_a = (a != NULL) ? &a->peer_id : &zero;
    const bowie_peer_id_t *id_b = (b != NULL) ? &b->peer_id : &zero;

    return bowie_peer_id_equal(id_a, id_b);
}

int bowie_peer_has_cap(const bowie_peer_t *peer, bowie_cap_t cap)
{
    if (peer == NULL) {
        return 0;
    }
    return bowie_cap_has(peer->capabilities, cap);
}

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

void bowie_peer_set_id(bowie_peer_t *peer,
                       const bowie_peer_id_t *id)
{
    if (peer == NULL || id == NULL) {
        return;
    }
    memcpy(&peer->peer_id, id, sizeof(peer->peer_id));
}

void bowie_peer_set_public_id(bowie_peer_t *peer,
                              const bowie_public_id_t *public_id)
{
    if (peer == NULL || public_id == NULL) {
        return;
    }
    memcpy(&peer->public_id, public_id, sizeof(peer->public_id));
}

void bowie_peer_set_endpoint(bowie_peer_t *peer,
                             const bowie_endpoint_t *endpoint)
{
    if (peer == NULL || endpoint == NULL) {
        return;
    }
    memcpy(&peer->endpoint, endpoint, sizeof(peer->endpoint));
}

void bowie_peer_set_capabilities(bowie_peer_t *peer, uint32_t mask)
{
    if (peer == NULL) {
        return;
    }
    peer->capabilities = mask;
}

void bowie_peer_set_last_seen(bowie_peer_t *peer,
                              bowie_mtime_t last_seen_ms)
{
    if (peer == NULL) {
        return;
    }
    peer->last_seen_ms = last_seen_ms;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
