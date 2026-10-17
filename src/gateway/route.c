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
 * BOWIE — GATEWAY: ROUTING (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the routing helpers declared in
 * gateway/route.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No kernel routing.
 *   - No NAT.
 *   - No forwarding.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The table is a small array. A lookup walks the array and
 * compares the peer ID. With a few hundred entries the walk is
 * fast enough; an index would cost more to maintain than it
 * would save.
 *
 * The add function is idempotent: adding a peer that is
 * already present updates the interface and does not grow the
 * table. The remove function is idempotent: removing a peer
 * that is not present succeeds without changing the table.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"        types
 *   "bowie/err.h"          errors
 *   "gateway/route.h"      declarations
 * ============================================================================
 */

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/route.h"

/*
 * ============================================================================
 * INTERNAL — FIND
 * ============================================================================
 *
 * Return the index of the peer in the table, or BOWIE_ROUTE_CAP
 * if it is not present.
 */

static size_t find_route(const bowie_route_table_t *rt,
                         const bowie_peer_id_t *peer)
{
    size_t i;

    for (i = 0; i < rt->count; i++) {
        if (bowie_peer_id_equal(&rt->entries[i].peer, peer)) {
            return i;
        }
    }

    return BOWIE_ROUTE_CAP;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_route_table_clear(bowie_route_table_t *rt)
{
    if (rt == NULL) {
        return;
    }

    rt->count = 0;
}

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

bowie_error_t bowie_route_table_add(bowie_route_table_t *rt,
                                    const bowie_peer_id_t *peer,
                                    uint32_t ifindex)
{
    size_t idx;

    if (rt == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (bowie_peer_id_is_zero(peer)) {
        return BOWIE_ERR_INVAL;
    }

    idx = find_route(rt, peer);

    if (idx != BOWIE_ROUTE_CAP) {
        rt->entries[idx].ifindex = ifindex;
        return BOWIE_OK;
    }

    if (rt->count >= BOWIE_ROUTE_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    rt->entries[rt->count].peer    = *peer;
    rt->entries[rt->count].ifindex = ifindex;
    rt->count += 1;

    return BOWIE_OK;
}

bowie_error_t bowie_route_table_remove(bowie_route_table_t *rt,
                                       const bowie_peer_id_t *peer)
{
    size_t idx;

    if (rt == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = find_route(rt, peer);

    if (idx == BOWIE_ROUTE_CAP) {
        return BOWIE_OK;
    }

    /* Shift the remaining entries down by one. */
    if (idx + 1u < rt->count) {
        size_t i;
        for (i = idx; i + 1u < rt->count; i++) {
            rt->entries[i] = rt->entries[i + 1u];
        }
    }

    rt->count -= 1;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * LOOKUP
 * ============================================================================
 */

int bowie_route_table_lookup(const bowie_route_table_t *rt,
                             const bowie_peer_id_t *peer,
                             uint32_t *out_ifindex)
{
    size_t idx;

    if (rt == NULL || peer == NULL || out_ifindex == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = find_route(rt, peer);

    if (idx == BOWIE_ROUTE_CAP) {
        return 0;
    }

    *out_ifindex = rt->entries[idx].ifindex;
    return 1;
}

/*
 * ============================================================================
 * COUNT
 * ============================================================================
 */

size_t bowie_route_table_count(const bowie_route_table_t *rt)
{
    if (rt == NULL) {
        return 0;
    }

    return rt->count;
}

/*
 * ============================================================================
 * END OF GATEWAY ROUTE IMPLEMENTATION
 * ============================================================================
 */
