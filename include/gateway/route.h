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
 * BOWIE — GATEWAY: ROUTING
 * ============================================================================
 *
 * Routing table management for the gateway.
 *
 * The gateway needs to know, for each packet it sees, whether
 * the packet should go out to the Internet or back to a peer.
 * This module provides a small routing table that maps a peer
 * ID to the interface that should be used for that peer.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No kernel routing. The kernel routing table is separate
 *     and is the caller's responsibility.
 *   - No NAT. Address translation is a separate concern.
 *   - No forwarding. This module only decides where a packet
 *     should go; the gateway does the actual forwarding.
 *   - No IPv6 routing. The table holds IPv4 routes; IPv6
 *     support is a later version.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The routing table is a small array of entries. Each entry
 * names a peer and the interface that leads to that peer. A
 * lookup walks the array; with a few hundred entries the walk
 * is fast enough and needs no index.
 *
 * A route is added when a peer connects and removed when the
 * peer disconnects. The table is not shared between gateways;
 * each gateway has its own.
 *
 * An entry with an unset peer ID is not a route. A lookup for
 * an unset peer returns "not found".
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

#ifndef BOWIE_GATEWAY_ROUTE_H
#define BOWIE_GATEWAY_ROUTE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

#define BOWIE_ROUTE_CAP 256

/*
 * ============================================================================
 * TYPES
 * ============================================================================
 *
 * The route table is a value type. It can be copied and stored
 * without allocation. The entries are fixed-size.
 *
 * The interface field is a small integer. The meaning of the
 * integer is defined by the caller. A route that maps a peer
 * to interface 1 is a route that says "this peer goes out
 * interface 1".
 */

typedef struct bowie_route {
    bowie_peer_id_t peer;
    uint32_t        ifindex;
} bowie_route_t;

typedef struct bowie_route_table {
    bowie_route_t entries[BOWIE_ROUTE_CAP];
    size_t        count;
} bowie_route_table_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a route table to empty.
 *
 * Passing NULL is a no-op.
 */
void bowie_route_table_clear(bowie_route_table_t *rt);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Add a route to the table.
 *
 * If the peer is already present, the interface is updated.
 * If the table is full, the call fails with
 * BOWIE_ERR_TOO_LARGE.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if rt is NULL.
 * Returns BOWIE_ERR_INVAL if the peer ID is unset.
 * Returns BOWIE_ERR_TOO_LARGE if the table is full.
 */
bowie_error_t bowie_route_table_add(bowie_route_table_t *rt,
                                    const bowie_peer_id_t *peer,
                                    uint32_t ifindex);

/*
 * Remove a route from the table.
 *
 * If the peer is not present, the call is a no-op and returns
 * BOWIE_OK.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if rt is NULL.
 */
bowie_error_t bowie_route_table_remove(bowie_route_table_t *rt,
                                       const bowie_peer_id_t *peer);

/*
 * ============================================================================
 * LOOKUP
 * ============================================================================
 */

/*
 * Look up a route by peer ID.
 *
 * On success, *out_ifindex is filled and the function returns
 * 1. If the peer is not present, the function returns 0 and
 * *out_ifindex is not modified.
 *
 * Returns 1 on hit, 0 on miss, and a negative bowie_error_t
 * on a NULL argument.
 */
int bowie_route_table_lookup(const bowie_route_table_t *rt,
                             const bowie_peer_id_t *peer,
                             uint32_t *out_ifindex);

/*
 * Return the number of routes in the table.
 *
 * Passing NULL returns 0.
 */
size_t bowie_route_table_count(const bowie_route_table_t *rt);

/*
 * ============================================================================
 * END OF GATEWAY ROUTE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_ROUTE_H */
