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
 * BOWIE — GATEWAY: CONNECTION TRACKING
 * ============================================================================
 *
 * Connection tracking for the gateway.
 *
 * The gateway needs to know which packets belong to the same
 * connection so that it can forward return traffic to the
 * right peer. A conntrack table maps a 5-tuple (source IP,
 * source port, destination IP, destination port, protocol) to
 * a peer ID.
 *
 * The table is a fixed-capacity hash map with linear probing.
 * The capacity is chosen at open time. A table that is full
 * evicts the oldest entry.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No NAT. The table records the 5-tuple as it appears on
 *     the wire; it does not rewrite addresses.
 *   - No TCP state machine. The table records that a tuple
 *     exists; it does not track SYN/FIN/RST.
 *   - No persistence. The table lives in memory.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A conntrack entry is small: two addresses, two ports, a
 * protocol byte, a peer ID, and a timestamp. A thousand
 * entries fit in well under a megabyte.
 *
 * The hash is a simple FNV-1a over the 5-tuple. The collision
 * resolution is linear probing. A table that is 75% full
 * starts to lose performance; the caller picks a capacity
 * large enough for the expected number of concurrent
 * connections.
 *
 * The table does not evict on a timer. An entry is removed
 * when the caller calls bowie_conntrack_remove() or when a
 * new entry evicts it because the table is full. A caller
 * that wants idle expiry runs a periodic sweep itself.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t, uint8_t, uint16_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_peer_id_t, bowie_addr_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_GATEWAY_CONNTRACK_H
#define BOWIE_GATEWAY_CONNTRACK_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * TYPES
 * ============================================================================
 *
 * The table is opaque. The caller owns it, never sees its
 * layout, and frees it with bowie_conntrack_close().
 *
 * The 5-tuple is a plain value struct. A caller may copy it,
 * store it, and pass it around without allocation.
 */

typedef struct bowie_conntrack_5tuple {
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} bowie_conntrack_5tuple_t;

typedef struct bowie_conntrack bowie_conntrack_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Open a conntrack table.
 *
 * The capacity is the maximum number of entries. Zero means
 * use a built-in default (1024).
 *
 * On success, *out points to the new table.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_conntrack_open(bowie_conntrack_t **out,
                                   size_t capacity);

/*
 * Close a conntrack table.
 *
 * Passing NULL is a no-op.
 */
void bowie_conntrack_close(bowie_conntrack_t *ct);

/*
 * ============================================================================
 * LOOKUP AND INSERT
 * ============================================================================
 */

/*
 * Add an entry to the table.
 *
 * If the tuple is already present, the peer ID is updated and
 * the timestamp is refreshed. If the table is full, the oldest
 * entry is evicted.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if ct or peer is NULL.
 */
bowie_error_t bowie_conntrack_add(bowie_conntrack_t *ct,
                                  const bowie_conntrack_5tuple_t *tuple,
                                  const bowie_peer_id_t *peer);

/*
 * Look up an entry by its 5-tuple.
 *
 * On success, *out_peer is filled with the peer ID and the
 * function returns 1. If the tuple is not present, the
 * function returns 0 and *out_peer is not modified.
 *
 * Returns 1 on hit, 0 on miss, and a negative bowie_error_t
 * on a NULL argument.
 */
int bowie_conntrack_lookup(const bowie_conntrack_t *ct,
                           const bowie_conntrack_5tuple_t *tuple,
                           bowie_peer_id_t *out_peer);

/*
 * Remove an entry by its 5-tuple.
 *
 * If the tuple is not present, the call is a no-op and returns
 * BOWIE_OK.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if ct or tuple is NULL.
 */
bowie_error_t bowie_conntrack_remove(bowie_conntrack_t *ct,
                                     const bowie_conntrack_5tuple_t *tuple);

/*
 * ============================================================================
 * STATISTICS
 * ============================================================================
 */

/*
 * Return the number of entries currently in the table.
 *
 * Passing NULL returns 0.
 */
size_t bowie_conntrack_count(const bowie_conntrack_t *ct);

/*
 * ============================================================================
 * END OF GATEWAY CONNTRACK
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_CONNTRACK_H */
