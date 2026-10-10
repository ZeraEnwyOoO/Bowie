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
 * BOWIE — PEER
 * ============================================================================
 *
 * A peer is a remote Bowie node: a Device, a Router, or a Box.
 *
 * The peer struct is a transparent value type. It carries the
 * identity of a remote node, the address it can be reached at,
 * the capabilities it advertises, and the last time it was
 * seen. It does not carry connection state; that is a session
 * concern and belongs to the session layer.
 *
 * The struct is fixed-size and caller-owned. It can be copied,
 * stored, and compared without allocation.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Every function operates on a caller-owned
 *     value.
 *   - No I/O. Nothing here opens a socket or sends a packet.
 *   - No connection state. Whether a peer is connected,
 *     connecting, or disconnected is a session concern, not a
 *     peer concern.
 *   - No permission. A peer advertises capabilities; it does
 *     not carry a grant. Authorization is a permission-layer
 *     concern.
 *   - No discovery. How a peer is found is a DHT concern.
 *   - No ownership. The peer struct does not own the storage
 *     of the peer ID or the public ID; it copies them.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The peer struct is deliberately small. It carries only the
 * fields that every layer above the net layer needs:
 *
 *   peer_id      identity for routing and equality
 *   public_id    identity for grant and session verification
 *   endpoint     where to reach the peer
 *   capabilities what the peer says it can do
 *   last_seen_ms when the peer was last heard from
 *
 * The peer ID is derived from the public ID by the hash
 * function in use. Both are stored, because the derivation is
 * not free and because the peer ID is what the DHT routes on.
 * A caller that trusts one but not the other must verify the
 * derivation; this header does not do that verification.
 *
 * The endpoint carries a transport tag. The tag values are
 * defined by the network layer; this header does not define
 * them. A peer with an unset endpoint has no known address and
 * cannot be reached.
 *
 * The capability mask is the same type that the configuration
 * carries. The peer operations that query capabilities use the
 * capability helpers from the net layer.
 *
 * A peer with an all-zero peer ID is unset. The functions that
 * operate on a peer treat an unset peer as "no peer"; they do
 * not fail.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t
 *   "bowie/types.h"               bowie_peer_id_t, bowie_public_id_t,
 *                                 bowie_endpoint_t, bowie_mtime_t
 *   "bowie/config.h"              bowie_cap_t
 * ============================================================================
 */

#ifndef BOWIE_NET_PEER_H
#define BOWIE_NET_PEER_H

#include <stdint.h>

#include "bowie/types.h"
#include "bowie/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * PEER
 * ============================================================================
 *
 * A remote Bowie node.
 *
 * The struct is transparent. A caller may read its fields.
 * The fields are fixed-size value types so that a peer can be
 * copied and stored without allocation.
 *
 * An all-zero peer_id means "unset". A peer with an unset
 * peer_id is not a valid peer.
 */

typedef struct bowie_peer {
    bowie_peer_id_t   peer_id;      /* derived from public_id */
    bowie_public_id_t public_id;    /* Ed25519 public key */
    bowie_endpoint_t  endpoint;     /* where to reach the peer */
    uint32_t          capabilities; /* what the peer can do */
    bowie_mtime_t     last_seen_ms; /* monotonic, milliseconds */
} bowie_peer_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a peer to the unset state.
 *
 * Every field becomes zero. The peer ID, the public ID, and
 * the endpoint all become unset. The capability mask becomes
 * BOWIE_CAP_NONE. The timestamp becomes zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_peer_clear(bowie_peer_t *peer);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * True when the peer has a set peer ID.
 *
 * A peer with an unset peer ID is not a valid peer. The
 * function returns 0 for NULL.
 */
int bowie_peer_is_set(const bowie_peer_t *peer);

/*
 * True when two peers have the same peer ID.
 *
 * Only the peer ID is compared. The endpoint, the
 * capabilities, and the timestamp may differ and the peers
 * are still equal: they identify the same remote node.
 *
 * Two NULL pointers are equal. A NULL pointer and an unset
 * peer are equal.
 */
int bowie_peer_equal(const bowie_peer_t *a, const bowie_peer_t *b);

/*
 * True when the peer advertises the given capability.
 *
 * A NULL peer or an unset peer has no capabilities and
 * returns 0 for every flag.
 */
int bowie_peer_has_cap(const bowie_peer_t *peer, bowie_cap_t cap);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Set the peer ID of a peer.
 *
 * The peer ID is copied. The caller may free the source after
 * the call returns.
 *
 * Passing NULL for peer is a no-op.
 */
void bowie_peer_set_id(bowie_peer_t *peer,
                       const bowie_peer_id_t *id);

/*
 * Set the public ID of a peer.
 *
 * The public ID is copied. The caller may free the source
 * after the call returns.
 *
 * Passing NULL for peer is a no-op.
 */
void bowie_peer_set_public_id(bowie_peer_t *peer,
                              const bowie_public_id_t *public_id);

/*
 * Set the endpoint of a peer.
 *
 * The endpoint is copied. The caller may free the source
 * after the call returns.
 *
 * Passing NULL for peer is a no-op.
 */
void bowie_peer_set_endpoint(bowie_peer_t *peer,
                             const bowie_endpoint_t *endpoint);

/*
 * Set the capability mask of a peer.
 *
 * The mask is copied. Unknown bits are not stripped; a caller
 * that wants a valid mask uses bowie_cap_mask_is_valid() from
 * the net layer before calling this function.
 *
 * Passing NULL for peer is a no-op.
 */
void bowie_peer_set_capabilities(bowie_peer_t *peer,
                                 uint32_t mask);

/*
 * Set the last-seen timestamp of a peer.
 *
 * The timestamp is a monotonic value in milliseconds.
 *
 * Passing NULL for peer is a no-op.
 */
void bowie_peer_set_last_seen(bowie_peer_t *peer,
                              bowie_mtime_t last_seen_ms);

/*
 * ============================================================================
 * END OF PEER
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_NET_PEER_H */
