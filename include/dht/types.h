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
 * BOWIE — DHT TYPES
 * ============================================================================
 *
 * Foundational data types for the DHT layer.
 *
 * The DHT is a Mainline-compatible Kademlia implementation. It
 * uses 160-bit identifiers, XOR distance, and the Mainline
 * message format. These types are the building blocks for the
 * routing table, the message layer, and the storage layer.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No functions. This header declares types only. Functions
 *     that operate on these types are declared in the headers
 *     that own the relevant capability.
 *   - No network. Nothing here touches a socket.
 *   - No allocation. Every type is a fixed-size value type.
 *   - No policy. Whether a node ID is "good", how a bucket is
 *     split, and how a lookup proceeds are policy decisions
 *     made by the layer that owns them.
 *   - No deployment mode. A DHT node is a DHT node whether it
 *     runs on a phone, a router, or a Box. This header does
 *     not distinguish them.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The DHT uses four identifiers:
 *
 *   - Node ID. 160 bits. Identifies a node in the DHT. Chosen
 *     randomly when a node starts, or derived from a stable
 *     key. Two nodes with the same ID are the same node.
 *
 *   - Info Hash. 160 bits. Identifies a value in the DHT. For
 *     a BitTorrent-compatible DHT, it is the SHA-1 of the
 *     torrent's info dictionary. For Bowie, it is the SHA-1 of
 *     whatever the value describes.
 *
 *   - Token. Variable length, up to 32 bytes. A short opaque
 *     value that a node hands out and later checks. It is not
 *     a cryptographic key; it is a way to make a node prove
 *     that it can receive at the address it claims.
 *
 *   - Distance. 160 bits. The XOR of two node IDs, or of a
 *     node ID and an info hash. It is used to order nodes by
 *     closeness. A distance is not an address; it is a value
 *     in the same 160-bit space as the IDs.
 *
 * All four are fixed-size value types. A caller can copy,
 * compare, and store them without allocation.
 *
 * The node ID length matches the peer ID length in
 * bowie/types.h. They are the same size because both match the
 * DHT identifier space. They are not the same type: a peer ID
 * identifies a Bowie peer, and a DHT node ID identifies a DHT
 * node. A peer may be a DHT node, but the two identities are
 * separate and may differ.
 *
 * A node ID, an info hash, or a distance with all bytes zero
 * is reserved and means "unset". A token with length zero is
 * unset. Functions that produce one of these values must not
 * produce an unset value as a valid result.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t
 *   <stddef.h>                    size_t
 * ============================================================================
 */

#ifndef BOWIE_DHT_TYPES_H
#define BOWIE_DHT_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * NODE ID
 * ============================================================================
 *
 * 160 bits. Identifies a node in the DHT.
 *
 * The value is chosen when the node starts. It may be random,
 * or it may be derived from a stable key. The DHT does not
 * care which, as long as the value is unique within the
 * network.
 *
 * An all-zero node ID is reserved and means "unset".
 */

#define BOWIE_DHT_NODE_ID_LEN 20

typedef struct bowie_dht_node_id {
    uint8_t bytes[BOWIE_DHT_NODE_ID_LEN];
} bowie_dht_node_id_t;

/*
 * ============================================================================
 * INFO HASH
 * ============================================================================
 *
 * 160 bits. Identifies a value in the DHT.
 *
 * For a BitTorrent-compatible DHT, the info hash is the SHA-1
 * of the torrent's info dictionary. For Bowie, it is the
 * SHA-1 of whatever the value describes. The DHT does not
 * interpret the value; it only stores and retrieves it.
 *
 * An all-zero info hash is reserved and means "unset".
 */

#define BOWIE_DHT_INFO_HASH_LEN 20

typedef struct bowie_dht_info_hash {
    uint8_t bytes[BOWIE_DHT_INFO_HASH_LEN];
} bowie_dht_info_hash_t;

/*
 * ============================================================================
 * TOKEN
 * ============================================================================
 *
 * A short opaque value, up to 32 bytes, that a node hands out
 * and later checks.
 *
 * The token is not a cryptographic key. It is a way to make a
 * node prove that it can receive at the address it claims. A
 * node that wants to store a value under an info hash must
 * first ask the target node for a token, and then include that
 * token in the store request. The target node checks that the
 * token matches the address the request came from.
 *
 * The length is stored separately because the token is
 * variable-length. A token with length zero is unset.
 *
 * The maximum length is 32 bytes. Mainline uses shorter
 * tokens; the extra room is for future use and for other
 * DHT variants that use longer tokens.
 */

#define BOWIE_DHT_TOKEN_MAX 32

typedef struct bowie_dht_token {
    uint8_t bytes[BOWIE_DHT_TOKEN_MAX];
    size_t  len;
} bowie_dht_token_t;

/*
 * ============================================================================
 * DISTANCE
 * ============================================================================
 *
 * 160 bits. The XOR of two node IDs, or of a node ID and an
 * info hash.
 *
 * The distance is used to order nodes by closeness. A distance
 * is not an address; it is a value in the same 160-bit space
 * as the IDs.
 *
 * A distance of zero means the two values are equal. An
 * all-zero distance is the closest possible distance, not an
 * unset value. The "unset" convention does not apply to a
 * distance; a distance is always meaningful.
 */

#define BOWIE_DHT_DISTANCE_LEN 20

typedef struct bowie_dht_distance {
    uint8_t bytes[BOWIE_DHT_DISTANCE_LEN];
} bowie_dht_distance_t;

/*
 * ============================================================================
 * TYPE HELPERS
 * ============================================================================
 *
 * Small value operations on the types in this header. These
 * are the operations that every DHT module needs and that
 * would otherwise be reimplemented in each module.
 *
 * The helpers are grouped by type. Each group follows the same
 * shape:
 *
 *   _clear()    zero the value
 *   _is_zero()  true when the value is unset
 *   _equal()    true when two values are equal
 *
 * A distance does not have an _is_zero() helper, because a
 * zero distance is a valid distance, not an unset value.
 *
 * No helper here allocates, performs I/O, or depends on a
 * platform. Every one is a pure value operation.
 *
 * Helpers whose semantics depend on a policy decision
 * (hashing, ordering, string formatting) are NOT declared
 * here. They are added by the module that owns the policy.
 */

/*
 * ----------------------------------------------------------------------------
 * Node ID
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a node ID to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_node_id_clear(bowie_dht_node_id_t *id);

/*
 * True when every byte of the node ID is zero.
 *
 * A NULL pointer is treated as zero, so the function returns
 * true for NULL.
 */
int bowie_dht_node_id_is_zero(const bowie_dht_node_id_t *id);

/*
 * True when two node IDs have the same bytes.
 *
 * Two NULL pointers are equal. A NULL pointer and a zero ID
 * are equal.
 */
int bowie_dht_node_id_equal(const bowie_dht_node_id_t *a,
                            const bowie_dht_node_id_t *b);

/*
 * ----------------------------------------------------------------------------
 * Info Hash
 * ----------------------------------------------------------------------------
 */

/*
 * Reset an info hash to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_info_hash_clear(bowie_dht_info_hash_t *h);

/*
 * True when every byte of the info hash is zero.
 *
 * A NULL pointer is treated as zero, so the function returns
 * true for NULL.
 */
int bowie_dht_info_hash_is_zero(const bowie_dht_info_hash_t *h);

/*
 * True when two info hashes have the same bytes.
 *
 * Two NULL pointers are equal. A NULL pointer and a zero hash
 * are equal.
 */
int bowie_dht_info_hash_equal(const bowie_dht_info_hash_t *a,
                              const bowie_dht_info_hash_t *b);

/*
 * ----------------------------------------------------------------------------
 * Token
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a token to the unset state.
 *
 * The length becomes zero. The bytes are not required to be
 * zero, but they are cleared so that a caller cannot
 * accidentally use stale bytes with a zero length.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_token_clear(bowie_dht_token_t *t);

/*
 * True when the token has zero length.
 *
 * A NULL pointer is treated as unset, so the function returns
 * true for NULL.
 */
int bowie_dht_token_is_zero(const bowie_dht_token_t *t);

/*
 * True when two tokens have the same length and the same
 * bytes.
 *
 * Two unset tokens are equal. A NULL pointer and an unset
 * token are equal.
 *
 * The comparison is byte-wise over the declared length. The
 * trailing bytes beyond the length are not compared.
 */
int bowie_dht_token_equal(const bowie_dht_token_t *a,
                          const bowie_dht_token_t *b);

/*
 * ----------------------------------------------------------------------------
 * Distance
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a distance to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_distance_clear(bowie_dht_distance_t *d);

/*
 * True when two distances have the same bytes.
 *
 * Two NULL pointers are equal.
 */
int bowie_dht_distance_equal(const bowie_dht_distance_t *a,
                             const bowie_dht_distance_t *b);

/*
 * ============================================================================
 * END OF DHT TYPES
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_TYPES_H */
