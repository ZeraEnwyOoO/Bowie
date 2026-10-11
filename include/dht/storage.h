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
 * BOWIE — DHT STORAGE
 * ============================================================================
 *
 * The key-value storage for the DHT: an info hash maps to a
 * list of peers that can serve it.
 *
 * The storage is a value type. The caller supplies the arrays
 * that hold the entries. There is no allocation.
 *
 * The storage is the part of the DHT that answers:
 *
 *   "Who can serve the value with this info hash?"
 *
 * The answer is a list of peers. Each peer carries its
 * address, its capabilities, and the time it was last seen.
 * A caller that needs a SOURCE peer filters the list by the
 * SOURCE capability.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network. The storage does not send or receive
 *     packets.
 *   - No allocation. The caller supplies the arrays.
 *   - No persistence. The storage is in-memory only. A node
 *     that restarts loses its storage.
 *   - No policy on which peers to accept. The DHT layer
 *     decides whether an announce is allowed; the storage
 *     just records it.
 *   - No search. The lookup algorithm is in search.h.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The storage has two arrays:
 *
 *   hashes   the info hashes, each with a range of peer
 *            entries
 *   peers    the peer entries, stored contiguously
 *
 * A hash entry stores the index of its first peer and the
 * count. The peers for a hash are stored contiguously, in the
 * order they were added. A peer that is removed leaves a hole;
 * the storage compacts the peer array on the next removal of
 * the same hash, or on a call to the expire function.
 *
 * The metadata is an optional third array, parallel to the
 * peer array. A storage with metadata disabled has a NULL
 * metadata array; the code checks the flag before reading it.
 * The metadata array is not required to be the same size as
 * the peer array when metadata is disabled.
 *
 * A peer is identified by its address, not by its peer ID.
 * Two peers with the same address are the same peer. This is
 * the Mainline rule: a node's identity in the DHT is its
 * address, and the node ID is used only for routing.
 *
 * A peer entry expires. The expiry time is set when the peer
 * is added and refreshed when the peer is seen again. The
 * expire function removes the expired entries. The DHT layer
 * calls expire periodically; the storage does not have a
 * timer of its own.
 *
 * The storage is not thread-safe. The caller must serialize
 * access. The DHT engine, which knows how many threads it
 * has, is the right place to make the thread-safety decision.
 *
 * ----------------------------------------------------------------------------
 * Capacity
 * ----------------------------------------------------------------------------
 *
 * The caller supplies the capacities. A router with little
 * RAM uses small capacities. A box with more RAM uses larger
 * ones. The storage does not allocate; a capacity that is too
 * small for the caller's needs is reported as
 * BOWIE_ERR_TOO_SMALL, and the caller decides what to do.
 *
 * The default capacities are policy, not part of the storage.
 * A caller that wants the defaults uses the values in the
 * config struct.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t, uint8_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "bowie/config.h"             bowie_cap_t
 *   "dht/types.h"                info hash
 * ============================================================================
 */

#ifndef BOWIE_DHT_STORAGE_H
#define BOWIE_DHT_STORAGE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/config.h"
#include "dht/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

#define BOWIE_DHT_STORAGE_DEFAULT_MAX_HASHES         256
#define BOWIE_DHT_STORAGE_DEFAULT_MAX_PEERS_PER_HASH   16
#define BOWIE_DHT_STORAGE_DEFAULT_PEER_LIFETIME_S    3600u

/*
 * ============================================================================
 * PEER METADATA
 * ============================================================================
 *
 * Optional information about a peer. The metadata is stored
 * only when the storage is configured to keep it. A storage
 * with metadata disabled does not read or write this struct.
 *
 * The fields are advisory. They are not security properties
 * and are not verified. A caller that uses them must treat
 * them as hints.
 */

typedef struct bowie_dht_peer_metadata {
    uint32_t bandwidth_kbps;
    uint16_t latency_ms;
    uint8_t  reliability;
} bowie_dht_peer_metadata_t;

/*
 * ============================================================================
 * PEER ENTRY
 * ============================================================================
 *
 * One peer that can serve a value. The entry is a value type.
 *
 * The "capabilities" field is the same bitmask that the peer
 * advertises in the configuration. A caller that needs a
 * SOURCE peer checks the SOURCE bit.
 *
 * The "last_seen_ms" is the monotonic time of the most recent
 * response. The "expires_at_ms" is the monotonic time after
 * which the entry is stale. A peer that is seen again has its
 * expiry refreshed.
 *
 * The address is the identity of the peer in the storage. Two
 * entries with the same address are the same peer.
 */

typedef struct bowie_dht_peer_entry {
    bowie_addr_t    addr;
    uint32_t        capabilities;
    bowie_mtime_t   last_seen_ms;
    bowie_mtime_t   expires_at_ms;
} bowie_dht_peer_entry_t;

/*
 * ============================================================================
 * HASH ENTRY
 * ============================================================================
 *
 * One info hash and its peers. The entry is a value type.
 *
 * The "first" field is the index of the first peer in the
 * storage's peer array. The "count" field is the number of
 * peers. The peers are stored contiguously.
 *
 * A hash entry with count == 0 has no peers; the first index
 * is unspecified.
 */

typedef struct bowie_dht_hash_entry {
    bowie_dht_info_hash_t hash;
    size_t                first;
    size_t                count;
} bowie_dht_hash_entry_t;

/*
 * ============================================================================
 * STORAGE CONFIG
 * ============================================================================
 *
 * The caller fills this struct and passes it to the init
 * function. The storage copies the fields it needs.
 *
 * A zeroed config is valid; the init function fills in the
 * defaults.
 */

typedef struct bowie_dht_storage_config {
    /*
     * The maximum number of distinct info hashes the storage
     * holds. A new hash that does not fit is rejected.
     */
    size_t   max_hashes;

    /*
     * The maximum number of peers per info hash. A new peer
     * that does not fit is rejected.
     */
    size_t   max_peers_per_hash;

    /*
     * The lifetime of a peer entry, in seconds. A peer whose
     * last_seen is older than this is expired.
     */
    uint32_t peer_lifetime_s;

    /*
     * When non-zero, the storage keeps the optional metadata
     * for each peer. When zero, the metadata array is not
     * required and is not touched.
     */
    int      store_metadata;
} bowie_dht_storage_config_t;

/*
 * ============================================================================
 * STORAGE
 * ============================================================================
 *
 * The storage. The caller supplies the arrays.
 *
 * The arrays are:
 *
 *   hashes       the info hashes, up to hashes_cap
 *   peers        the peer entries, up to peers_cap
 *   metadata     the peer metadata, parallel to peers
 *
 * The metadata array is optional. When store_metadata is 0,
 * the metadata pointer may be NULL; the code does not touch
 * it.
 *
 * The peers array is shared by all hashes. A hash's peers are
 * a contiguous range of the array. When a hash's peers are
 * removed, the storage compacts the array by shifting the
 * later peers down. The hash entries that follow are updated
 * to point at their new first index.
 *
 * The struct is a value type. It is stored in the DHT engine
 * and copied with the engine.
 */

typedef struct bowie_dht_storage {
    bowie_dht_hash_entry_t    *hashes;
    size_t                     hashes_cap;
    size_t                     hashes_used;

    bowie_dht_peer_entry_t    *peers;
    size_t                     peers_cap;
    size_t                     peers_used;

    bowie_dht_peer_metadata_t *metadata;

    bowie_dht_storage_config_t config;
} bowie_dht_storage_t;

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

/*
 * Fill a config with the library defaults.
 *
 * The caller's values are preserved if they are non-zero; the
 * zero fields are filled with the defaults.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_dht_storage_config_defaults(
    bowie_dht_storage_config_t *cfg);

/*
 * ============================================================================
 * PEER ENTRY
 * ============================================================================
 */

/*
 * Reset a peer entry to the unset state.
 *
 * Every field becomes zero. The address is unset, the
 * capabilities are BOWIE_CAP_NONE, and the times are zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_peer_entry_clear(bowie_dht_peer_entry_t *e);

/*
 * True when the peer entry has a set address.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_peer_entry_is_set(const bowie_dht_peer_entry_t *e);

/*
 * True when the peer entry advertises the given capability.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_peer_entry_has_cap(const bowie_dht_peer_entry_t *e,
                                 bowie_cap_t cap);

/*
 * True when the peer entry has expired at the given time.
 *
 * An entry whose expires_at_ms is zero has never been seen
 * and is treated as expired. An entry whose expires_at_ms is
 * in the past relative to now_ms is expired.
 *
 * Returns 1 for NULL.
 */
int bowie_dht_peer_entry_is_expired(
    const bowie_dht_peer_entry_t *e, bowie_mtime_t now_ms);

/*
 * True when two peer entries refer to the same peer.
 *
 * The comparison is by address. Two entries with the same
 * address are equal, even if their capabilities or timestamps
 * differ.
 *
 * Two NULL pointers are equal. A NULL pointer and an unset
 * entry are equal.
 */
int bowie_dht_peer_entry_equal(const bowie_dht_peer_entry_t *a,
                               const bowie_dht_peer_entry_t *b);

/*
 * ============================================================================
 * METADATA
 * ============================================================================
 */

/*
 * Reset a metadata struct to zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_peer_metadata_clear(bowie_dht_peer_metadata_t *m);

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a storage with a config and caller-supplied
 * arrays.
 *
 * The config is copied. The zero fields are filled with the
 * defaults before the copy.
 *
 * The caller supplies:
 *
 *   hashes     an array of at least max_hashes entries
 *   peers      an array of at least
 *              max_hashes * max_peers_per_hash entries
 *   metadata   an array of the same size as peers, or NULL
 *              when store_metadata is 0
 *
 * A NULL hashes or peers is a programming error and returns
 * BOWIE_ERR_NULL_ARG. A metadata pointer is required when
 * store_metadata is non-zero.
 *
 * Passing NULL for storage is a programming error and returns
 * BOWIE_ERR_NULL_ARG.
 *
 * The storage is reset: hashes_used and peers_used become
 * zero.
 */
bowie_error_t bowie_dht_storage_init(
    bowie_dht_storage_t                 *storage,
    const bowie_dht_storage_config_t    *config,
    bowie_dht_hash_entry_t              *hashes,
    size_t                               hashes_cap,
    bowie_dht_peer_entry_t              *peers,
    size_t                               peers_cap,
    bowie_dht_peer_metadata_t           *metadata);

/*
 * Reset a storage to the empty state.
 *
 * The capacities and the config are not changed; only the
 * used counters are reset.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_storage_clear(bowie_dht_storage_t *storage);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the number of distinct info hashes.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_storage_hash_count(
    const bowie_dht_storage_t *storage);

/*
 * Return the total number of peer entries.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_storage_peer_count(
    const bowie_dht_storage_t *storage);

/*
 * Find a hash entry by info hash.
 *
 * Returns a pointer to the entry, or NULL if the hash is not
 * in the storage.
 */
const bowie_dht_hash_entry_t *bowie_dht_storage_find_hash(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash);

/*
 * ============================================================================
 * STORE
 * ============================================================================
 */

/*
 * Add or update a peer for an info hash.
 *
 * If the hash is not in the storage, a new hash entry is
 * created. If the hash is in the storage, the peer is added
 * to the existing entry.
 *
 * If a peer with the same address is already present for the
 * hash, its entry is updated: the capabilities are replaced,
 * the last-seen time is set, and the expiry is refreshed.
 *
 * A new peer that would exceed max_peers_per_hash is
 * rejected. A new hash that would exceed max_hashes is
 * rejected.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the storage is full.
 */
bowie_error_t bowie_dht_storage_add_peer(
    bowie_dht_storage_t          *storage,
    const bowie_dht_info_hash_t  *hash,
    const bowie_dht_peer_entry_t *peer);

/*
 * Store the metadata for a peer.
 *
 * The peer is identified by its address and the hash. The
 * peer must already be in the storage.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the peer is not in the
 *   storage.
 * Returns BOWIE_ERR_NOT_SUPPORTED if the storage does not
 *   keep metadata.
 */
bowie_error_t bowie_dht_storage_set_metadata(
    bowie_dht_storage_t                *storage,
    const bowie_dht_info_hash_t        *hash,
    const bowie_addr_t                 *addr,
    const bowie_dht_peer_metadata_t    *metadata);

/*
 * ============================================================================
 * FIND
 * ============================================================================
 */

/*
 * Find all peers for an info hash.
 *
 * The output array is caller-supplied. The number of entries
 * written is returned through out_count. A hash with more
 * peers than the output array can hold is truncated to the
 * array size; the caller checks whether the count equals the
 * array size.
 *
 * The metadata for each peer is written to the parallel
 * metadata output array, when the storage keeps metadata and
 * the metadata output is non-NULL. The metadata output is
 * optional even when the storage keeps metadata.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the hash is not in the
 *   storage.
 */
bowie_error_t bowie_dht_storage_find_peers(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash,
    bowie_dht_peer_entry_t      *out,
    bowie_dht_peer_metadata_t   *out_metadata,
    size_t                       out_cap,
    size_t                      *out_count);

/*
 * Find peers for an info hash that advertise a capability.
 *
 * The output is filtered: only peers whose capability mask
 * contains the given cap are written.
 *
 * Same return values as find_peers.
 */
bowie_error_t bowie_dht_storage_find_peers_with_cap(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash,
    bowie_cap_t                  cap,
    bowie_dht_peer_entry_t      *out,
    bowie_dht_peer_metadata_t   *out_metadata,
    size_t                       out_cap,
    size_t                      *out_count);

/*
 * ============================================================================
 * REMOVE
 * ============================================================================
 */

/*
 * Remove a peer from an info hash.
 *
 * The peer is identified by its address. If the peer is not
 * in the hash, the function returns BOWIE_ERR_NOT_FOUND.
 *
 * If the hash has no peers after the removal, the hash entry
 * is removed.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the hash or the peer is not
 *   in the storage.
 */
bowie_error_t bowie_dht_storage_remove_peer(
    bowie_dht_storage_t         *storage,
    const bowie_dht_info_hash_t *hash,
    const bowie_addr_t          *addr);

/*
 * Remove an info hash and all its peers.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the hash is not in the
 *   storage.
 */
bowie_error_t bowie_dht_storage_remove_hash(
    bowie_dht_storage_t         *storage,
    const bowie_dht_info_hash_t *hash);

/*
 * ============================================================================
 * MAINTENANCE
 * ============================================================================
 */

/*
 * Remove all expired peer entries.
 *
 * An entry is expired when its expires_at_ms is in the past
 * relative to now_ms, or when it is zero.
 *
 * A hash whose entries are all expired is removed.
 *
 * The number of peer entries removed is returned.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_storage_expire(bowie_dht_storage_t *storage,
                                bowie_mtime_t now_ms);

/*
 * ============================================================================
 * END OF DHT STORAGE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_STORAGE_H */
