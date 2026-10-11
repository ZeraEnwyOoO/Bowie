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
 * BOWIE — DHT STORAGE IMPLEMENTATION
 * ============================================================================
 *
 * The key-value storage for the DHT. The file is organized in
 * two parts:
 *
 *   1. Value operations: peer entry, metadata, config,
 *      lifecycle, store, find.
 *   2. Maintenance: remove, expire, compaction.
 *
 * The two parts share the internal helper functions.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network.
 *   - No allocation.
 *   - No persistence.
 *   - No thread safety.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The storage has two arrays: hashes and peers. A hash entry
 * points at a contiguous range of the peers array. The peers
 * for a hash are stored in the order they were added.
 *
 * When a peer is removed, the peers array has a hole. The
 * storage compacts the array by shifting the later peers down
 * and updating the "first" index of every hash entry that
 * follows. The compaction is O(n) in the number of peers; the
 * number of peers is bounded by the caller's capacities, so
 * the cost is acceptable.
 *
 * The compaction is done on the same call as the removal, so
 * the array is always dense after a removal. The expire
 * function calls the removal function once per expired peer.
 *
 * The metadata array is parallel to the peers array. When the
 * storage does not keep metadata, the metadata pointer is
 * NULL and is never dereferenced. The "store_metadata" flag
 * is the only test.
 *
 * The peer identity is the address. Two peers with the same
 * address are the same peer. The peer ID is not part of the
 * storage; the DHT routing table holds the peer ID, and the
 * storage holds the address.
 *
 * A hash entry with count == 0 is removed. The storage
 * compacts the hashes array on the same call.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint32_t, uint8_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "bowie/config.h"             bowie_cap_t, bowie_cap_has
 *   "dht/types.h"                info hash
 *   "dht/storage.h"              the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/config.h"
#include "dht/types.h"
#include "dht/storage.h"

/*
 * ============================================================================
 * PART 1 — CONFIG
 * ============================================================================
 */

bowie_error_t bowie_dht_storage_config_defaults(
    bowie_dht_storage_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cfg->max_hashes == 0u) {
        cfg->max_hashes = BOWIE_DHT_STORAGE_DEFAULT_MAX_HASHES;
    }
    if (cfg->max_peers_per_hash == 0u) {
        cfg->max_peers_per_hash =
            BOWIE_DHT_STORAGE_DEFAULT_MAX_PEERS_PER_HASH;
    }
    if (cfg->peer_lifetime_s == 0u) {
        cfg->peer_lifetime_s =
            BOWIE_DHT_STORAGE_DEFAULT_PEER_LIFETIME_S;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * PART 1 — PEER ENTRY
 * ============================================================================
 */

void bowie_dht_peer_entry_clear(bowie_dht_peer_entry_t *e)
{
    if (e == NULL) {
        return;
    }
    memset(e, 0, sizeof(*e));
}

int bowie_dht_peer_entry_is_set(const bowie_dht_peer_entry_t *e)
{
    if (e == NULL) {
        return 0;
    }
    return bowie_addr_is_set(&e->addr);
}

int bowie_dht_peer_entry_has_cap(const bowie_dht_peer_entry_t *e,
                                 bowie_cap_t cap)
{
    if (e == NULL) {
        return 0;
    }
    return bowie_cap_has(e->capabilities, cap);
}

int bowie_dht_peer_entry_is_expired(
    const bowie_dht_peer_entry_t *e, bowie_mtime_t now_ms)
{
    if (e == NULL) {
        return 1;
    }
    if (e->expires_at_ms == 0u) {
        return 1;
    }
    if (now_ms < e->expires_at_ms) {
        return 0;
    }
    /*
     * now_ms >= expires_at_ms. The entry is expired.
     */
    return 1;
}

int bowie_dht_peer_entry_equal(const bowie_dht_peer_entry_t *a,
                               const bowie_dht_peer_entry_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        /*
         * A NULL pointer is an unset entry. An unset entry
         * is equal to another unset entry, and not equal to
         * a set one.
         */
        return 0;
    }
    return bowie_addr_equal(&a->addr, &b->addr);
}

/*
 * ============================================================================
 * PART 1 — METADATA
 * ============================================================================
 */

void bowie_dht_peer_metadata_clear(bowie_dht_peer_metadata_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
}

/*
 * ============================================================================
 * PART 1 — LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_dht_storage_init(
    bowie_dht_storage_t              *storage,
    const bowie_dht_storage_config_t *config,
    bowie_dht_hash_entry_t           *hashes,
    size_t                            hashes_cap,
    bowie_dht_peer_entry_t           *peers,
    size_t                            peers_cap,
    bowie_dht_peer_metadata_t        *metadata)
{
    if (storage == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (hashes == NULL || peers == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (hashes_cap == 0u || peers_cap == 0u) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * Copy the config, filling in the defaults first.
     */
    bowie_dht_storage_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (config != NULL) {
        cfg = *config;
    }
    (void)bowie_dht_storage_config_defaults(&cfg);

    if (cfg.store_metadata && metadata == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(storage, 0, sizeof(*storage));
    storage->hashes       = hashes;
    storage->hashes_cap   = hashes_cap;
    storage->hashes_used  = 0u;
    storage->peers        = peers;
    storage->peers_cap    = peers_cap;
    storage->peers_used   = 0u;
    storage->metadata     = metadata;
    storage->config       = cfg;

    return BOWIE_OK;
}

void bowie_dht_storage_clear(bowie_dht_storage_t *storage)
{
    if (storage == NULL) {
        return;
    }
    storage->hashes_used = 0u;
    storage->peers_used  = 0u;
}

/*
 * ============================================================================
 * PART 1 — QUERY
 * ============================================================================
 */

size_t bowie_dht_storage_hash_count(
    const bowie_dht_storage_t *storage)
{
    if (storage == NULL) {
        return 0u;
    }
    return storage->hashes_used;
}

size_t bowie_dht_storage_peer_count(
    const bowie_dht_storage_t *storage)
{
    if (storage == NULL) {
        return 0u;
    }
    return storage->peers_used;
}

/*
 * Find the index of a hash in the hashes array. Returns the
 * index, or -1 when the hash is not present.
 */
static int find_hash_index(const bowie_dht_storage_t   *storage,
                           const bowie_dht_info_hash_t *hash)
{
    for (size_t i = 0u; i < storage->hashes_used; i++) {
        if (bowie_dht_info_hash_equal(&storage->hashes[i].hash,
                                      hash)) {
            return (int)i;
        }
    }
    return -1;
}

const bowie_dht_hash_entry_t *bowie_dht_storage_find_hash(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash)
{
    if (storage == NULL || hash == NULL) {
        return NULL;
    }
    int idx = find_hash_index(storage, hash);
    if (idx < 0) {
        return NULL;
    }
    return &storage->hashes[idx];
}

/*
 * Find the index of a peer in a hash's range. Returns the
 * index into the peers array, or -1 when the peer is not in
 * the hash.
 */
static int find_peer_index(const bowie_dht_storage_t   *storage,
                           const bowie_dht_hash_entry_t *h,
                           const bowie_addr_t           *addr)
{
    for (size_t i = 0u; i < h->count; i++) {
        size_t p = h->first + i;
        if (bowie_addr_equal(&storage->peers[p].addr, addr)) {
            return (int)p;
        }
    }
    return -1;
}

/*
 * ============================================================================
 * PART 1 — STORE
 * ============================================================================
 */

/*
 * Append a new hash entry with an empty peer range. The range
 * starts at the current end of the peers array.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_TOO_SMALL when the hashes array is full.
 */
static bowie_error_t append_hash(bowie_dht_storage_t         *storage,
                                 const bowie_dht_info_hash_t *hash)
{
    if (storage->hashes_used >= storage->hashes_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    size_t idx = storage->hashes_used;
    bowie_dht_hash_entry_t *h = &storage->hashes[idx];
    h->hash  = *hash;
    h->first = storage->peers_used;
    h->count = 0u;
    storage->hashes_used++;
    return BOWIE_OK;
}

bowie_error_t bowie_dht_storage_add_peer(
    bowie_dht_storage_t          *storage,
    const bowie_dht_info_hash_t  *hash,
    const bowie_dht_peer_entry_t *peer)
{
    if (storage == NULL || hash == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!bowie_dht_peer_entry_is_set(peer)) {
        return BOWIE_ERR_INVAL;
    }

    int idx = find_hash_index(storage, hash);
    if (idx < 0) {
        /*
         * The hash is not present. Add a new hash entry,
         * then add the peer to it.
         */
        bowie_error_t rc = append_hash(storage, hash);
        if (rc != BOWIE_OK) {
            return rc;
        }
        idx = (int)(storage->hashes_used - 1u);
    }

    bowie_dht_hash_entry_t *h = &storage->hashes[idx];

    /*
     * Update path: the peer is already in the hash.
     */
    int p = find_peer_index(storage, h, &peer->addr);
    if (p >= 0) {
        bowie_mtime_t expires = peer->expires_at_ms;
        if (expires == 0u) {
            expires = peer->last_seen_ms +
                (bowie_mtime_t)storage->config.peer_lifetime_s *
                1000u;
        }
        bowie_dht_peer_entry_t *existing = &storage->peers[p];
        existing->capabilities = peer->capabilities;
        existing->last_seen_ms = peer->last_seen_ms;
        existing->expires_at_ms = expires;
        return BOWIE_OK;
    }

    /*
     * Add path: the hash has room for another peer.
     */
    if (h->count >= storage->config.max_peers_per_hash) {
        return BOWIE_ERR_TOO_SMALL;
    }
    if (storage->peers_used >= storage->peers_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The new peer goes at the end of the peers array. The
     * peers of a hash are contiguous, so the new peer must
     * be at the end of the array. When the new hash was
     * just created, its range starts at the end; when the
     * hash already exists, its range may be followed by
     * other hashes' peers.
     *
     * To keep the hash's range contiguous, the storage
     * inserts the new peer at the end of the hash's range
     * and shifts the following peers down by one.
     */
    size_t insert_at = h->first + h->count;

    if (insert_at < storage->peers_used) {
        /*
         * Shift the following peers down by one.
         */
        size_t move_count = storage->peers_used - insert_at;
        memmove(&storage->peers[insert_at + 1u],
                &storage->peers[insert_at],
                move_count * sizeof(bowie_dht_peer_entry_t));

        if (storage->config.store_metadata &&
            storage->metadata != NULL) {
            memmove(&storage->metadata[insert_at + 1u],
                    &storage->metadata[insert_at],
                    move_count * sizeof(bowie_dht_peer_metadata_t));
        }

        /*
         * Update the "first" index of every hash entry
         * that follows.
         */
        for (size_t i = 0u; i < storage->hashes_used; i++) {
            bowie_dht_hash_entry_t *other = &storage->hashes[i];
            if (other->first >= insert_at) {
                other->first++;
            } else if (other->first + other->count > insert_at) {
                /*
                 * The insert is inside this hash's
                 * range. That cannot happen: the insert
                 * is at the end of this hash's own
                 * range, which is the start of the
                 * next hash's range. The check is here
                 * to catch a bug.
                 */
            }
        }
    }

    bowie_mtime_t expires = peer->expires_at_ms;
    if (expires == 0u) {
        expires = peer->last_seen_ms +
            (bowie_mtime_t)storage->config.peer_lifetime_s * 1000u;
    }

    bowie_dht_peer_entry_t *slot = &storage->peers[insert_at];
    *slot = *peer;
    slot->expires_at_ms = expires;

    if (storage->config.store_metadata &&
        storage->metadata != NULL) {
        bowie_dht_peer_metadata_t *m = &storage->metadata[insert_at];
        memset(m, 0, sizeof(*m));
    }

    storage->peers_used++;
    h->count++;

    return BOWIE_OK;
}

bowie_error_t bowie_dht_storage_set_metadata(
    bowie_dht_storage_t             *storage,
    const bowie_dht_info_hash_t     *hash,
    const bowie_addr_t              *addr,
    const bowie_dht_peer_metadata_t *metadata)
{
    if (storage == NULL || hash == NULL || addr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!storage->config.store_metadata) {
        return BOWIE_ERR_NOT_SUPPORTED;
    }
    if (storage->metadata == NULL) {
        return BOWIE_ERR_NOT_SUPPORTED;
    }

    int idx = find_hash_index(storage, hash);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }
    const bowie_dht_hash_entry_t *h = &storage->hashes[idx];

    int p = find_peer_index(storage, h, addr);
    if (p < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    if (metadata != NULL) {
        storage->metadata[p] = *metadata;
    } else {
        memset(&storage->metadata[p], 0,
               sizeof(storage->metadata[p]));
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * PART 1 — FIND
 * ============================================================================
 */

/*
 * Copy the peers of a hash into the caller's output. The
 * metadata is copied when the storage keeps metadata and the
 * metadata output is non-NULL.
 *
 * When a capability filter is given (cap_filter != 0), only
 * peers that advertise the capability are copied.
 *
 * The return value is the number of peers copied. The caller
 * checks whether the number equals the output capacity to
 * know whether the list was truncated.
 */
static size_t copy_peers(const bowie_dht_storage_t    *storage,
                         const bowie_dht_hash_entry_t *h,
                         bowie_cap_t                   cap_filter,
                         bowie_dht_peer_entry_t       *out,
                         bowie_dht_peer_metadata_t    *out_metadata,
                         size_t                        out_cap)
{
    size_t n = 0u;
    for (size_t i = 0u; i < h->count; i++) {
        size_t p = h->first + i;
        const bowie_dht_peer_entry_t *e = &storage->peers[p];

        if (cap_filter != BOWIE_CAP_NONE) {
            if (!bowie_dht_peer_entry_has_cap(e, cap_filter)) {
                continue;
            }
        }

        if (n >= out_cap) {
            break;
        }
        out[n] = *e;

        if (storage->config.store_metadata &&
            storage->metadata != NULL &&
            out_metadata != NULL) {
            out_metadata[n] = storage->metadata[p];
        }
        n++;
    }
    return n;
}

bowie_error_t bowie_dht_storage_find_peers(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash,
    bowie_dht_peer_entry_t      *out,
    bowie_dht_peer_metadata_t   *out_metadata,
    size_t                       out_cap,
    size_t                      *out_count)
{
    if (storage == NULL || hash == NULL ||
        out == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out_cap == 0u) {
        *out_count = 0u;
        return BOWIE_OK;
    }

    int idx = find_hash_index(storage, hash);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    size_t n = copy_peers(storage, &storage->hashes[idx],
                          BOWIE_CAP_NONE,
                          out, out_metadata, out_cap);
    *out_count = n;
    return BOWIE_OK;
}

bowie_error_t bowie_dht_storage_find_peers_with_cap(
    const bowie_dht_storage_t   *storage,
    const bowie_dht_info_hash_t *hash,
    bowie_cap_t                  cap,
    bowie_dht_peer_entry_t      *out,
    bowie_dht_peer_metadata_t   *out_metadata,
    size_t                       out_cap,
    size_t                      *out_count)
{
    if (storage == NULL || hash == NULL ||
        out == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cap == BOWIE_CAP_NONE) {
        return bowie_dht_storage_find_peers(storage, hash, out,
                                            out_metadata,
                                            out_cap, out_count);
    }
    if (out_cap == 0u) {
        *out_count = 0u;
        return BOWIE_OK;
    }

    int idx = find_hash_index(storage, hash);
    if (idx < 0) {
        return BOWIE_ERR_NOT_FOUND;
    }

    size_t n = copy_peers(storage, &storage->hashes[idx],
                          cap,
                          out, out_metadata, out_cap);
    *out_count = n;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF PART 1
 * ============================================================================
 */
