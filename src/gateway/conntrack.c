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
 * BOWIE — GATEWAY: CONNECTION TRACKING (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the conntrack helpers declared in
 * gateway/conntrack.h.
 *
 * The table is a fixed-capacity hash map with linear probing.
 * The hash is FNV-1a over the 5-tuple. A collision is resolved
 * by walking forward until an empty slot is found.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No NAT.
 *   - No TCP state machine.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Each entry stores the full 5-tuple. A lookup walks the
 * table until it finds either the tuple or an empty slot; a
 * full walk without a hit means the tuple is not present.
 *
 * Eviction is oldest-first. The entry with the smallest
 * timestamp is removed when the table is full and a new entry
 * needs a slot. A linear scan finds the oldest entry; with a
 * thousand entries, the scan is a few microseconds.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdlib.h>              calloc, free
 *   <string.h>              memcpy, memset
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "gateway/conntrack.h"   declarations
 * ============================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/conntrack.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

#define BOWIE_CONNTRACK_DEFAULT_CAPACITY 1024

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 */

typedef struct bowie_conntrack_entry {
    bowie_conntrack_5tuple_t tuple;
    bowie_peer_id_t          peer;
    uint64_t                 timestamp;
    int                      used;
} bowie_conntrack_entry_t;

struct bowie_conntrack {
    bowie_conntrack_entry_t *entries;
    size_t                   capacity;
    size_t                   count;
    uint64_t                 clock;
};

/*
 * ============================================================================
 * INTERNAL — HASH
 * ============================================================================
 *
 * FNV-1a over the 5-tuple. The tuple is treated as a byte
 * sequence; the addresses, the ports, and the protocol are
 * hashed in that order.
 */

static uint32_t fnv1a(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261u;
    size_t   i;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= 16777619u;
    }

    return h;
}

static uint32_t hash_tuple(const bowie_conntrack_5tuple_t *t)
{
    uint8_t  buf[16 + 16 + 2 + 2 + 1];
    size_t   off = 0;

    memcpy(buf + off, t->src_addr, 16);
    off += 16;
    memcpy(buf + off, t->dst_addr, 16);
    off += 16;
    buf[off++] = (uint8_t)(t->src_port >> 8);
    buf[off++] = (uint8_t)(t->src_port);
    buf[off++] = (uint8_t)(t->dst_port >> 8);
    buf[off++] = (uint8_t)(t->dst_port);
    buf[off++] = t->protocol;

    return fnv1a(buf, off);
}

/*
 * ============================================================================
 * INTERNAL — TUPLE EQUALITY
 * ============================================================================
 */

static int tuple_equal(const bowie_conntrack_5tuple_t *a,
                       const bowie_conntrack_5tuple_t *b)
{
    return (memcmp(a->src_addr, b->src_addr, 16) == 0) &&
           (memcmp(a->dst_addr, b->dst_addr, 16) == 0) &&
           (a->src_port == b->src_port) &&
           (a->dst_port == b->dst_port) &&
           (a->protocol == b->protocol);
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_conntrack_open(bowie_conntrack_t **out,
                                   size_t capacity)
{
    bowie_conntrack_t *ct;

    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (capacity == 0) {
        capacity = BOWIE_CONNTRACK_DEFAULT_CAPACITY;
    }

    ct = (bowie_conntrack_t *)calloc(1, sizeof(*ct));

    if (ct == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    ct->entries = (bowie_conntrack_entry_t *)calloc(
                      capacity, sizeof(*ct->entries));

    if (ct->entries == NULL) {
        free(ct);
        return BOWIE_ERR_NOMEM;
    }

    ct->capacity = capacity;
    ct->count    = 0;
    ct->clock    = 0;

    *out = ct;

    return BOWIE_OK;
}

void bowie_conntrack_close(bowie_conntrack_t *ct)
{
    if (ct == NULL) {
        return;
    }

    free(ct->entries);
    free(ct);
}

/*
 * ============================================================================
 * INTERNAL — EVICT OLDEST
 * ============================================================================
 */

static void evict_oldest(bowie_conntrack_t *ct)
{
    size_t   i;
    size_t   oldest = (size_t)-1;
    uint64_t oldest_ts = UINT64_MAX;

    for (i = 0; i < ct->capacity; i++) {
        if (ct->entries[i].used && ct->entries[i].timestamp < oldest_ts) {
            oldest_ts = ct->entries[i].timestamp;
            oldest    = i;
        }
    }

    if (oldest != (size_t)-1) {
        ct->entries[oldest].used = 0;
        ct->count--;
    }
}

/*
 * ============================================================================
 * ADD
 * ============================================================================
 */

bowie_error_t bowie_conntrack_add(bowie_conntrack_t *ct,
                                  const bowie_conntrack_5tuple_t *tuple,
                                  const bowie_peer_id_t *peer)
{
    uint32_t idx;

    if (ct == NULL || tuple == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = hash_tuple(tuple) % ct->capacity;

    for (;;) {
        bowie_conntrack_entry_t *e = &ct->entries[idx];

        if (!e->used) {
            if (ct->count >= ct->capacity) {
                evict_oldest(ct);
                /* After eviction, the slot may now be free;
                 * recompute the index and try again. */
                idx = hash_tuple(tuple) % ct->capacity;
                continue;
            }

            e->tuple    = *tuple;
            e->peer     = *peer;
            e->timestamp = ++ct->clock;
            e->used     = 1;
            ct->count++;
            return BOWIE_OK;
        }

        if (tuple_equal(&e->tuple, tuple)) {
            e->peer      = *peer;
            e->timestamp = ++ct->clock;
            return BOWIE_OK;
        }

        idx = (idx + 1) % ct->capacity;
    }
}

/*
 * ============================================================================
 * LOOKUP
 * ============================================================================
 */

int bowie_conntrack_lookup(const bowie_conntrack_t *ct,
                           const bowie_conntrack_5tuple_t *tuple,
                           bowie_peer_id_t *out_peer)
{
    uint32_t idx;
    size_t   probes = 0;

    if (ct == NULL || tuple == NULL || out_peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = hash_tuple(tuple) % ct->capacity;

    while (probes < ct->capacity) {
        const bowie_conntrack_entry_t *e = &ct->entries[idx];

        if (!e->used) {
            return 0;
        }

        if (tuple_equal(&e->tuple, tuple)) {
            *out_peer = e->peer;
            return 1;
        }

        idx = (idx + 1) % ct->capacity;
        probes++;
    }

    return 0;
}

/*
 * ============================================================================
 * REMOVE
 * ============================================================================
 */

bowie_error_t bowie_conntrack_remove(bowie_conntrack_t *ct,
                                     const bowie_conntrack_5tuple_t *tuple)
{
    uint32_t idx;
    size_t   probes = 0;

    if (ct == NULL || tuple == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = hash_tuple(tuple) % ct->capacity;

    while (probes < ct->capacity) {
        bowie_conntrack_entry_t *e = &ct->entries[idx];

        if (!e->used) {
            return BOWIE_OK;
        }

        if (tuple_equal(&e->tuple, tuple)) {
            e->used = 0;
            ct->count--;
            return BOWIE_OK;
        }

        idx = (idx + 1) % ct->capacity;
        probes++;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * COUNT
 * ============================================================================
 */

size_t bowie_conntrack_count(const bowie_conntrack_t *ct)
{
    if (ct == NULL) {
        return 0;
    }

    return ct->count;
}

/*
 * ============================================================================
 * END OF GATEWAY CONNTRACK IMPLEMENTATION
 * ============================================================================
 */
