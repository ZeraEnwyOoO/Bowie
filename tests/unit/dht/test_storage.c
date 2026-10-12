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
 * BOWIE — DHT STORAGE TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/storage.c.
 *
 * The tests cover:
 *
 *   - Config defaults.
 *   - Peer entry: clear, is_set, has_cap, is_expired, equal.
 *   - Metadata: clear.
 *   - Lifecycle: init, clear.
 *   - Query: hash_count, peer_count, find_hash.
 *   - Add peer: new hash, existing hash, update, full.
 *   - Set metadata.
 *   - Find peers: all, with capability filter.
 *   - Remove peer: with auto-remove of empty hash.
 *   - Remove hash.
 *   - Expire.
 *
 * The tests use small capacities so that the "full" paths are
 * exercised without large arrays.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "bowie/config.h"             bowie_cap_t
 *   "dht/storage.h"              the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "bowie/config.h"
#include "dht/storage.h"

/*
 * ============================================================================
 * FIXTURE
 * ============================================================================
 *
 * A small storage: 2 hashes, 4 peers per hash. The metadata
 * array is present so that the metadata paths can be tested.
 */

#define TEST_MAX_HASHES          2
#define TEST_MAX_PEERS_PER_HASH  4
#define TEST_PEERS_CAP \
    (TEST_MAX_HASHES * TEST_MAX_PEERS_PER_HASH)

static bowie_dht_hash_entry_t      g_hashes[TEST_MAX_HASHES];
static bowie_dht_peer_entry_t      g_peers[TEST_PEERS_CAP];
static bowie_dht_peer_metadata_t   g_metadata[TEST_PEERS_CAP];

static bowie_dht_storage_t make_storage(void)
{
    bowie_dht_storage_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_hashes         = TEST_MAX_HASHES;
    cfg.max_peers_per_hash = TEST_MAX_PEERS_PER_HASH;
    cfg.peer_lifetime_s    = 60u;
    cfg.store_metadata     = 1;

    bowie_dht_storage_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_storage_init(&s, &cfg,
                                 g_hashes, TEST_MAX_HASHES,
                                 g_peers, TEST_PEERS_CAP,
                                 g_metadata);
    return s;
}

static void make_hash(bowie_dht_info_hash_t *h, uint8_t seed)
{
    memset(h, 0, sizeof(*h));
    h->bytes[0] = seed;
}

static void make_addr(bowie_addr_t *a, uint8_t last_octet,
                      uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->family = BOWIE_AF_INET;
    a->addr[0] = 10u;
    a->addr[3] = last_octet;
    a->port = port;
}

static void make_peer(bowie_dht_peer_entry_t *p,
                      uint8_t last_octet, uint16_t port,
                      uint32_t caps, bowie_mtime_t seen)
{
    memset(p, 0, sizeof(*p));
    make_addr(&p->addr, last_octet, port);
    p->capabilities = caps;
    p->last_seen_ms = seen;
    /* expires_at_ms left at 0; the storage fills it in. */
}

/*
 * ============================================================================
 * CONFIG DEFAULTS
 * ============================================================================
 */

START_TEST(test_config_defaults_null)
{
    ck_assert_int_eq(bowie_dht_storage_config_defaults(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_config_defaults_zeroed)
{
    bowie_dht_storage_config_t c;
    memset(&c, 0, sizeof(c));
    ck_assert_int_eq(bowie_dht_storage_config_defaults(&c),
                     BOWIE_OK);
    ck_assert_uint_gt(c.max_hashes, 0u);
    ck_assert_uint_gt(c.max_peers_per_hash, 0u);
    ck_assert_uint_gt(c.peer_lifetime_s, 0u);
}
END_TEST

START_TEST(test_config_defaults_preserves_nonzero)
{
    bowie_dht_storage_config_t c;
    memset(&c, 0, sizeof(c));
    c.max_hashes = 7u;
    c.peer_lifetime_s = 99u;
    (void)bowie_dht_storage_config_defaults(&c);
    ck_assert_uint_eq(c.max_hashes, 7u);
    ck_assert_uint_eq(c.peer_lifetime_s, 99u);
}
END_TEST

/*
 * ============================================================================
 * PEER ENTRY
 * ============================================================================
 */

START_TEST(test_peer_entry_clear)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, (uint32_t)BOWIE_CAP_SOURCE, 1000u);
    bowie_dht_peer_entry_clear(&e);
    ck_assert(!bowie_dht_peer_entry_is_set(&e));
    ck_assert_uint_eq(e.capabilities, 0u);
}
END_TEST

START_TEST(test_peer_entry_clear_null)
{
    bowie_dht_peer_entry_clear(NULL);
}
END_TEST

START_TEST(test_peer_entry_is_set_null)
{
    ck_assert(!bowie_dht_peer_entry_is_set(NULL));
}
END_TEST

START_TEST(test_peer_entry_is_set_false)
{
    bowie_dht_peer_entry_t e;
    memset(&e, 0, sizeof(e));
    ck_assert(!bowie_dht_peer_entry_is_set(&e));
}
END_TEST

START_TEST(test_peer_entry_is_set_true)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, 0u, 1000u);
    ck_assert(bowie_dht_peer_entry_is_set(&e));
}
END_TEST

START_TEST(test_peer_entry_has_cap_null)
{
    ck_assert(!bowie_dht_peer_entry_has_cap(NULL, BOWIE_CAP_SOURCE));
}
END_TEST

START_TEST(test_peer_entry_has_cap_true)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u,
              (uint32_t)BOWIE_CAP_SOURCE
              | (uint32_t)BOWIE_CAP_GATEWAY, 1000u);
    ck_assert(bowie_dht_peer_entry_has_cap(&e, BOWIE_CAP_SOURCE));
    ck_assert(bowie_dht_peer_entry_has_cap(&e, BOWIE_CAP_GATEWAY));
    ck_assert(!bowie_dht_peer_entry_has_cap(&e, BOWIE_CAP_CLIENT));
}
END_TEST

START_TEST(test_peer_entry_is_expired_null)
{
    ck_assert(bowie_dht_peer_entry_is_expired(NULL, 1000u));
}
END_TEST

START_TEST(test_peer_entry_is_expired_never)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, 0u, 1000u);
    /* expires_at_ms is 0 -> always expired. */
    ck_assert(bowie_dht_peer_entry_is_expired(&e, 1000u));
}
END_TEST

START_TEST(test_peer_entry_is_expired_future)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, 0u, 1000u);
    e.expires_at_ms = 5000u;
    ck_assert(!bowie_dht_peer_entry_is_expired(&e, 4000u));
}
END_TEST

START_TEST(test_peer_entry_is_expired_past)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, 0u, 1000u);
    e.expires_at_ms = 5000u;
    ck_assert(bowie_dht_peer_entry_is_expired(&e, 5000u));
    ck_assert(bowie_dht_peer_entry_is_expired(&e, 6000u));
}
END_TEST

START_TEST(test_peer_entry_equal_null_null)
{
    ck_assert(bowie_dht_peer_entry_equal(NULL, NULL));
}
END_TEST

START_TEST(test_peer_entry_equal_null_nonnull)
{
    bowie_dht_peer_entry_t e;
    make_peer(&e, 1u, 6881u, 0u, 1000u);
    ck_assert(!bowie_dht_peer_entry_equal(NULL, &e));
    ck_assert(!bowie_dht_peer_entry_equal(&e, NULL));
}
END_TEST

START_TEST(test_peer_entry_equal_same_addr)
{
    bowie_dht_peer_entry_t a;
    bowie_dht_peer_entry_t b;
    make_peer(&a, 1u, 6881u, (uint32_t)BOWIE_CAP_SOURCE, 1000u);
    make_peer(&b, 1u, 6881u, (uint32_t)BOWIE_CAP_CLIENT, 2000u);
    ck_assert(bowie_dht_peer_entry_equal(&a, &b));
}
END_TEST

START_TEST(test_peer_entry_equal_different_addr)
{
    bowie_dht_peer_entry_t a;
    bowie_dht_peer_entry_t b;
    make_peer(&a, 1u, 6881u, 0u, 1000u);
    make_peer(&b, 2u, 6881u, 0u, 1000u);
    ck_assert(!bowie_dht_peer_entry_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * METADATA
 * ============================================================================
 */

START_TEST(test_metadata_clear)
{
    bowie_dht_peer_metadata_t m;
    m.bandwidth_kbps = 100u;
    m.latency_ms = 50u;
    m.reliability = 99u;
    bowie_dht_peer_metadata_clear(&m);
    ck_assert_uint_eq(m.bandwidth_kbps, 0u);
    ck_assert_uint_eq(m.latency_ms, 0u);
    ck_assert_uint_eq(m.reliability, 0u);
}
END_TEST

START_TEST(test_metadata_clear_null)
{
    bowie_dht_peer_metadata_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null_storage)
{
    ck_assert_int_eq(
        bowie_dht_storage_init(NULL, NULL,
                               g_hashes, 2u,
                               g_peers, 8u,
                               g_metadata),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_hashes)
{
    bowie_dht_storage_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_storage_init(&s, NULL,
                               NULL, 2u,
                               g_peers, 8u,
                               g_metadata),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_metadata_with_store)
{
    bowie_dht_storage_config_t c;
    memset(&c, 0, sizeof(c));
    c.store_metadata = 1;

    bowie_dht_storage_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_storage_init(&s, &c,
                               g_hashes, 2u,
                               g_peers, 8u,
                               NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_ok)
{
    bowie_dht_storage_t s = make_storage();
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 0u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 0u);
    ck_assert_int_eq(s.config.store_metadata, 1);
}
END_TEST

START_TEST(test_clear_resets_counts)
{
    bowie_dht_storage_t s = make_storage();

    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    bowie_dht_storage_clear(&s);
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 0u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 0u);
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_dht_storage_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_hash_count_null)
{
    ck_assert_uint_eq(bowie_dht_storage_hash_count(NULL), 0u);
}
END_TEST

START_TEST(test_peer_count_null)
{
    ck_assert_uint_eq(bowie_dht_storage_peer_count(NULL), 0u);
}
END_TEST

START_TEST(test_find_hash_null)
{
    ck_assert_ptr_null(bowie_dht_storage_find_hash(NULL, NULL));
}
END_TEST

START_TEST(test_find_hash_missing)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 42u);
    ck_assert_ptr_null(bowie_dht_storage_find_hash(&s, &h));
}
END_TEST

START_TEST(test_find_hash_ok)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 42u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    const bowie_dht_hash_entry_t *he =
        bowie_dht_storage_find_hash(&s, &h);
    ck_assert_ptr_nonnull(he);
    ck_assert_uint_eq(he->count, 1u);
}
END_TEST

/*
 * ============================================================================
 * ADD PEER
 * ============================================================================
 */

START_TEST(test_add_peer_null)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);

    ck_assert_int_eq(
        bowie_dht_storage_add_peer(NULL, &h, &p),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_add_peer(&s, NULL, &p),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_add_peer(&s, &h, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_add_peer_unset)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    memset(&p, 0, sizeof(p));

    ck_assert_int_eq(
        bowie_dht_storage_add_peer(&s, &h, &p),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_add_peer_new_hash)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, (uint32_t)BOWIE_CAP_SOURCE, 1000u);

    ck_assert_int_eq(bowie_dht_storage_add_peer(&s, &h, &p),
                     BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 1u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 1u);
}
END_TEST

START_TEST(test_add_peer_existing_hash)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p1;
    make_peer(&p1, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p1);

    bowie_dht_peer_entry_t p2;
    make_peer(&p2, 2u, 6882u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p2);

    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 1u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 2u);
}
END_TEST

START_TEST(test_add_peer_update_existing)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, (uint32_t)BOWIE_CAP_SOURCE, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    /* Same address, different capability and time. */
    bowie_dht_peer_entry_t p2;
    make_peer(&p2, 1u, 6881u, (uint32_t)BOWIE_CAP_CLIENT, 2000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p2);

    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 1u);

    const bowie_dht_hash_entry_t *he =
        bowie_dht_storage_find_hash(&s, &h);
    ck_assert_ptr_nonnull(he);
    ck_assert_uint_eq(he->count, 1u);
}
END_TEST

START_TEST(test_add_peer_hash_full)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    for (uint8_t i = 1u; i <= TEST_MAX_PEERS_PER_HASH; i++) {
        bowie_dht_peer_entry_t p;
        make_peer(&p, i, (uint16_t)(6881u + i), 0u, 1000u);
        ck_assert_int_eq(
            bowie_dht_storage_add_peer(&s, &h, &p), BOWIE_OK);
    }

    bowie_dht_peer_entry_t extra;
    make_peer(&extra, 100u, 9999u, 0u, 1000u);
    ck_assert_int_eq(
        bowie_dht_storage_add_peer(&s, &h, &extra),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_add_peer_hash_table_full)
{
    bowie_dht_storage_t s = make_storage();

    for (uint8_t i = 1u; i <= TEST_MAX_HASHES; i++) {
        bowie_dht_info_hash_t h;
        make_hash(&h, i);
        bowie_dht_peer_entry_t p;
        make_peer(&p, i, 6881u, 0u, 1000u);
        ck_assert_int_eq(
            bowie_dht_storage_add_peer(&s, &h, &p), BOWIE_OK);
    }

    bowie_dht_info_hash_t extra;
    make_hash(&extra, 100u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 100u, 6881u, 0u, 1000u);
    ck_assert_int_eq(
        bowie_dht_storage_add_peer(&s, &extra, &p),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

/*
 * ============================================================================
 * SET METADATA
 * ============================================================================
 */

START_TEST(test_set_metadata_null)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_addr_t a;
    make_addr(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(NULL, &h, &a, NULL),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(&s, NULL, &a, NULL),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(&s, &h, NULL, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_set_metadata_not_supported)
{
    bowie_dht_storage_config_t c;
    memset(&c, 0, sizeof(c));
    c.max_hashes = TEST_MAX_HASHES;
    c.max_peers_per_hash = TEST_MAX_PEERS_PER_HASH;
    c.store_metadata = 0;

    bowie_dht_storage_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_storage_init(&s, &c,
                                 g_hashes, TEST_MAX_HASHES,
                                 g_peers, TEST_PEERS_CAP,
                                 NULL);

    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_addr_t a;
    make_addr(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(&s, &h, &a, NULL),
        BOWIE_ERR_NOT_SUPPORTED);
}
END_TEST

START_TEST(test_set_metadata_ok)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    bowie_dht_peer_metadata_t m;
    memset(&m, 0, sizeof(m));
    m.bandwidth_kbps = 1000u;
    m.latency_ms = 50u;
    m.reliability = 99u;

    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(&s, &h, &p.addr, &m),
        BOWIE_OK);
}
END_TEST

START_TEST(test_set_metadata_not_found)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    bowie_addr_t other;
    make_addr(&other, 99u, 9999u);
    ck_assert_int_eq(
        bowie_dht_storage_set_metadata(&s, &h, &other, NULL),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

/*
 * ============================================================================
 * FIND PEERS
 * ============================================================================
 */

START_TEST(test_find_peers_null)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t out[4];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers(NULL, &h, out, NULL,
                                     4u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, NULL, out, NULL,
                                     4u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, &h, NULL, NULL,
                                     4u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, &h, out, NULL,
                                     4u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_find_peers_not_found)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_dht_peer_entry_t out[4];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, &h, out, NULL,
                                     4u, &count),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_find_peers_all)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    for (uint8_t i = 1u; i <= 3u; i++) {
        bowie_dht_peer_entry_t p;
        make_peer(&p, i, (uint16_t)(6881u + i), 0u, 1000u);
        (void)bowie_dht_storage_add_peer(&s, &h, &p);
    }

    bowie_dht_peer_entry_t out[4];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, &h, out, NULL,
                                     4u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 3u);
}
END_TEST

START_TEST(test_find_peers_truncated)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    for (uint8_t i = 1u; i <= 4u; i++) {
        bowie_dht_peer_entry_t p;
        make_peer(&p, i, (uint16_t)(6881u + i), 0u, 1000u);
        (void)bowie_dht_storage_add_peer(&s, &h, &p);
    }

    bowie_dht_peer_entry_t out[2];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers(&s, &h, out, NULL,
                                     2u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 2u);
}
END_TEST

START_TEST(test_find_peers_with_cap)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t src;
    make_peer(&src, 1u, 6881u, (uint32_t)BOWIE_CAP_SOURCE, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &src);

    bowie_dht_peer_entry_t cli;
    make_peer(&cli, 2u, 6882u, (uint32_t)BOWIE_CAP_CLIENT, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &cli);

    bowie_dht_peer_entry_t out[4];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers_with_cap(
            &s, &h, BOWIE_CAP_SOURCE, out, NULL, 4u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 1u);
    ck_assert_uint_eq(out[0].addr.addr[3], 1u);
}
END_TEST

START_TEST(test_find_peers_with_cap_none_delegates)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    bowie_dht_peer_entry_t out[4];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_storage_find_peers_with_cap(
            &s, &h, BOWIE_CAP_NONE, out, NULL, 4u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 1u);
}
END_TEST

/*
 * ============================================================================
 * REMOVE
 * ============================================================================
 */

START_TEST(test_remove_peer_null)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_addr_t a;
    make_addr(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(NULL, &h, &a),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(&s, NULL, &a),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(&s, &h, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remove_peer_not_found)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    bowie_addr_t a;
    make_addr(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(&s, &h, &a),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_remove_peer_ok)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p1;
    make_peer(&p1, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p1);

    bowie_dht_peer_entry_t p2;
    make_peer(&p2, 2u, 6882u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p2);

    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(&s, &h, &p1.addr),
        BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 1u);

    const bowie_dht_hash_entry_t *he =
        bowie_dht_storage_find_hash(&s, &h);
    ck_assert_ptr_nonnull(he);
    ck_assert_uint_eq(he->count, 1u);
}
END_TEST

START_TEST(test_remove_peer_auto_removes_hash)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    ck_assert_int_eq(
        bowie_dht_storage_remove_peer(&s, &h, &p.addr),
        BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 0u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 0u);
}
END_TEST

START_TEST(test_remove_hash_null)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    ck_assert_int_eq(
        bowie_dht_storage_remove_hash(NULL, &h),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_storage_remove_hash(&s, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remove_hash_not_found)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);
    ck_assert_int_eq(
        bowie_dht_storage_remove_hash(&s, &h),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_remove_hash_ok)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    for (uint8_t i = 1u; i <= 3u; i++) {
        bowie_dht_peer_entry_t p;
        make_peer(&p, i, (uint16_t)(6881u + i), 0u, 1000u);
        (void)bowie_dht_storage_add_peer(&s, &h, &p);
    }

    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 3u);

    ck_assert_int_eq(
        bowie_dht_storage_remove_hash(&s, &h), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 0u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 0u);
}
END_TEST

/*
 * ============================================================================
 * EXPIRE
 * ============================================================================
 */

START_TEST(test_expire_null)
{
    ck_assert_uint_eq(bowie_dht_storage_expire(NULL, 1000u), 0u);
}
END_TEST

START_TEST(test_expire_none)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    /* The peer's expiry is last_seen + 60 s = 61000 ms. */
    size_t removed = bowie_dht_storage_expire(&s, 5000u);
    ck_assert_uint_eq(removed, 0u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 1u);
}
END_TEST

START_TEST(test_expire_one)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t p;
    make_peer(&p, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &p);

    size_t removed = bowie_dht_storage_expire(&s, 70000u);
    ck_assert_uint_eq(removed, 1u);
    ck_assert_uint_eq(bowie_dht_storage_hash_count(&s), 0u);
}
END_TEST

START_TEST(test_expire_keeps_fresh)
{
    bowie_dht_storage_t s = make_storage();
    bowie_dht_info_hash_t h;
    make_hash(&h, 1u);

    bowie_dht_peer_entry_t old_peer;
    make_peer(&old_peer, 1u, 6881u, 0u, 1000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &old_peer);

    bowie_dht_peer_entry_t new_peer;
    make_peer(&new_peer, 2u, 6882u, 0u, 100000u);
    (void)bowie_dht_storage_add_peer(&s, &h, &new_peer);

    /* At 70000 ms, the old peer is expired, the new is not. */
    size_t removed = bowie_dht_storage_expire(&s, 70000u);
    ck_assert_uint_eq(removed, 1u);
    ck_assert_uint_eq(bowie_dht_storage_peer_count(&s), 1u);

    const bowie_dht_hash_entry_t *he =
        bowie_dht_storage_find_hash(&s, &h);
    ck_assert_ptr_nonnull(he);
    ck_assert_uint_eq(he->count, 1u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *storage_suite(void)
{
    Suite *s = suite_create("DhtStorage");

    TCase *tc_cfg = tcase_create("ConfigDefaults");
    tcase_add_test(tc_cfg, test_config_defaults_null);
    tcase_add_test(tc_cfg, test_config_defaults_zeroed);
    tcase_add_test(tc_cfg, test_config_defaults_preserves_nonzero);
    suite_add_tcase(s, tc_cfg);

    TCase *tc_pe = tcase_create("PeerEntry");
    tcase_add_test(tc_pe, test_peer_entry_clear);
    tcase_add_test(tc_pe, test_peer_entry_clear_null);
    tcase_add_test(tc_pe, test_peer_entry_is_set_null);
    tcase_add_test(tc_pe, test_peer_entry_is_set_false);
    tcase_add_test(tc_pe, test_peer_entry_is_set_true);
    tcase_add_test(tc_pe, test_peer_entry_has_cap_null);
    tcase_add_test(tc_pe, test_peer_entry_has_cap_true);
    tcase_add_test(tc_pe, test_peer_entry_is_expired_null);
    tcase_add_test(tc_pe, test_peer_entry_is_expired_never);
    tcase_add_test(tc_pe, test_peer_entry_is_expired_future);
    tcase_add_test(tc_pe, test_peer_entry_is_expired_past);
    tcase_add_test(tc_pe, test_peer_entry_equal_null_null);
    tcase_add_test(tc_pe, test_peer_entry_equal_null_nonnull);
    tcase_add_test(tc_pe, test_peer_entry_equal_same_addr);
    tcase_add_test(tc_pe, test_peer_entry_equal_different_addr);
    suite_add_tcase(s, tc_pe);

    TCase *tc_md = tcase_create("Metadata");
    tcase_add_test(tc_md, test_metadata_clear);
    tcase_add_test(tc_md, test_metadata_clear_null);
    suite_add_tcase(s, tc_md);

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null_storage);
    tcase_add_test(tc_life, test_init_null_hashes);
    tcase_add_test(tc_life, test_init_null_metadata_with_store);
    tcase_add_test(tc_life, test_init_ok);
    tcase_add_test(tc_life, test_clear_resets_counts);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_q = tcase_create("Query");
    tcase_add_test(tc_q, test_hash_count_null);
    tcase_add_test(tc_q, test_peer_count_null);
    tcase_add_test(tc_q, test_find_hash_null);
    tcase_add_test(tc_q, test_find_hash_missing);
    tcase_add_test(tc_q, test_find_hash_ok);
    suite_add_tcase(s, tc_q);

    TCase *tc_add = tcase_create("AddPeer");
    tcase_add_test(tc_add, test_add_peer_null);
    tcase_add_test(tc_add, test_add_peer_unset);
    tcase_add_test(tc_add, test_add_peer_new_hash);
    tcase_add_test(tc_add, test_add_peer_existing_hash);
    tcase_add_test(tc_add, test_add_peer_update_existing);
    tcase_add_test(tc_add, test_add_peer_hash_full);
    tcase_add_test(tc_add, test_add_peer_hash_table_full);
    suite_add_tcase(s, tc_add);

    TCase *tc_mdset = tcase_create("SetMetadata");
    tcase_add_test(tc_mdset, test_set_metadata_null);
    tcase_add_test(tc_mdset, test_set_metadata_not_supported);
    tcase_add_test(tc_mdset, test_set_metadata_ok);
    tcase_add_test(tc_mdset, test_set_metadata_not_found);
    suite_add_tcase(s, tc_mdset);

    TCase *tc_find = tcase_create("FindPeers");
    tcase_add_test(tc_find, test_find_peers_null);
    tcase_add_test(tc_find, test_find_peers_not_found);
    tcase_add_test(tc_find, test_find_peers_all);
    tcase_add_test(tc_find, test_find_peers_truncated);
    tcase_add_test(tc_find, test_find_peers_with_cap);
    tcase_add_test(tc_find, test_find_peers_with_cap_none_delegates);
    suite_add_tcase(s, tc_find);

    TCase *tc_rem = tcase_create("Remove");
    tcase_add_test(tc_rem, test_remove_peer_null);
    tcase_add_test(tc_rem, test_remove_peer_not_found);
    tcase_add_test(tc_rem, test_remove_peer_ok);
    tcase_add_test(tc_rem, test_remove_peer_auto_removes_hash);
    tcase_add_test(tc_rem, test_remove_hash_null);
    tcase_add_test(tc_rem, test_remove_hash_not_found);
    tcase_add_test(tc_rem, test_remove_hash_ok);
    suite_add_tcase(s, tc_rem);

    TCase *tc_exp = tcase_create("Expire");
    tcase_add_test(tc_exp, test_expire_null);
    tcase_add_test(tc_exp, test_expire_none);
    tcase_add_test(tc_exp, test_expire_one);
    tcase_add_test(tc_exp, test_expire_keeps_fresh);
    suite_add_tcase(s, tc_exp);

    return s;
}

int main(void)
{
    Suite *s = storage_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
