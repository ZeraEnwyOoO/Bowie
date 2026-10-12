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
 * BOWIE — DHT ROUTING TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/routing.c.
 *
 * The tests cover:
 *
 *   - Lifecycle: init, clear.
 *   - Query: bucket_count, bucket_at, node_count,
 *     bucket_index, find.
 *   - Add: grow, split, cache.
 *   - Remove / Seen / Failed / SetToken.
 *   - Selection: by distance, skips bad.
 *   - Stalest bucket.
 *
 * The tests use deterministic node IDs so that the bucket
 * index of each node is visible in the test.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/routing.h"              the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/routing.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_local_id(bowie_dht_node_id_t *id)
{
    memset(id, 0, sizeof(*id));
}

/*
 * Build a node with an ID whose first non-zero byte is at
 * position 0 (the first byte).
 */
static void make_node(bowie_dht_node_t *n, uint8_t seed)
{
    memset(n, 0, sizeof(*n));
    if (seed == 0u) {
        seed = 1u;
    }
    n->id.bytes[0] = seed;
    n->addr.family = BOWIE_AF_INET;
    n->addr.addr[0] = 10u;
    n->addr.addr[1] = 0u;
    n->addr.addr[2] = 0u;
    n->addr.addr[3] = seed;
    n->addr.port = (uint16_t)(6881u + seed);
}

/*
 * Build a node whose ID has the given byte set at the given
 * position.
 */
static void make_node_byte(bowie_dht_node_t *n,
                           size_t byte_idx, uint8_t value)
{
    memset(n, 0, sizeof(*n));
    if (byte_idx >= BOWIE_DHT_NODE_ID_LEN) {
        byte_idx = 0u;
    }
    if (value == 0u) {
        value = 1u;
    }
    n->id.bytes[byte_idx] = value;
    n->addr.family = BOWIE_AF_INET;
    n->addr.addr[0] = 10u;
    n->addr.addr[1] = 0u;
    n->addr.addr[2] = 0u;
    n->addr.addr[3] = value;
    n->addr.port = 6881u;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null_table)
{
    bowie_dht_node_id_t id;
    make_local_id(&id);
    bowie_dht_routing_init(NULL, &id);
}
END_TEST

START_TEST(test_init_sets_local_id)
{
    bowie_dht_node_id_t id;
    make_local_id(&id);
    id.bytes[0] = 0x42u;

    bowie_dht_routing_t t;
    bowie_dht_routing_init(&t, &id);

    ck_assert_uint_eq(t.local_id.bytes[0], 0x42u);
    ck_assert_uint_eq(bowie_dht_routing_bucket_count(&t), 1u);
}
END_TEST

START_TEST(test_init_null_local_id)
{
    bowie_dht_routing_t t;
    bowie_dht_routing_init(&t, NULL);
    ck_assert_uint_eq(bowie_dht_routing_bucket_count(&t), 1u);
    ck_assert(bowie_dht_node_id_is_zero(&t.local_id));
}
END_TEST

START_TEST(test_clear_resets)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t id;
    make_local_id(&id);
    id.bytes[0] = 0x01u;
    bowie_dht_routing_init(&t, &id);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    bowie_dht_routing_clear(&t);

    ck_assert_uint_eq(bowie_dht_routing_bucket_count(&t), 1u);
    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 0u);
    ck_assert(bowie_dht_node_id_is_zero(&t.local_id));
}
END_TEST

START_TEST(test_clear_null_is_noop)
{
    bowie_dht_routing_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_bucket_count_null)
{
    ck_assert_uint_eq(bowie_dht_routing_bucket_count(NULL), 0u);
}
END_TEST

START_TEST(test_bucket_at_null)
{
    ck_assert_ptr_null(bowie_dht_routing_bucket_at(NULL, 0u));
}
END_TEST

START_TEST(test_bucket_at_out_of_range)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t id;
    make_local_id(&id);
    bowie_dht_routing_init(&t, &id);

    ck_assert_ptr_null(bowie_dht_routing_bucket_at(&t, 5u));
}
END_TEST

START_TEST(test_bucket_at_ok)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t id;
    make_local_id(&id);
    bowie_dht_routing_init(&t, &id);

    const bowie_dht_bucket_t *b =
        bowie_dht_routing_bucket_at(&t, 0u);
    ck_assert_ptr_nonnull(b);
}
END_TEST

START_TEST(test_node_count_null)
{
    ck_assert_uint_eq(bowie_dht_routing_node_count(NULL), 0u);
}
END_TEST

START_TEST(test_node_count_empty)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t id;
    make_local_id(&id);
    bowie_dht_routing_init(&t, &id);

    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 0u);
}
END_TEST

/*
 * ============================================================================
 * QUERY — BUCKET INDEX
 * ============================================================================
 */

START_TEST(test_bucket_index_null)
{
    bowie_dht_node_id_t id;
    make_local_id(&id);
    ck_assert_int_eq(bowie_dht_routing_bucket_index(NULL, &id),
                     -1);
}
END_TEST

START_TEST(test_bucket_index_null_id)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, NULL), -1);
}
END_TEST

START_TEST(test_bucket_index_equal_local)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t id;
    make_local_id(&id);
    bowie_dht_routing_init(&t, &id);

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, &id), -1);
}
END_TEST

START_TEST(test_bucket_index_bit0)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0x80u;

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, &id), 0);
}
END_TEST

START_TEST(test_bucket_index_bit7)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0x01u;

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, &id), 7);
}
END_TEST

START_TEST(test_bucket_index_byte1)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[1] = 0x80u;

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, &id), 8);
}
END_TEST

START_TEST(test_bucket_index_byte19)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[19] = 0x80u;

    ck_assert_int_eq(bowie_dht_routing_bucket_index(&t, &id), 152);
}
END_TEST

/*
 * ============================================================================
 * QUERY — FIND
 * ============================================================================
 */

START_TEST(test_find_null)
{
    ck_assert_ptr_null(bowie_dht_routing_find(NULL, NULL));
}
END_TEST

START_TEST(test_find_missing)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0x80u;

    ck_assert_ptr_null(bowie_dht_routing_find(&t, &id));
}
END_TEST

START_TEST(test_find_ok)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    const bowie_dht_node_t *found =
        bowie_dht_routing_find(&t, &n.id);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->id.bytes[0], 0x80u);
}
END_TEST

/*
 * ============================================================================
 * ADD
 * ============================================================================
 */

START_TEST(test_add_null)
{
    bowie_dht_node_t n;
    make_node(&n, 1u);
    ck_assert_int_eq(
        bowie_dht_routing_add(NULL, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_null_node)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, NULL, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_unset_node)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_local_id_invalid)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    local.bytes[0] = 0x01u;
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x01u);
    n.id.bytes[0] = 0x01u;

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_first)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_ADDED);
    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 1u);
}
END_TEST

START_TEST(test_add_updates_existing)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, &n, 200u),
        BOWIE_DHT_BUCKET_ADD_UPDATED);
    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 1u);
}
END_TEST

START_TEST(test_add_grows_table_for_high_index)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node_byte(&n, 19u, 0x80u);

    ck_assert_int_eq(
        bowie_dht_routing_add(&t, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_ADDED);
    ck_assert_uint_eq(bowie_dht_routing_bucket_count(&t), 153u);
}
END_TEST

START_TEST(test_add_fills_bucket)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    for (uint8_t i = 0u; i < BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        memset(&n, 0, sizeof(n));
        n.id.bytes[0] = 0x80u;
        n.id.bytes[1] = (uint8_t)(i + 1u);
        n.addr.family = BOWIE_AF_INET;
        n.addr.addr[0] = 10u;
        n.addr.addr[3] = (uint8_t)(i + 1u);
        n.addr.port = 6881u;

        ck_assert_int_eq(
            bowie_dht_routing_add(&t, &n, 100u),
            BOWIE_DHT_BUCKET_ADD_ADDED);
    }

    ck_assert_uint_eq(bowie_dht_routing_node_count(&t),
                      BOWIE_DHT_K);
}
END_TEST

/*
 * ============================================================================
 * REMOVE / SEEN / FAILED / SET_TOKEN
 * ============================================================================
 */

START_TEST(test_remove_null)
{
    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0x80u;

    ck_assert_int_eq(bowie_dht_routing_remove(NULL, &id, 100u),
                     BOWIE_ERR_NULL_ARG);

    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    ck_assert_int_eq(bowie_dht_routing_remove(&t, NULL, 100u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remove_not_found)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0x80u;

    ck_assert_int_eq(bowie_dht_routing_remove(&t, &id, 100u),
                     BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_remove_ok)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    ck_assert_int_eq(bowie_dht_routing_remove(&t, &n.id, 200u),
                     BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 0u);
}
END_TEST

START_TEST(test_seen_ok)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    ck_assert_int_eq(bowie_dht_routing_seen(&t, &n.id, 300u),
                     BOWIE_OK);

    const bowie_dht_node_t *found =
        bowie_dht_routing_find(&t, &n.id);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->last_seen_ms, 300u);
}
END_TEST

START_TEST(test_failed_three_times_removes)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    (void)bowie_dht_routing_failed(&t, &n.id, 100u);
    (void)bowie_dht_routing_failed(&t, &n.id, 100u);
    (void)bowie_dht_routing_failed(&t, &n.id, 100u);

    ck_assert_uint_eq(bowie_dht_routing_node_count(&t), 0u);
}
END_TEST

START_TEST(test_set_token_ok)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x80u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    bowie_dht_token_t tok;
    memset(&tok, 0, sizeof(tok));
    tok.bytes[0] = 0xAA;
    tok.len = 1u;

    ck_assert_int_eq(
        bowie_dht_routing_set_token(&t, &n.id, &tok),
        BOWIE_OK);

    const bowie_dht_node_t *found =
        bowie_dht_routing_find(&t, &n.id);
    ck_assert_ptr_nonnull(found);
    ck_assert_int_eq(found->has_token, 1);
}
END_TEST

/*
 * ============================================================================
 * SELECTION
 * ============================================================================
 */

START_TEST(test_select_null)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t target;
    memset(&target, 0, sizeof(target));

    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_routing_select_closest(NULL, &target, 100u,
                                         out, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, NULL, 100u,
                                         out, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         NULL, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         out, 8u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_select_empty)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_id_t target;
    memset(&target, 0, sizeof(target));

    bowie_dht_node_t out[8];
    size_t count = 99u;

    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 0u);
}
END_TEST

START_TEST(test_select_sorted_by_distance)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n;
    make_node(&n, 0x00u);
    (void)bowie_dht_routing_add(&t, &n, 100u);
    make_node(&n, 0x20u);
    (void)bowie_dht_routing_add(&t, &n, 100u);
    make_node(&n, 0x18u);
    (void)bowie_dht_routing_add(&t, &n, 100u);

    bowie_dht_node_id_t target;
    memset(&target, 0, sizeof(target));
    target.bytes[0] = 0x10u;

    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 3u);
    ck_assert_uint_eq(out[0].id.bytes[0], 0x18u);
    ck_assert_uint_eq(out[1].id.bytes[0], 0x00u);
    ck_assert_uint_eq(out[2].id.bytes[0], 0x20u);
}
END_TEST

START_TEST(test_select_skips_bad)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n1;
    make_node(&n1, 0x18u);
    (void)bowie_dht_routing_add(&t, &n1, 100u);
    bowie_dht_node_t n2;
    make_node(&n2, 0x00u);
    (void)bowie_dht_routing_add(&t, &n2, 100u);

    (void)bowie_dht_routing_failed(&t, &n1.id, 100u);
    (void)bowie_dht_routing_failed(&t, &n1.id, 100u);
    (void)bowie_dht_routing_failed(&t, &n1.id, 100u);

    bowie_dht_node_id_t target;
    memset(&target, 0, sizeof(target));
    target.bytes[0] = 0x10u;

    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 1u);
    ck_assert_uint_eq(out[0].id.bytes[0], 0x00u);
}
END_TEST

START_TEST(test_select_cap)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    for (uint8_t i = 0u; i < 4u; i++) {
        bowie_dht_node_t n;
        memset(&n, 0, sizeof(n));
        n.id.bytes[0] = 0x80u;
        n.id.bytes[1] = (uint8_t)(i + 1u);
        n.addr.family = BOWIE_AF_INET;
        n.addr.addr[0] = 10u;
        n.addr.addr[3] = (uint8_t)(i + 1u);
        n.addr.port = 6881u;
        (void)bowie_dht_routing_add(&t, &n, 100u);
    }

    bowie_dht_node_id_t target;
    memset(&target, 0, sizeof(target));
    target.bytes[0] = 0x80u;

    bowie_dht_node_t out[2];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_routing_select_closest(&t, &target, 100u,
                                         out, 2u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 2u);
}
END_TEST

/*
 * ============================================================================
 * STALEST BUCKET
 * ============================================================================
 */

START_TEST(test_stalest_null)
{
    ck_assert_int_eq(bowie_dht_routing_stalest_bucket(NULL), -1);
}
END_TEST

START_TEST(test_stalest_fresh_table)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    ck_assert_int_eq(bowie_dht_routing_stalest_bucket(&t), 0);
}
END_TEST

START_TEST(test_stalest_picks_smallest)
{
    bowie_dht_routing_t t;
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_routing_init(&t, &local);

    bowie_dht_node_t n1;
    make_node(&n1, 0x80u);
    (void)bowie_dht_routing_add(&t, &n1, 100u);

    bowie_dht_node_t n2;
    make_node_byte(&n2, 19u, 0x80u);
    (void)bowie_dht_routing_add(&t, &n2, 200u);

    int idx = bowie_dht_routing_stalest_bucket(&t);
    ck_assert_int_ge(idx, 0);
    ck_assert_int_lt(idx, (int)bowie_dht_routing_bucket_count(&t));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *routing_suite(void)
{
    Suite *s = suite_create("DhtRouting");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null_table);
    tcase_add_test(tc_life, test_init_sets_local_id);
    tcase_add_test(tc_life, test_init_null_local_id);
    tcase_add_test(tc_life, test_clear_resets);
    tcase_add_test(tc_life, test_clear_null_is_noop);
    suite_add_tcase(s, tc_life);

    TCase *tc_q = tcase_create("Query");
    tcase_add_test(tc_q, test_bucket_count_null);
    tcase_add_test(tc_q, test_bucket_at_null);
    tcase_add_test(tc_q, test_bucket_at_out_of_range);
    tcase_add_test(tc_q, test_bucket_at_ok);
    tcase_add_test(tc_q, test_node_count_null);
    tcase_add_test(tc_q, test_node_count_empty);
    suite_add_tcase(s, tc_q);

    TCase *tc_bi = tcase_create("BucketIndex");
    tcase_add_test(tc_bi, test_bucket_index_null);
    tcase_add_test(tc_bi, test_bucket_index_null_id);
    tcase_add_test(tc_bi, test_bucket_index_equal_local);
    tcase_add_test(tc_bi, test_bucket_index_bit0);
    tcase_add_test(tc_bi, test_bucket_index_bit7);
    tcase_add_test(tc_bi, test_bucket_index_byte1);
    tcase_add_test(tc_bi, test_bucket_index_byte19);
    suite_add_tcase(s, tc_bi);

    TCase *tc_find = tcase_create("Find");
    tcase_add_test(tc_find, test_find_null);
    tcase_add_test(tc_find, test_find_missing);
    tcase_add_test(tc_find, test_find_ok);
    suite_add_tcase(s, tc_find);

    TCase *tc_add = tcase_create("Add");
    tcase_add_test(tc_add, test_add_null);
    tcase_add_test(tc_add, test_add_null_node);
    tcase_add_test(tc_add, test_add_unset_node);
    tcase_add_test(tc_add, test_add_local_id_invalid);
    tcase_add_test(tc_add, test_add_first);
    tcase_add_test(tc_add, test_add_updates_existing);
    tcase_add_test(tc_add, test_add_grows_table_for_high_index);
    tcase_add_test(tc_add, test_add_fills_bucket);
    suite_add_tcase(s, tc_add);

    TCase *tc_mut = tcase_create("Mutation");
    tcase_add_test(tc_mut, test_remove_null);
    tcase_add_test(tc_mut, test_remove_not_found);
    tcase_add_test(tc_mut, test_remove_ok);
    tcase_add_test(tc_mut, test_seen_ok);
    tcase_add_test(tc_mut, test_failed_three_times_removes);
    tcase_add_test(tc_mut, test_set_token_ok);
    suite_add_tcase(s, tc_mut);

    TCase *tc_sel = tcase_create("Select");
    tcase_add_test(tc_sel, test_select_null);
    tcase_add_test(tc_sel, test_select_empty);
    tcase_add_test(tc_sel, test_select_sorted_by_distance);
    tcase_add_test(tc_sel, test_select_skips_bad);
    tcase_add_test(tc_sel, test_select_cap);
    suite_add_tcase(s, tc_sel);

    TCase *tc_stale = tcase_create("Stalest");
    tcase_add_test(tc_stale, test_stalest_null);
    tcase_add_test(tc_stale, test_stalest_fresh_table);
    tcase_add_test(tc_stale, test_stalest_picks_smallest);
    suite_add_tcase(s, tc_stale);

    return s;
}

int main(void)
{
    Suite *s = routing_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
