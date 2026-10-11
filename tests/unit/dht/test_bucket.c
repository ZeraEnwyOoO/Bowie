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
 * BOWIE — DHT BUCKET TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/bucket.c.
 *
 * The tests cover:
 *
 *   - Lifecycle: clear.
 *   - Query: is_empty, is_full, count, at, find.
 *   - Add: added, updated, cached, cache full, invalid.
 *   - Remove: promotes a replacement.
 *   - Seen / Failed / SetToken.
 *   - Selection: by XOR distance, skips bad nodes.
 *
 * The tests use a helper to fill nodes with deterministic IDs
 * so that the expected bucket state is visible in the test.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/bucket.h"               the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/bucket.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build a node with a deterministic id from a seed. The id is
 * the seed in the first byte, zero elsewhere. The address is
 * a valid IPv4 address with the seed as the last octet.
 */
static void make_node(bowie_dht_node_t *n, uint8_t seed)
{
    memset(n, 0, sizeof(*n));
    n->id.bytes[0] = seed;
    n->addr.family = BOWIE_AF_INET;
    n->addr.addr[0] = 10u;
    n->addr.addr[1] = 0u;
    n->addr.addr[2] = 0u;
    n->addr.addr[3] = seed;
    n->addr.port = (uint16_t)(6881u + seed);
}

static void make_id(bowie_dht_node_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0] = seed;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_clear_zeroes)
{
    bowie_dht_bucket_t b;
    bowie_dht_node_t n;
    make_node(&n, 1u);

    (void)bowie_dht_bucket_add(&b, &n, 100u);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 1u);

    bowie_dht_bucket_clear(&b);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 0u);
    ck_assert_uint_eq(bowie_dht_bucket_replacement_count(&b), 0u);
}
END_TEST

START_TEST(test_clear_null_is_noop)
{
    bowie_dht_bucket_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * QUERY — IS_EMPTY
 * ============================================================================
 */

START_TEST(test_is_empty_null)
{
    ck_assert(bowie_dht_bucket_is_empty(NULL));
}
END_TEST

START_TEST(test_is_empty_true)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    ck_assert(bowie_dht_bucket_is_empty(&b));
}
END_TEST

START_TEST(test_is_empty_false)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);
    ck_assert(!bowie_dht_bucket_is_empty(&b));
}
END_TEST

/*
 * ============================================================================
 * QUERY — IS_FULL
 * ============================================================================
 */

START_TEST(test_is_full_null)
{
    ck_assert(!bowie_dht_bucket_is_full(NULL));
}
END_TEST

START_TEST(test_is_full_empty)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    ck_assert(!bowie_dht_bucket_is_full(&b));
}
END_TEST

START_TEST(test_is_full_partial)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    for (uint8_t i = 1u; i < BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }
    ck_assert(!bowie_dht_bucket_is_full(&b));
}
END_TEST

START_TEST(test_is_full_exact)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    for (uint8_t i = 1u; i <= BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }
    ck_assert(bowie_dht_bucket_is_full(&b));
}
END_TEST

/*
 * ============================================================================
 * QUERY — COUNT / AT / FIND
 * ============================================================================
 */

START_TEST(test_count_null)
{
    ck_assert_uint_eq(bowie_dht_bucket_count(NULL), 0u);
}
END_TEST

START_TEST(test_at_null)
{
    ck_assert_ptr_null(bowie_dht_bucket_at(NULL, 0u));
}
END_TEST

START_TEST(test_at_out_of_range)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    ck_assert_ptr_null(bowie_dht_bucket_at(&b, 1u));
}
END_TEST

START_TEST(test_at_ok)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 42u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    const bowie_dht_node_t *found = bowie_dht_bucket_at(&b, 0u);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->id.bytes[0], 42u);
}
END_TEST

START_TEST(test_find_null)
{
    ck_assert_ptr_null(bowie_dht_bucket_find(NULL, NULL));
}
END_TEST

START_TEST(test_find_missing)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 99u);
    ck_assert_ptr_null(bowie_dht_bucket_find(&b, &id));
}
END_TEST

START_TEST(test_find_ok)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 42u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 42u);

    const bowie_dht_node_t *found = bowie_dht_bucket_find(&b, &id);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->addr.port, 6881u + 42u);
}
END_TEST

/*
 * ============================================================================
 * ADD
 * ============================================================================
 */

START_TEST(test_add_invalid_null_bucket)
{
    bowie_dht_node_t n;
    make_node(&n, 1u);
    ck_assert_int_eq(
        bowie_dht_bucket_add(NULL, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_invalid_null_node)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, NULL, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_invalid_unset_node)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));

    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_INVALID);
}
END_TEST

START_TEST(test_add_first)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);

    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, &n, 100u),
        BOWIE_DHT_BUCKET_ADD_ADDED);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 1u);
    ck_assert_uint_eq(b.last_changed_ms, 100u);
}
END_TEST

START_TEST(test_add_updates_existing)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, &n, 200u),
        BOWIE_DHT_BUCKET_ADD_UPDATED);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 1u);
    ck_assert_uint_eq(b.last_changed_ms, 200u);
}
END_TEST

START_TEST(test_add_fills_live)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    for (uint8_t i = 1u; i <= BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        ck_assert_int_eq(
            bowie_dht_bucket_add(&b, &n, 100u),
            BOWIE_DHT_BUCKET_ADD_ADDED);
    }
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), BOWIE_DHT_K);
    ck_assert(bowie_dht_bucket_is_full(&b));
}
END_TEST

START_TEST(test_add_caches_when_full)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    for (uint8_t i = 1u; i <= BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }

    bowie_dht_node_t extra;
    make_node(&extra, 100u);

    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, &extra, 200u),
        BOWIE_DHT_BUCKET_ADD_CACHED);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), BOWIE_DHT_K);
    ck_assert_uint_eq(bowie_dht_bucket_replacement_count(&b), 1u);
}
END_TEST

START_TEST(test_add_cache_full_evicts_oldest)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    for (uint8_t i = 1u; i <= BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }

    /*
     * Fill the cache with BOWIE_DHT_REPLACEMENT nodes.
     * The seeds are 100..100+REPLACEMENT-1.
     */
    for (uint8_t i = 0u; i < BOWIE_DHT_REPLACEMENT; i++) {
        bowie_dht_node_t n;
        make_node(&n, (uint8_t)(100u + i));
        ck_assert_int_eq(
            bowie_dht_bucket_add(&b, &n, 200u),
            BOWIE_DHT_BUCKET_ADD_CACHED);
    }

    ck_assert_uint_eq(bowie_dht_bucket_replacement_count(&b),
                      BOWIE_DHT_REPLACEMENT);

    /*
     * Add one more. The oldest cached node (seed 100) is
     * evicted.
     */
    bowie_dht_node_t n;
    make_node(&n, 200u);
    ck_assert_int_eq(
        bowie_dht_bucket_add(&b, &n, 300u),
        BOWIE_DHT_BUCKET_ADD_CACHED);

    /*
     * The oldest is gone. The new one is present.
     */
    bowie_dht_node_id_t id_old;
    make_id(&id_old, 100u);
    bowie_dht_node_id_t id_new;
    make_id(&id_new, 200u);

    /*
     * The old and new nodes are not in the live set. Check
     * the replacement cache directly.
     */
    int found_old = 0;
    int found_new = 0;
    for (size_t i = 0u; i < b.replacement_count; i++) {
        if (bowie_dht_node_id_equal(&b.replacements[i].id,
                                    &id_old)) {
            found_old = 1;
        }
        if (bowie_dht_node_id_equal(&b.replacements[i].id,
                                    &id_new)) {
            found_new = 1;
        }
    }
    ck_assert(!found_old);
    ck_assert(found_new);
}
END_TEST

/*
 * ============================================================================
 * REMOVE
 * ============================================================================
 */

START_TEST(test_remove_null)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    ck_assert_int_eq(bowie_dht_bucket_remove(NULL, &id, 100u),
                     BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(bowie_dht_bucket_remove(&b, NULL, 100u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remove_not_found)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 99u);

    ck_assert_int_eq(bowie_dht_bucket_remove(&b, &id, 100u),
                     BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_remove_ok)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    ck_assert_int_eq(bowie_dht_bucket_remove(&b, &id, 200u),
                     BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 0u);
    ck_assert_uint_eq(b.last_changed_ms, 200u);
}
END_TEST

START_TEST(test_remove_promotes_replacement)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    for (uint8_t i = 1u; i <= BOWIE_DHT_K; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }

    bowie_dht_node_t cached;
    make_node(&cached, 100u);
    (void)bowie_dht_bucket_add(&b, &cached, 100u);

    ck_assert_uint_eq(bowie_dht_bucket_replacement_count(&b), 1u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);
    ck_assert_int_eq(bowie_dht_bucket_remove(&b, &id, 200u),
                     BOWIE_OK);

    ck_assert_uint_eq(bowie_dht_bucket_count(&b), BOWIE_DHT_K);
    ck_assert_uint_eq(bowie_dht_bucket_replacement_count(&b), 0u);

    bowie_dht_node_id_t cached_id;
    make_id(&cached_id, 100u);
    ck_assert_ptr_nonnull(
        bowie_dht_bucket_find(&b, &cached_id));
}
END_TEST

/*
 * ============================================================================
 * SEEN / FAILED / SET_TOKEN
 * ============================================================================
 */

START_TEST(test_seen_null)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 1u);
    ck_assert_int_eq(bowie_dht_bucket_seen(NULL, &id, 100u),
                     BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(bowie_dht_bucket_seen(&b, NULL, 100u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_seen_not_found)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 99u);
    ck_assert_int_eq(bowie_dht_bucket_seen(&b, &id, 100u),
                     BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_seen_resets_fail_count)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    (void)bowie_dht_bucket_failed(&b, &id, 100u);
    (void)bowie_dht_bucket_failed(&b, &id, 100u);

    ck_assert_int_eq(bowie_dht_bucket_seen(&b, &id, 300u),
                     BOWIE_OK);

    const bowie_dht_node_t *found = bowie_dht_bucket_find(&b, &id);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->fail_count, 0u);
    ck_assert_uint_eq(found->last_seen_ms, 300u);
}
END_TEST

START_TEST(test_failed_increments)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    ck_assert_int_eq(bowie_dht_bucket_failed(&b, &id, 100u),
                     BOWIE_OK);

    const bowie_dht_node_t *found = bowie_dht_bucket_find(&b, &id);
    ck_assert_ptr_nonnull(found);
    ck_assert_uint_eq(found->fail_count, 1u);
}
END_TEST

START_TEST(test_failed_three_times_removes)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    (void)bowie_dht_bucket_failed(&b, &id, 100u);
    (void)bowie_dht_bucket_failed(&b, &id, 100u);
    (void)bowie_dht_bucket_failed(&b, &id, 100u);

    ck_assert_uint_eq(bowie_dht_bucket_count(&b), 0u);
    ck_assert_ptr_null(bowie_dht_bucket_find(&b, &id));
}
END_TEST

START_TEST(test_failed_null)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 1u);
    ck_assert_int_eq(bowie_dht_bucket_failed(NULL, &id, 100u),
                     BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(bowie_dht_bucket_failed(&b, NULL, 100u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_set_token_null)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 1u);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));

    ck_assert_int_eq(
        bowie_dht_bucket_set_token(NULL, &id, &t),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_bucket_set_token(&b, NULL, &t),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_set_token_not_found)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t id;
    make_id(&id, 99u);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));

    ck_assert_int_eq(
        bowie_dht_bucket_set_token(&b, &id, &t),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_set_token_ok)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t id;
    make_id(&id, 1u);

    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.bytes[0] = 0xAA;
    t.len = 1u;

    ck_assert_int_eq(bowie_dht_bucket_set_token(&b, &id, &t),
                     BOWIE_OK);

    const bowie_dht_node_t *found = bowie_dht_bucket_find(&b, &id);
    ck_assert_ptr_nonnull(found);
    ck_assert_int_eq(found->has_token, 1);
    ck_assert_uint_eq(found->token.len, 1u);
    ck_assert_uint_eq(found->token.bytes[0], 0xAAu);
}
END_TEST

/*
 * ============================================================================
 * SELECT CLOSEST
 * ============================================================================
 */

START_TEST(test_select_null)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t target;
    make_id(&target, 1u);
    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(NULL, &target, 100u,
                                        out, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, NULL, 100u,
                                        out, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        NULL, 8u, &count),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        out, 8u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_select_empty_bucket)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));
    bowie_dht_node_id_t target;
    make_id(&target, 1u);
    bowie_dht_node_t out[8];
    size_t count = 99u;

    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 0u);
}
END_TEST

START_TEST(test_select_sorted_by_distance)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    /*
     * Target is 0x10. The nodes are 0x00, 0x20, 0x18.
     * Distances:
     *   0x10 ^ 0x00 = 0x10
     *   0x10 ^ 0x20 = 0x30
     *   0x10 ^ 0x18 = 0x08
     * Sorted: 0x18 (0x08), 0x00 (0x10), 0x20 (0x30).
     */
    bowie_dht_node_t n;
    make_node(&n, 0x00u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);
    make_node(&n, 0x20u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);
    make_node(&n, 0x18u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    bowie_dht_node_id_t target;
    make_id(&target, 0x10u);

    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 3u);
    ck_assert_uint_eq(out[0].id.bytes[0], 0x18u);
    ck_assert_uint_eq(out[1].id.bytes[0], 0x00u);
    ck_assert_uint_eq(out[2].id.bytes[0], 0x20u);
}
END_TEST

START_TEST(test_select_skips_failed)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    bowie_dht_node_t n;
    make_node(&n, 0x18u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);
    make_node(&n, 0x00u);
    (void)bowie_dht_bucket_add(&b, &n, 100u);

    /*
     * Fail the closest node three times so it is removed.
     * (Three failures removes it from the live set.)
     */
    bowie_dht_node_id_t fail_id;
    make_id(&fail_id, 0x18u);
    (void)bowie_dht_bucket_failed(&b, &fail_id, 100u);
    (void)bowie_dht_bucket_failed(&b, &fail_id, 100u);
    (void)bowie_dht_bucket_failed(&b, &fail_id, 100u);

    bowie_dht_node_id_t target;
    make_id(&target, 0x10u);

    bowie_dht_node_t out[8];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        out, 8u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 1u);
    ck_assert_uint_eq(out[0].id.bytes[0], 0x00u);
}
END_TEST

START_TEST(test_select_respects_out_cap)
{
    bowie_dht_bucket_t b;
    memset(&b, 0, sizeof(b));

    for (uint8_t i = 1u; i <= 4u; i++) {
        bowie_dht_node_t n;
        make_node(&n, i);
        (void)bowie_dht_bucket_add(&b, &n, 100u);
    }

    bowie_dht_node_id_t target;
    make_id(&target, 0u);

    bowie_dht_node_t out[2];
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_bucket_select_closest(&b, &target, 100u,
                                        out, 2u, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 2u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *bucket_suite(void)
{
    Suite *s = suite_create("DhtBucket");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_clear_zeroes);
    tcase_add_test(tc_life, test_clear_null_is_noop);
    suite_add_tcase(s, tc_life);

    TCase *tc_empty = tcase_create("IsEmpty");
    tcase_add_test(tc_empty, test_is_empty_null);
    tcase_add_test(tc_empty, test_is_empty_true);
    tcase_add_test(tc_empty, test_is_empty_false);
    suite_add_tcase(s, tc_empty);

    TCase *tc_full = tcase_create("IsFull");
    tcase_add_test(tc_full, test_is_full_null);
    tcase_add_test(tc_full, test_is_full_empty);
    tcase_add_test(tc_full, test_is_full_partial);
    tcase_add_test(tc_full, test_is_full_exact);
    suite_add_tcase(s, tc_full);

    TCase *tc_q = tcase_create("Query");
    tcase_add_test(tc_q, test_count_null);
    tcase_add_test(tc_q, test_at_null);
    tcase_add_test(tc_q, test_at_out_of_range);
    tcase_add_test(tc_q, test_at_ok);
    tcase_add_test(tc_q, test_find_null);
    tcase_add_test(tc_q, test_find_missing);
    tcase_add_test(tc_q, test_find_ok);
    suite_add_tcase(s, tc_q);

    TCase *tc_add = tcase_create("Add");
    tcase_add_test(tc_add, test_add_invalid_null_bucket);
    tcase_add_test(tc_add, test_add_invalid_null_node);
    tcase_add_test(tc_add, test_add_invalid_unset_node);
    tcase_add_test(tc_add, test_add_first);
    tcase_add_test(tc_add, test_add_updates_existing);
    tcase_add_test(tc_add, test_add_fills_live);
    tcase_add_test(tc_add, test_add_caches_when_full);
    tcase_add_test(tc_add, test_add_cache_full_evicts_oldest);
    suite_add_tcase(s, tc_add);

    TCase *tc_rem = tcase_create("Remove");
    tcase_add_test(tc_rem, test_remove_null);
    tcase_add_test(tc_rem, test_remove_not_found);
    tcase_add_test(tc_rem, test_remove_ok);
    tcase_add_test(tc_rem, test_remove_promotes_replacement);
    suite_add_tcase(s, tc_rem);

    TCase *tc_seen = tcase_create("Seen");
    tcase_add_test(tc_seen, test_seen_null);
    tcase_add_test(tc_seen, test_seen_not_found);
    tcase_add_test(tc_seen, test_seen_resets_fail_count);
    suite_add_tcase(s, tc_seen);

    TCase *tc_fail = tcase_create("Failed");
    tcase_add_test(tc_fail, test_failed_increments);
    tcase_add_test(tc_fail, test_failed_three_times_removes);
    tcase_add_test(tc_fail, test_failed_null);
    suite_add_tcase(s, tc_fail);

    TCase *tc_tok = tcase_create("SetToken");
    tcase_add_test(tc_tok, test_set_token_null);
    tcase_add_test(tc_tok, test_set_token_not_found);
    tcase_add_test(tc_tok, test_set_token_ok);
    suite_add_tcase(s, tc_tok);

    TCase *tc_sel = tcase_create("SelectClosest");
    tcase_add_test(tc_sel, test_select_null);
    tcase_add_test(tc_sel, test_select_empty_bucket);
    tcase_add_test(tc_sel, test_select_sorted_by_distance);
    tcase_add_test(tc_sel, test_select_skips_failed);
    tcase_add_test(tc_sel, test_select_respects_out_cap);
    suite_add_tcase(s, tc_sel);

    return s;
}

int main(void)
{
    Suite *s = bucket_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
