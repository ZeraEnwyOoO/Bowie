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
 * BOWIE — DHT NODE TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/node.c.
 *
 * The tests cover:
 *
 *   - Lifecycle: clear.
 *   - Query: is_set, equal, has_token.
 *   - Distance: XOR, compare, first_bit.
 *   - Staleness: fresh, failed, good.
 *   - Mutation: seen, failed, set_token.
 *   - Compact format: from_compact, to_compact.
 *
 * The distance tests use hand-computed values so that the
 * expected result is visible in the test, not derived from the
 * code under test.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/node.h"                 the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/node.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_id(bowie_dht_node_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_NODE_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_hash(bowie_dht_info_hash_t *h, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_INFO_HASH_LEN; i++) {
        h->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_addr(bowie_addr_t *a, uint8_t last_octet,
                      uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->family = BOWIE_AF_INET;
    a->addr[0] = 10u;
    a->addr[1] = 0u;
    a->addr[2] = 0u;
    a->addr[3] = last_octet;
    a->port = port;
}

static void make_node(bowie_dht_node_t *n, uint8_t seed,
                      uint8_t last_octet, uint16_t port)
{
    memset(n, 0, sizeof(*n));
    make_id(&n->id, seed);
    make_addr(&n->addr, last_octet, port);
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_clear_zeroes_everything)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 5u, 6881u);
    n.last_seen_ms = 12345u;
    n.fail_count   = 7u;
    n.token.bytes[0] = 0xAA;
    n.token.len = 1u;
    n.has_token = 1;

    bowie_dht_node_clear(&n);

    ck_assert(bowie_dht_node_id_is_zero(&n.id));
    ck_assert_int_eq(n.addr.family, BOWIE_AF_UNSPEC);
    ck_assert_uint_eq(n.last_seen_ms, 0u);
    ck_assert_uint_eq(n.fail_count, 0u);
    ck_assert_uint_eq(n.token.len, 0u);
    ck_assert_int_eq(n.has_token, 0);
}
END_TEST

START_TEST(test_clear_null_is_noop)
{
    bowie_dht_node_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * QUERY — IS_SET
 * ============================================================================
 */

START_TEST(test_is_set_null)
{
    ck_assert(!bowie_dht_node_is_set(NULL));
}
END_TEST

START_TEST(test_is_set_zeroed)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(!bowie_dht_node_is_set(&n));
}
END_TEST

START_TEST(test_is_set_id_only)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    make_id(&n.id, 1u);
    ck_assert(!bowie_dht_node_is_set(&n));
}
END_TEST

START_TEST(test_is_set_addr_only)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    make_addr(&n.addr, 1u, 6881u);
    ck_assert(!bowie_dht_node_is_set(&n));
}
END_TEST

START_TEST(test_is_set_both)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 1u, 6881u);
    ck_assert(bowie_dht_node_is_set(&n));
}
END_TEST

/*
 * ============================================================================
 * QUERY — EQUAL
 * ============================================================================
 */

START_TEST(test_equal_null_null)
{
    ck_assert(bowie_dht_node_equal(NULL, NULL));
}
END_TEST

START_TEST(test_equal_null_unset)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(bowie_dht_node_equal(NULL, &n));
    ck_assert(bowie_dht_node_equal(&n, NULL));
}
END_TEST

START_TEST(test_equal_null_set)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 1u, 6881u);
    ck_assert(!bowie_dht_node_equal(NULL, &n));
}
END_TEST

START_TEST(test_equal_same_id_different_addr)
{
    bowie_dht_node_t a;
    bowie_dht_node_t b;
    make_node(&a, 5u, 1u, 1111u);
    make_node(&b, 5u, 2u, 2222u);
    ck_assert(bowie_dht_node_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_different_id)
{
    bowie_dht_node_t a;
    bowie_dht_node_t b;
    make_node(&a, 5u, 1u, 6881u);
    make_node(&b, 6u, 1u, 6881u);
    ck_assert(!bowie_dht_node_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_two_unset)
{
    bowie_dht_node_t a;
    bowie_dht_node_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    ck_assert(bowie_dht_node_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * QUERY — HAS_TOKEN
 * ============================================================================
 */

START_TEST(test_has_token_null)
{
    ck_assert(!bowie_dht_node_has_token(NULL));
}
END_TEST

START_TEST(test_has_token_false)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(!bowie_dht_node_has_token(&n));
}
END_TEST

START_TEST(test_has_token_true)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.has_token = 1;
    ck_assert(bowie_dht_node_has_token(&n));
}
END_TEST

/*
 * ============================================================================
 * DISTANCE — XOR
 * ============================================================================
 */

START_TEST(test_distance_between_ids_null)
{
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    bowie_dht_distance_t d;
    make_id(&a, 1u);
    make_id(&b, 2u);

    ck_assert_int_eq(
        bowie_dht_distance_between_ids(NULL, &b, &d),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&a, NULL, &d),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&a, &b, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_distance_between_ids_zero)
{
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    bowie_dht_distance_t d;
    make_id(&a, 5u);
    make_id(&b, 5u);

    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&a, &b, &d),
        BOWIE_OK);
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        ck_assert_uint_eq(d.bytes[i], 0u);
    }
}
END_TEST

START_TEST(test_distance_between_ids_xor)
{
    /*
     * a = 0x00, 0x00, ..., 0x00
     * b = 0xFF, 0xFF, ..., 0xFF
     * The XOR is all ones.
     */
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    bowie_dht_distance_t d;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0xFF, sizeof(b));

    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&a, &b, &d),
        BOWIE_OK);
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        ck_assert_uint_eq(d.bytes[i], 0xFFu);
    }
}
END_TEST

START_TEST(test_distance_between_ids_symmetric)
{
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    bowie_dht_distance_t d1;
    bowie_dht_distance_t d2;
    make_id(&a, 1u);
    make_id(&b, 50u);

    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&a, &b, &d1),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_distance_between_ids(&b, &a, &d2),
        BOWIE_OK);

    ck_assert(bowie_dht_distance_equal(&d1, &d2));
}
END_TEST

START_TEST(test_distance_id_to_hash)
{
    bowie_dht_node_id_t id;
    bowie_dht_info_hash_t h;
    bowie_dht_distance_t d;
    memset(&id, 0x00, sizeof(id));
    memset(&h, 0x00, sizeof(h));
    h.bytes[0] = 0x01;

    ck_assert_int_eq(
        bowie_dht_distance_id_to_hash(&id, &h, &d),
        BOWIE_OK);
    ck_assert_uint_eq(d.bytes[0], 0x01u);
    for (size_t i = 1u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        ck_assert_uint_eq(d.bytes[i], 0u);
    }
}
END_TEST

/*
 * ============================================================================
 * DISTANCE — COMPARE
 * ============================================================================
 */

START_TEST(test_distance_compare_null_null)
{
    ck_assert_int_eq(bowie_dht_distance_compare(NULL, NULL), 0);
}
END_TEST

START_TEST(test_distance_compare_null_a)
{
    bowie_dht_distance_t b;
    memset(&b, 0, sizeof(b));
    ck_assert_int_eq(bowie_dht_distance_compare(NULL, &b), -1);
}
END_TEST

START_TEST(test_distance_compare_null_b)
{
    bowie_dht_distance_t a;
    memset(&a, 0, sizeof(a));
    ck_assert_int_eq(bowie_dht_distance_compare(&a, NULL), 1);
}
END_TEST

START_TEST(test_distance_compare_equal)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    memset(&a, 0xAA, sizeof(a));
    memset(&b, 0xAA, sizeof(b));
    ck_assert_int_eq(bowie_dht_distance_compare(&a, &b), 0);
}
END_TEST

START_TEST(test_distance_compare_less)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.bytes[0] = 0x01;
    b.bytes[0] = 0x02;
    ck_assert_int_eq(bowie_dht_distance_compare(&a, &b), -1);
}
END_TEST

START_TEST(test_distance_compare_greater)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.bytes[0] = 0x03;
    b.bytes[0] = 0x02;
    ck_assert_int_eq(bowie_dht_distance_compare(&a, &b), 1);
}
END_TEST

START_TEST(test_distance_compare_last_byte)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.bytes[BOWIE_DHT_DISTANCE_LEN - 1u] = 0x01;
    b.bytes[BOWIE_DHT_DISTANCE_LEN - 1u] = 0x02;
    ck_assert_int_eq(bowie_dht_distance_compare(&a, &b), -1);
}
END_TEST

/*
 * ============================================================================
 * DISTANCE — FIRST BIT
 * ============================================================================
 */

START_TEST(test_distance_first_bit_null)
{
    ck_assert_int_eq(bowie_dht_distance_first_bit(NULL), -1);
}
END_TEST

START_TEST(test_distance_first_bit_zero)
{
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), -1);
}
END_TEST

START_TEST(test_distance_first_bit_bit0)
{
    /* 0x80 = 1000 0000. First set bit is position 0. */
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    d.bytes[0] = 0x80u;
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), 0);
}
END_TEST

START_TEST(test_distance_first_bit_bit7)
{
    /* 0x01 = 0000 0001. First set bit is position 7. */
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    d.bytes[0] = 0x01u;
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), 7);
}
END_TEST

START_TEST(test_distance_first_bit_byte1)
{
    /* First set bit in byte 1: position 8 + 0 = 8. */
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    d.bytes[1] = 0x80u;
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), 8);
}
END_TEST

START_TEST(test_distance_first_bit_byte19)
{
    /* First set bit in byte 19: position 19 * 8 + 0 = 152. */
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    d.bytes[19] = 0x80u;
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), 152);
}
END_TEST

START_TEST(test_distance_first_bit_middle_of_byte)
{
    /* 0x10 = 0001 0000. First set bit is position 3. */
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    d.bytes[0] = 0x10u;
    ck_assert_int_eq(bowie_dht_distance_first_bit(&d), 3);
}
END_TEST

/*
 * ============================================================================
 * STALENESS
 * ============================================================================
 */

START_TEST(test_is_fresh_null)
{
    ck_assert(!bowie_dht_node_is_fresh(NULL, 1000u));
}
END_TEST

START_TEST(test_is_fresh_never_seen)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(!bowie_dht_node_is_fresh(&n, 1000u));
}
END_TEST

START_TEST(test_is_fresh_recent)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    ck_assert(bowie_dht_node_is_fresh(&n, 1000u + 100u));
}
END_TEST

START_TEST(test_is_fresh_exactly_at_limit)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    ck_assert(bowie_dht_node_is_fresh(
        &n, 1000u + BOWIE_DHT_NODE_GOOD_MS));
}
END_TEST

START_TEST(test_is_fresh_expired)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    ck_assert(!bowie_dht_node_is_fresh(
        &n, 1000u + BOWIE_DHT_NODE_GOOD_MS + 1u));
}
END_TEST

START_TEST(test_is_fresh_clock_moved_backwards)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 5000u;
    /* now < last_seen. */
    ck_assert(bowie_dht_node_is_fresh(&n, 1000u));
}
END_TEST

/*
 * ============================================================================
 * FAILED
 * ============================================================================
 */

START_TEST(test_is_failed_null)
{
    ck_assert(!bowie_dht_node_is_failed(NULL));
}
END_TEST

START_TEST(test_is_failed_zero)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(!bowie_dht_node_is_failed(&n));
}
END_TEST

START_TEST(test_is_failed_two)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.fail_count = 2u;
    ck_assert(!bowie_dht_node_is_failed(&n));
}
END_TEST

START_TEST(test_is_failed_three)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.fail_count = 3u;
    ck_assert(bowie_dht_node_is_failed(&n));
}
END_TEST

/*
 * ============================================================================
 * GOOD
 * ============================================================================
 */

START_TEST(test_is_good_null)
{
    ck_assert(!bowie_dht_node_is_good(NULL, 1000u));
}
END_TEST

START_TEST(test_is_good_never_seen)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    ck_assert(!bowie_dht_node_is_good(&n, 1000u));
}
END_TEST

START_TEST(test_is_good_fresh)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    ck_assert(bowie_dht_node_is_good(&n, 1100u));
}
END_TEST

START_TEST(test_is_good_seen_but_stale_not_failed)
{
    /*
     * Mainline: a node that has ever responded and has not
     * failed three times is good, even if it is stale.
     */
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    n.fail_count = 2u;
    ck_assert(bowie_dht_node_is_good(
        &n, 1000u + BOWIE_DHT_NODE_GOOD_MS + 1u));
}
END_TEST

START_TEST(test_is_good_seen_and_failed)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    n.fail_count = 3u;
    ck_assert(!bowie_dht_node_is_good(&n, 1100u));
}
END_TEST

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

START_TEST(test_seen_sets_timestamp_and_resets_fail)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.fail_count = 5u;
    bowie_dht_node_seen(&n, 9999u);
    ck_assert_uint_eq(n.last_seen_ms, 9999u);
    ck_assert_uint_eq(n.fail_count, 0u);
}
END_TEST

START_TEST(test_seen_null_is_noop)
{
    bowie_dht_node_seen(NULL, 1000u);
}
END_TEST

START_TEST(test_failed_increments)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    bowie_dht_node_failed(&n);
    ck_assert_uint_eq(n.fail_count, 1u);
    bowie_dht_node_failed(&n);
    ck_assert_uint_eq(n.fail_count, 2u);
}
END_TEST

START_TEST(test_failed_does_not_touch_timestamp)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.last_seen_ms = 1000u;
    bowie_dht_node_failed(&n);
    ck_assert_uint_eq(n.last_seen_ms, 1000u);
}
END_TEST

START_TEST(test_failed_null_is_noop)
{
    bowie_dht_node_failed(NULL);
}
END_TEST

START_TEST(test_set_token_copies)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));

    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.bytes[0] = 0xAA;
    t.bytes[1] = 0xBB;
    t.len = 2u;

    bowie_dht_node_set_token(&n, &t);

    ck_assert_int_eq(n.has_token, 1);
    ck_assert_uint_eq(n.token.len, 2u);
    ck_assert_uint_eq(n.token.bytes[0], 0xAAu);
    ck_assert_uint_eq(n.token.bytes[1], 0xBBu);
}
END_TEST

START_TEST(test_set_token_null_clears)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.has_token = 1;
    n.token.len = 2u;

    bowie_dht_node_set_token(&n, NULL);

    ck_assert_int_eq(n.has_token, 0);
    ck_assert_uint_eq(n.token.len, 0u);
}
END_TEST

START_TEST(test_set_token_zero_length_clears)
{
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));
    n.has_token = 1;
    n.token.len = 2u;

    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.len = 0u;

    bowie_dht_node_set_token(&n, &t);
    ck_assert_int_eq(n.has_token, 0);
}
END_TEST

START_TEST(test_set_token_null_node_is_noop)
{
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    bowie_dht_node_set_token(NULL, &t);
}
END_TEST

/*
 * ============================================================================
 * COMPACT FORMAT
 * ============================================================================
 */

START_TEST(test_from_compact_bad_length)
{
    uint8_t buf[25];
    memset(buf, 0, sizeof(buf));
    bowie_dht_node_t n;

    bowie_span_t in = { buf, 25u };
    ck_assert_int_eq(bowie_dht_node_from_compact(in, &n),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_from_compact_null_out)
{
    uint8_t buf[26];
    memset(buf, 0, sizeof(buf));
    bowie_span_t in = { buf, 26u };
    ck_assert_int_eq(bowie_dht_node_from_compact(in, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_from_compact_ok)
{
    uint8_t buf[26];
    memset(buf, 0, sizeof(buf));
    for (size_t i = 0u; i < 20u; i++) {
        buf[i] = (uint8_t)(1u + i);
    }
    buf[20] = 10u;
    buf[21] = 0u;
    buf[22] = 0u;
    buf[23] = 5u;
    buf[24] = 0x1Au; /* 26 */
    buf[25] = 0xE1u; /* 225 -> 0x1AE1 = 6881 */

    bowie_span_t in = { buf, 26u };
    bowie_dht_node_t n;

    ck_assert_int_eq(bowie_dht_node_from_compact(in, &n),
                     BOWIE_OK);
    ck_assert_uint_eq(n.id.bytes[0], 1u);
    ck_assert_uint_eq(n.id.bytes[19], 20u);
    ck_assert_int_eq(n.addr.family, BOWIE_AF_INET);
    ck_assert_uint_eq(n.addr.addr[3], 5u);
    ck_assert_uint_eq(n.addr.port, 6881u);
}
END_TEST

START_TEST(test_to_compact_round_trip)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 5u, 6881u);

    uint8_t buf[26];
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_node_to_compact(&n, buf, sizeof(buf), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 26u);

    bowie_dht_node_t n2;
    bowie_span_t in = { buf, out_len };
    ck_assert_int_eq(bowie_dht_node_from_compact(in, &n2),
                     BOWIE_OK);

    ck_assert(bowie_dht_node_equal(&n, &n2));
    ck_assert_uint_eq(n2.addr.port, 6881u);
    ck_assert_uint_eq(n2.addr.addr[3], 5u);
}
END_TEST

START_TEST(test_to_compact_non_ipv4)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 5u, 6881u);
    n.addr.family = BOWIE_AF_INET6;

    uint8_t buf[26];
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_node_to_compact(&n, buf, sizeof(buf), &out_len),
        BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_to_compact_too_small)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 5u, 6881u);

    uint8_t buf[25];
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_node_to_compact(&n, buf, sizeof(buf), &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_to_compact_null)
{
    bowie_dht_node_t n;
    make_node(&n, 1u, 5u, 6881u);
    uint8_t buf[26];
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_node_to_compact(NULL, buf, sizeof(buf), &out_len),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_node_to_compact(&n, NULL, sizeof(buf), &out_len),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_node_to_compact(&n, buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *node_suite(void)
{
    Suite *s = suite_create("DhtNode");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_clear_zeroes_everything);
    tcase_add_test(tc_life, test_clear_null_is_noop);
    suite_add_tcase(s, tc_life);

    TCase *tc_isset = tcase_create("IsSet");
    tcase_add_test(tc_isset, test_is_set_null);
    tcase_add_test(tc_isset, test_is_set_zeroed);
    tcase_add_test(tc_isset, test_is_set_id_only);
    tcase_add_test(tc_isset, test_is_set_addr_only);
    tcase_add_test(tc_isset, test_is_set_both);
    suite_add_tcase(s, tc_isset);

    TCase *tc_eq = tcase_create("Equal");
    tcase_add_test(tc_eq, test_equal_null_null);
    tcase_add_test(tc_eq, test_equal_null_unset);
    tcase_add_test(tc_eq, test_equal_null_set);
    tcase_add_test(tc_eq, test_equal_same_id_different_addr);
    tcase_add_test(tc_eq, test_equal_different_id);
    tcase_add_test(tc_eq, test_equal_two_unset);
    suite_add_tcase(s, tc_eq);

    TCase *tc_tok = tcase_create("HasToken");
    tcase_add_test(tc_tok, test_has_token_null);
    tcase_add_test(tc_tok, test_has_token_false);
    tcase_add_test(tc_tok, test_has_token_true);
    suite_add_tcase(s, tc_tok);

    TCase *tc_xor = tcase_create("DistanceXor");
    tcase_add_test(tc_xor, test_distance_between_ids_null);
    tcase_add_test(tc_xor, test_distance_between_ids_zero);
    tcase_add_test(tc_xor, test_distance_between_ids_xor);
    tcase_add_test(tc_xor, test_distance_between_ids_symmetric);
    tcase_add_test(tc_xor, test_distance_id_to_hash);
    suite_add_tcase(s, tc_xor);

    TCase *tc_cmp = tcase_create("DistanceCompare");
    tcase_add_test(tc_cmp, test_distance_compare_null_null);
    tcase_add_test(tc_cmp, test_distance_compare_null_a);
    tcase_add_test(tc_cmp, test_distance_compare_null_b);
    tcase_add_test(tc_cmp, test_distance_compare_equal);
    tcase_add_test(tc_cmp, test_distance_compare_less);
    tcase_add_test(tc_cmp, test_distance_compare_greater);
    tcase_add_test(tc_cmp, test_distance_compare_last_byte);
    suite_add_tcase(s, tc_cmp);

    TCase *tc_bit = tcase_create("DistanceFirstBit");
    tcase_add_test(tc_bit, test_distance_first_bit_null);
    tcase_add_test(tc_bit, test_distance_first_bit_zero);
    tcase_add_test(tc_bit, test_distance_first_bit_bit0);
    tcase_add_test(tc_bit, test_distance_first_bit_bit7);
    tcase_add_test(tc_bit, test_distance_first_bit_byte1);
    tcase_add_test(tc_bit, test_distance_first_bit_byte19);
    tcase_add_test(tc_bit, test_distance_first_bit_middle_of_byte);
    suite_add_tcase(s, tc_bit);

    TCase *tc_fresh = tcase_create("Fresh");
    tcase_add_test(tc_fresh, test_is_fresh_null);
    tcase_add_test(tc_fresh, test_is_fresh_never_seen);
    tcase_add_test(tc_fresh, test_is_fresh_recent);
    tcase_add_test(tc_fresh, test_is_fresh_exactly_at_limit);
    tcase_add_test(tc_fresh, test_is_fresh_expired);
    tcase_add_test(tc_fresh, test_is_fresh_clock_moved_backwards);
    suite_add_tcase(s, tc_fresh);

    TCase *tc_failed = tcase_create("Failed");
    tcase_add_test(tc_failed, test_is_failed_null);
    tcase_add_test(tc_failed, test_is_failed_zero);
    tcase_add_test(tc_failed, test_is_failed_two);
    tcase_add_test(tc_failed, test_is_failed_three);
    suite_add_tcase(s, tc_failed);

    TCase *tc_good = tcase_create("Good");
    tcase_add_test(tc_good, test_is_good_null);
    tcase_add_test(tc_good, test_is_good_never_seen);
    tcase_add_test(tc_good, test_is_good_fresh);
    tcase_add_test(tc_good, test_is_good_seen_but_stale_not_failed);
    tcase_add_test(tc_good, test_is_good_seen_and_failed);
    suite_add_tcase(s, tc_good);

    TCase *tc_mut = tcase_create("Mutation");
    tcase_add_test(tc_mut, test_seen_sets_timestamp_and_resets_fail);
    tcase_add_test(tc_mut, test_seen_null_is_noop);
    tcase_add_test(tc_mut, test_failed_increments);
    tcase_add_test(tc_mut, test_failed_does_not_touch_timestamp);
    tcase_add_test(tc_mut, test_failed_null_is_noop);
    tcase_add_test(tc_mut, test_set_token_copies);
    tcase_add_test(tc_mut, test_set_token_null_clears);
    tcase_add_test(tc_mut, test_set_token_zero_length_clears);
    tcase_add_test(tc_mut, test_set_token_null_node_is_noop);
    suite_add_tcase(s, tc_mut);

    TCase *tc_compact = tcase_create("Compact");
    tcase_add_test(tc_compact, test_from_compact_bad_length);
    tcase_add_test(tc_compact, test_from_compact_null_out);
    tcase_add_test(tc_compact, test_from_compact_ok);
    tcase_add_test(tc_compact, test_to_compact_round_trip);
    tcase_add_test(tc_compact, test_to_compact_non_ipv4);
    tcase_add_test(tc_compact, test_to_compact_too_small);
    tcase_add_test(tc_compact, test_to_compact_null);
    suite_add_tcase(s, tc_compact);

    return s;
}

int main(void)
{
    Suite *s = node_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
