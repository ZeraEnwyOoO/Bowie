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

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/conntrack.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_tuple(bowie_conntrack_5tuple_t *t,
                        uint8_t seed, uint16_t sport, uint16_t dport,
                        uint8_t proto)
{
    memset(t, 0, sizeof(*t));
    t->src_addr[0]  = seed;
    t->src_addr[3]  = seed;
    t->dst_addr[0]  = seed;
    t->dst_addr[3]  = seed;
    t->src_port     = sport;
    t->dst_port     = dport;
    t->protocol     = proto;
}

static void make_peer_id(bowie_peer_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0]  = seed;
    id->bytes[19] = seed;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_conntrack_open_close)
{
    bowie_conntrack_t *ct = NULL;
    bowie_error_t      rc;

    rc = bowie_conntrack_open(&ct, 16);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(ct);
    ck_assert_uint_eq(bowie_conntrack_count(ct), 0);

    bowie_conntrack_close(ct);
}
END_TEST

START_TEST(test_conntrack_open_null)
{
    bowie_error_t rc = bowie_conntrack_open(NULL, 16);
    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * ADD / LOOKUP
 * ============================================================================
 */

START_TEST(test_conntrack_add_lookup)
{
    bowie_conntrack_t      *ct = NULL;
    bowie_conntrack_5tuple_t t;
    bowie_peer_id_t         peer_in, peer_out;
    bowie_error_t           rc;

    rc = bowie_conntrack_open(&ct, 16);
    ck_assert_int_eq(rc, BOWIE_OK);

    make_tuple(&t, 0xAA, 1234, 80, 6);
    make_peer_id(&peer_in, 0x01);

    rc = bowie_conntrack_add(ct, &t, &peer_in);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(bowie_conntrack_count(ct), 1);

    rc = bowie_conntrack_lookup(ct, &t, &peer_out);
    ck_assert_int_eq(rc, 1);
    ck_assert_int_eq(bowie_peer_id_equal(&peer_in, &peer_out), 1);

    bowie_conntrack_close(ct);
}
END_TEST

START_TEST(test_conntrack_lookup_miss)
{
    bowie_conntrack_t      *ct = NULL;
    bowie_conntrack_5tuple_t t;
    bowie_peer_id_t         peer_out;
    int                     rc;

    rc = bowie_conntrack_open(&ct, 16);
    ck_assert_int_eq(rc, BOWIE_OK);

    make_tuple(&t, 0xAA, 1234, 80, 6);

    rc = bowie_conntrack_lookup(ct, &t, &peer_out);
    ck_assert_int_eq(rc, 0);

    bowie_conntrack_close(ct);
}
END_TEST

START_TEST(test_conntrack_add_duplicate)
{
    bowie_conntrack_t      *ct = NULL;
    bowie_conntrack_5tuple_t t;
    bowie_peer_id_t         peer1, peer2, peer_out;

    bowie_conntrack_open(&ct, 16);

    make_tuple(&t, 0xAA, 1234, 80, 6);
    make_peer_id(&peer1, 0x01);
    make_peer_id(&peer2, 0x02);

    bowie_conntrack_add(ct, &t, &peer1);
    bowie_conntrack_add(ct, &t, &peer2);

    ck_assert_uint_eq(bowie_conntrack_count(ct), 1);
    ck_assert_int_eq(bowie_conntrack_lookup(ct, &t, &peer_out), 1);
    ck_assert_int_eq(bowie_peer_id_equal(&peer_out, &peer2), 1);

    bowie_conntrack_close(ct);
}
END_TEST

/*
 * ============================================================================
 * REMOVE
 * ============================================================================
 */

START_TEST(test_conntrack_remove)
{
    bowie_conntrack_t      *ct = NULL;
    bowie_conntrack_5tuple_t t;
    bowie_peer_id_t         peer, peer_out;

    bowie_conntrack_open(&ct, 16);

    make_tuple(&t, 0xAA, 1234, 80, 6);
    make_peer_id(&peer, 0x01);

    bowie_conntrack_add(ct, &t, &peer);
    bowie_conntrack_remove(ct, &t);

    ck_assert_uint_eq(bowie_conntrack_count(ct), 0);
    ck_assert_int_eq(bowie_conntrack_lookup(ct, &t, &peer_out), 0);

    bowie_conntrack_close(ct);
}
END_TEST

/*
 * ============================================================================
 * EVICTION
 * ============================================================================
 */

START_TEST(test_conntrack_evict)
{
    bowie_conntrack_t      *ct = NULL;
    bowie_conntrack_5tuple_t t;
    bowie_peer_id_t         peer;
    uint16_t                i;
    bowie_error_t           rc;

    /* Capacity 4; add 5 entries; the first must be evicted. */
    bowie_conntrack_open(&ct, 4);

    for (i = 0; i < 5; i++) {
        make_tuple(&t, (uint8_t)(i + 1), (uint16_t)(1000 + i), 80, 6);
        make_peer_id(&peer, (uint8_t)(i + 1));
        rc = bowie_conntrack_add(ct, &t, &peer);
        ck_assert_int_eq(rc, BOWIE_OK);
    }

    ck_assert_uint_eq(bowie_conntrack_count(ct), 4);

    /* First tuple should be gone. */
    make_tuple(&t, 1, 1000, 80, 6);
    {
        bowie_peer_id_t out;
        ck_assert_int_eq(bowie_conntrack_lookup(ct, &t, &out), 0);
    }

    bowie_conntrack_close(ct);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *conntrack_suite(void)
{
    Suite *s;
    TCase *tc_lifecycle;
    TCase *tc_lookup;
    TCase *tc_remove;
    TCase *tc_evict;

    s = suite_create("GatewayConntrack");

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_conntrack_open_close);
    tcase_add_test(tc_lifecycle, test_conntrack_open_null);
    suite_add_tcase(s, tc_lifecycle);

    tc_lookup = tcase_create("Lookup");
    tcase_add_test(tc_lookup, test_conntrack_add_lookup);
    tcase_add_test(tc_lookup, test_conntrack_lookup_miss);
    tcase_add_test(tc_lookup, test_conntrack_add_duplicate);
    suite_add_tcase(s, tc_lookup);

    tc_remove = tcase_create("Remove");
    tcase_add_test(tc_remove, test_conntrack_remove);
    suite_add_tcase(s, tc_remove);

    tc_evict = tcase_create("Evict");
    tcase_add_test(tc_evict, test_conntrack_evict);
    suite_add_tcase(s, tc_evict);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = conntrack_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
