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
#include "gateway/route.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

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

START_TEST(test_route_clear_null)
{
    bowie_route_table_clear(NULL);
}
END_TEST

START_TEST(test_route_clear)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;

    make_peer_id(&id, 1);
    bowie_route_table_clear(&rt);
    bowie_route_table_add(&rt, &id, 1);

    ck_assert_uint_eq(bowie_route_table_count(&rt), 1);

    bowie_route_table_clear(&rt);

    ck_assert_uint_eq(bowie_route_table_count(&rt), 0);
}
END_TEST

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

START_TEST(test_route_add_one)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;
    bowie_error_t       rc;
    uint32_t            ifindex;

    bowie_route_table_clear(&rt);
    make_peer_id(&id, 1);

    rc = bowie_route_table_add(&rt, &id, 42);
    ck_assert_int_eq(rc, BOWIE_OK);

    ck_assert_uint_eq(bowie_route_table_count(&rt), 1);
    ck_assert_int_eq(bowie_route_table_lookup(&rt, &id, &ifindex), 1);
    ck_assert_uint_eq(ifindex, 42);
}
END_TEST

START_TEST(test_route_add_duplicate)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;
    uint32_t            ifindex;

    bowie_route_table_clear(&rt);
    make_peer_id(&id, 1);

    bowie_route_table_add(&rt, &id, 1);
    bowie_route_table_add(&rt, &id, 2);

    ck_assert_uint_eq(bowie_route_table_count(&rt), 1);
    ck_assert_int_eq(bowie_route_table_lookup(&rt, &id, &ifindex), 1);
    ck_assert_uint_eq(ifindex, 2);
}
END_TEST

START_TEST(test_route_add_zero_id)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;
    bowie_error_t       rc;

    bowie_route_table_clear(&rt);
    memset(&id, 0, sizeof(id));

    rc = bowie_route_table_add(&rt, &id, 1);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_uint_eq(bowie_route_table_count(&rt), 0);
}
END_TEST

START_TEST(test_route_add_full)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;
    size_t              i;
    bowie_error_t       rc;

    bowie_route_table_clear(&rt);

    for (i = 0; i < BOWIE_ROUTE_CAP; i++) {
        make_peer_id(&id, (uint8_t)(i + 1));
        rc = bowie_route_table_add(&rt, &id, (uint32_t)i);
        ck_assert_int_eq(rc, BOWIE_OK);
    }

    ck_assert_uint_eq(bowie_route_table_count(&rt), BOWIE_ROUTE_CAP);

    make_peer_id(&id, 255);
    rc = bowie_route_table_add(&rt, &id, 1);

    ck_assert_int_eq(rc, BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_route_remove)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id1, id2;
    uint32_t            ifindex;

    bowie_route_table_clear(&rt);
    make_peer_id(&id1, 1);
    make_peer_id(&id2, 2);

    bowie_route_table_add(&rt, &id1, 1);
    bowie_route_table_add(&rt, &id2, 2);

    bowie_route_table_remove(&rt, &id1);

    ck_assert_uint_eq(bowie_route_table_count(&rt), 1);
    ck_assert_int_eq(bowie_route_table_lookup(&rt, &id1, &ifindex), 0);
    ck_assert_int_eq(bowie_route_table_lookup(&rt, &id2, &ifindex), 1);
}
END_TEST

START_TEST(test_route_remove_not_present)
{
    bowie_route_table_t rt;
    bowie_peer_id_t     id;
    bowie_error_t       rc;

    bowie_route_table_clear(&rt);
    make_peer_id(&id, 1);

    rc = bowie_route_table_remove(&rt, &id);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(bowie_route_table_count(&rt), 0);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_route_lookup_null)
{
    bowie_peer_id_t id;
    uint32_t        ifindex;

    make_peer_id(&id, 1);

    ck_assert_int_eq((bowie_error_t)bowie_route_table_lookup(NULL, &id, &ifindex),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_route_count_null)
{
    ck_assert_uint_eq(bowie_route_table_count(NULL), 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *route_suite(void)
{
    Suite *s;
    TCase *tc_lifecycle;
    TCase *tc_mutation;
    TCase *tc_query;

    s = suite_create("GatewayRoute");

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_route_clear_null);
    tcase_add_test(tc_lifecycle, test_route_clear);
    suite_add_tcase(s, tc_lifecycle);

    tc_mutation = tcase_create("Mutation");
    tcase_add_test(tc_mutation, test_route_add_one);
    tcase_add_test(tc_mutation, test_route_add_duplicate);
    tcase_add_test(tc_mutation, test_route_add_zero_id);
    tcase_add_test(tc_mutation, test_route_add_full);
    tcase_add_test(tc_mutation, test_route_remove);
    tcase_add_test(tc_mutation, test_route_remove_not_present);
    suite_add_tcase(s, tc_mutation);

    tc_query = tcase_create("Query");
    tcase_add_test(tc_query, test_route_lookup_null);
    tcase_add_test(tc_query, test_route_count_null);
    suite_add_tcase(s, tc_query);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = route_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
