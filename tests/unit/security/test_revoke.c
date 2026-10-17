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
 * BOWIE — SECURITY: REVOCATION UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the revocation list helpers declared in
 * security/revoke.h.
 *
 * These tests exercise the real logic: add an entry, check
 * that it is in the list, remove it, and check that it is not.
 * The add and remove functions are idempotent, so a duplicate
 * add and a missing remove must both succeed. A full list
 * must reject a further add.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The suite is split into three cases:
 *
 *   lifecycle   — clear
 *   mutation    — add, remove, idempotency, full list
 *   query       — contains, count
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         bowie_grant_id_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "security/revoke.h"     declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/revoke.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_grant_id(bowie_grant_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0]  = seed;
    id->bytes[15] = seed;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_revoke_clear_null)
{
    bowie_revoke_list_clear(NULL);
    /* no crash is the assertion */
}
END_TEST

START_TEST(test_revoke_clear)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id;

    make_grant_id(&id, 1);
    bowie_revoke_list_clear(&list);
    bowie_revoke_list_add(&list, &id);

    ck_assert_uint_eq(bowie_revoke_list_count(&list), 1);

    bowie_revoke_list_clear(&list);

    ck_assert_uint_eq(bowie_revoke_list_count(&list), 0);
    ck_assert_int_eq(bowie_revoke_list_contains(&list, &id), 0);
}
END_TEST

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

START_TEST(test_revoke_add_one)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id;
    bowie_error_t       rc;

    bowie_revoke_list_clear(&list);
    make_grant_id(&id, 1);

    rc = bowie_revoke_list_add(&list, &id);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(bowie_revoke_list_count(&list), 1);
    ck_assert_int_eq(bowie_revoke_list_contains(&list, &id), 1);
}
END_TEST

START_TEST(test_revoke_add_duplicate)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id;

    bowie_revoke_list_clear(&list);
    make_grant_id(&id, 1);

    bowie_revoke_list_add(&list, &id);
    bowie_revoke_list_add(&list, &id);

    ck_assert_uint_eq(bowie_revoke_list_count(&list), 1);
}
END_TEST

START_TEST(test_revoke_add_zero_id)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id;
    bowie_error_t       rc;

    bowie_revoke_list_clear(&list);
    memset(&id, 0, sizeof(id));

    rc = bowie_revoke_list_add(&list, &id);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_uint_eq(bowie_revoke_list_count(&list), 0);
}
END_TEST

START_TEST(test_revoke_add_full)
{
    bowie_revoke_list_t list;
    size_t              i;
    bowie_error_t       rc;
    bowie_grant_id_t    id;

    bowie_revoke_list_clear(&list);

    for (i = 0; i < BOWIE_REVOKE_CAP; i++) {
        make_grant_id(&id, (uint8_t)(i + 1));
        rc = bowie_revoke_list_add(&list, &id);
        ck_assert_int_eq(rc, BOWIE_OK);
    }

    ck_assert_uint_eq(bowie_revoke_list_count(&list), BOWIE_REVOKE_CAP);

    make_grant_id(&id, 255);
    rc = bowie_revoke_list_add(&list, &id);

    ck_assert_int_eq(rc, BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_revoke_remove)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id1, id2;
    bowie_error_t       rc;

    bowie_revoke_list_clear(&list);
    make_grant_id(&id1, 1);
    make_grant_id(&id2, 2);

    bowie_revoke_list_add(&list, &id1);
    bowie_revoke_list_add(&list, &id2);

    rc = bowie_revoke_list_remove(&list, &id1);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(bowie_revoke_list_count(&list), 1);
    ck_assert_int_eq(bowie_revoke_list_contains(&list, &id1), 0);
    ck_assert_int_eq(bowie_revoke_list_contains(&list, &id2), 1);
}
END_TEST

START_TEST(test_revoke_remove_not_present)
{
    bowie_revoke_list_t list;
    bowie_grant_id_t    id;
    bowie_error_t       rc;

    bowie_revoke_list_clear(&list);
    make_grant_id(&id, 1);

    rc = bowie_revoke_list_remove(&list, &id);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(bowie_revoke_list_count(&list), 0);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_revoke_contains_null)
{
    ck_assert_int_eq(bowie_revoke_list_contains(NULL, NULL), 0);
}
END_TEST

START_TEST(test_revoke_count_null)
{
    ck_assert_uint_eq(bowie_revoke_list_count(NULL), 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *revoke_suite(void)
{
    Suite *s;
    TCase *tc_lifecycle;
    TCase *tc_mutation;
    TCase *tc_query;

    s = suite_create("SecurityRevoke");

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_revoke_clear_null);
    tcase_add_test(tc_lifecycle, test_revoke_clear);
    suite_add_tcase(s, tc_lifecycle);

    tc_mutation = tcase_create("Mutation");
    tcase_add_test(tc_mutation, test_revoke_add_one);
    tcase_add_test(tc_mutation, test_revoke_add_duplicate);
    tcase_add_test(tc_mutation, test_revoke_add_zero_id);
    tcase_add_test(tc_mutation, test_revoke_add_full);
    tcase_add_test(tc_mutation, test_revoke_remove);
    tcase_add_test(tc_mutation, test_revoke_remove_not_present);
    suite_add_tcase(s, tc_mutation);

    tc_query = tcase_create("Query");
    tcase_add_test(tc_query, test_revoke_contains_null);
    tcase_add_test(tc_query, test_revoke_count_null);
    suite_add_tcase(s, tc_query);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = revoke_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
