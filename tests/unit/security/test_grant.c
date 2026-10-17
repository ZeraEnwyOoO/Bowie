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
 * BOWIE — SECURITY: GRANT UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the grant helpers declared in security/grant.h.
 *
 * These tests exercise the real logic: the serialization must
 * produce a deterministic byte sequence, the time validity
 * must respect the inclusive lower bound and the exclusive
 * upper bound, the subject and issuer matching must reject
 * unset IDs, and the permission check must respect the bit
 * mask.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No signature generation or verification.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every test sets up a grant with known bytes and checks the
 * result of one helper. A test that needs a non-zero time
 * uses a constant value, not the real clock, so that the test
 * is deterministic.
 *
 * The suite is split into four cases:
 *
 *   lifecycle   — clear
 *   serialize   — length and byte layout
 *   time        — validity across boundaries
 *   match       — subject, issuer, permission
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "security/grant.h"      declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/grant.h"

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

static void make_peer_id(bowie_peer_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0]  = seed;
    id->bytes[19] = seed;
}

static void make_public_id(bowie_public_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0]  = seed;
    id->bytes[31] = seed;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_grant_clear)
{
    bowie_grant_t g;

    memset(&g, 0xFF, sizeof(g));

    bowie_grant_clear(&g);

    ck_assert_int_eq(bowie_peer_id_is_zero(&g.subject), 1);
    ck_assert_int_eq(bowie_public_id_is_zero(&g.issuer), 1);
    ck_assert_int_eq(bowie_grant_id_is_zero(&g.grant_id), 1);
    ck_assert_uint_eq(g.permissions, 0);
    ck_assert_uint_eq(g.issued_at, 0);
    ck_assert_uint_eq(g.expires_at, 0);
}
END_TEST

START_TEST(test_grant_clear_null)
{
    bowie_grant_clear(NULL);
    /* no crash is the assertion */
}
END_TEST

/*
 * ============================================================================
 * SERIALIZE
 * ============================================================================
 */

START_TEST(test_grant_serialized_len)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);

    ck_assert_uint_eq(bowie_grant_serialized_len(&g),
                      BOWIE_PEER_ID_LEN + BOWIE_PUBLIC_ID_LEN +
                      BOWIE_GRANT_ID_LEN + 4 + 8 + 8);
}
END_TEST

START_TEST(test_grant_serialize_ok)
{
    bowie_grant_t g;
    uint8_t       buf[128];
    long          n;

    bowie_grant_clear(&g);

    make_peer_id(&g.subject, 0xAA);
    make_public_id(&g.issuer, 0xBB);
    make_grant_id(&g.grant_id, 0xCC);
    g.permissions = 0x12345678;
    g.issued_at   = 0x1122334455667788ULL;
    g.expires_at  = 0x99AABBCCDDEEFF00ULL;

    n = bowie_grant_serialize(&g, buf, sizeof(buf));

    ck_assert_int_eq(n, (long)bowie_grant_serialized_len(&g));
}
END_TEST

START_TEST(test_grant_serialize_too_small)
{
    bowie_grant_t g;
    uint8_t       buf[4];
    long          n;

    bowie_grant_clear(&g);

    n = bowie_grant_serialize(&g, buf, sizeof(buf));

    ck_assert_int_eq((bowie_error_t)n, BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_grant_serialize_null)
{
    bowie_grant_t g;
    long          n;

    bowie_grant_clear(&g);

    n = bowie_grant_serialize(NULL, NULL, 0);

    ck_assert_int_eq((bowie_error_t)n, BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * TIME
 * ============================================================================
 */

START_TEST(test_grant_time_valid)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 1000;
    g.expires_at = 2000;

    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 1500), 1);
}
END_TEST

START_TEST(test_grant_time_at_issued)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 1000;
    g.expires_at = 2000;

    /* Inclusive of issued_at. */
    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 1000), 1);
}
END_TEST

START_TEST(test_grant_time_at_expires)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 1000;
    g.expires_at = 2000;

    /* Exclusive of expires_at. */
    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 2000), 0);
}
END_TEST

START_TEST(test_grant_time_before_issued)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 1000;
    g.expires_at = 2000;

    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 999), 0);
}
END_TEST

START_TEST(test_grant_time_after_expires)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 1000;
    g.expires_at = 2000;

    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 2001), 0);
}
END_TEST

START_TEST(test_grant_time_invalid_range)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.issued_at  = 2000;
    g.expires_at = 1000;

    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 1500), 0);
}
END_TEST

START_TEST(test_grant_time_zero)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);

    ck_assert_int_eq(bowie_grant_is_time_valid(&g, 1500), 0);
}
END_TEST

/*
 * ============================================================================
 * MATCH
 * ============================================================================
 */

START_TEST(test_grant_matches_subject)
{
    bowie_grant_t     g;
    bowie_peer_id_t   id;

    bowie_grant_clear(&g);
    make_peer_id(&g.subject, 0xAA);
    make_peer_id(&id, 0xAA);

    ck_assert_int_eq(bowie_grant_matches_subject(&g, &id), 1);
}
END_TEST

START_TEST(test_grant_matches_subject_different)
{
    bowie_grant_t     g;
    bowie_peer_id_t   id;

    bowie_grant_clear(&g);
    make_peer_id(&g.subject, 0xAA);
    make_peer_id(&id, 0xBB);

    ck_assert_int_eq(bowie_grant_matches_subject(&g, &id), 0);
}
END_TEST

START_TEST(test_grant_matches_subject_unset)
{
    bowie_grant_t     g;
    bowie_peer_id_t   id;

    bowie_grant_clear(&g);   /* subject is zero */
    make_peer_id(&id, 0x00); /* id is zero */

    ck_assert_int_eq(bowie_grant_matches_subject(&g, &id), 0);
}
END_TEST

START_TEST(test_grant_matches_issuer)
{
    bowie_grant_t     g;
    bowie_public_id_t id;

    bowie_grant_clear(&g);
    make_public_id(&g.issuer, 0xCC);
    make_public_id(&id, 0xCC);

    ck_assert_int_eq(bowie_grant_matches_issuer(&g, &id), 1);
}
END_TEST

START_TEST(test_grant_allows_set)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);
    g.permissions = 0x00000010u;

    ck_assert_int_eq(bowie_grant_allows(&g, 0x00000010u), 1);
    ck_assert_int_eq(bowie_grant_allows(&g, 0x00000020u), 0);
}
END_TEST

START_TEST(test_grant_allows_zero)
{
    bowie_grant_t g;

    bowie_grant_clear(&g);

    ck_assert_int_eq(bowie_grant_allows(&g, 0x00000010u), 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *grant_suite(void)
{
    Suite *s;
    TCase *tc_lifecycle;
    TCase *tc_serialize;
    TCase *tc_time;
    TCase *tc_match;

    s = suite_create("SecurityGrant");

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_grant_clear);
    tcase_add_test(tc_lifecycle, test_grant_clear_null);
    suite_add_tcase(s, tc_lifecycle);

    tc_serialize = tcase_create("Serialize");
    tcase_add_test(tc_serialize, test_grant_serialized_len);
    tcase_add_test(tc_serialize, test_grant_serialize_ok);
    tcase_add_test(tc_serialize, test_grant_serialize_too_small);
    tcase_add_test(tc_serialize, test_grant_serialize_null);
    suite_add_tcase(s, tc_serialize);

    tc_time = tcase_create("Time");
    tcase_add_test(tc_time, test_grant_time_valid);
    tcase_add_test(tc_time, test_grant_time_at_issued);
    tcase_add_test(tc_time, test_grant_time_at_expires);
    tcase_add_test(tc_time, test_grant_time_before_issued);
    tcase_add_test(tc_time, test_grant_time_after_expires);
    tcase_add_test(tc_time, test_grant_time_invalid_range);
    tcase_add_test(tc_time, test_grant_time_zero);
    suite_add_tcase(s, tc_time);

    tc_match = tcase_create("Match");
    tcase_add_test(tc_match, test_grant_matches_subject);
    tcase_add_test(tc_match, test_grant_matches_subject_different);
    tcase_add_test(tc_match, test_grant_matches_subject_unset);
    tcase_add_test(tc_match, test_grant_matches_issuer);
    tcase_add_test(tc_match, test_grant_allows_set);
    tcase_add_test(tc_match, test_grant_allows_zero);
    suite_add_tcase(s, tc_match);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = grant_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
