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
 * BOWIE — CAPABILITIES TESTS
 * ============================================================================
 *
 * Unit tests for src/net/capabilities.c.
 *
 * Every public function declared in net/capabilities.h is
 * covered here.
 *
 * The capability enum and the bowie_cap_has / bowie_cap_for_mode
 * functions are declared in bowie/config.h and tested by
 * tests/unit/api/test_config.c. They are not retested here.
 * This file tests the operations that net/capabilities.h adds:
 * name lookup, string formatting, string parsing, and mask
 * validation.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset, strcmp
 *   "net/capabilities.h"         the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "net/capabilities.h"

/*
 * ============================================================================
 * BOWIE_CAP_ALL
 * ============================================================================
 */

START_TEST(test_cap_all_contains_every_known_bit)
{
    uint32_t all = BOWIE_CAP_ALL;
    ck_assert(bowie_cap_has(all, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(all, BOWIE_CAP_CLIENT));
    ck_assert(bowie_cap_has(all, BOWIE_CAP_GATEWAY));
}
END_TEST

/*
 * ============================================================================
 * NAME LOOKUP
 * ============================================================================
 */

START_TEST(test_cap_name_zero_is_none)
{
    ck_assert_str_eq(bowie_cap_name(0u), "none");
}
END_TEST

START_TEST(test_cap_name_source)
{
    ck_assert_str_eq(bowie_cap_name((uint32_t)BOWIE_CAP_SOURCE),
                     "source");
}
END_TEST

START_TEST(test_cap_name_client)
{
    ck_assert_str_eq(bowie_cap_name((uint32_t)BOWIE_CAP_CLIENT),
                     "client");
}
END_TEST

START_TEST(test_cap_name_gateway)
{
    ck_assert_str_eq(bowie_cap_name((uint32_t)BOWIE_CAP_GATEWAY),
                     "gateway");
}
END_TEST

START_TEST(test_cap_name_multiple_known_bits)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE
                  | (uint32_t)BOWIE_CAP_CLIENT;
    ck_assert_str_eq(bowie_cap_name(mask), "multiple");
}
END_TEST

START_TEST(test_cap_name_unknown_bit)
{
    ck_assert_str_eq(bowie_cap_name(0x80000000u), "unknown");
}
END_TEST

START_TEST(test_cap_name_unknown_with_known)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE | 0x80000000u;
    ck_assert_str_eq(bowie_cap_name(mask), "unknown");
}
END_TEST

/*
 * ============================================================================
 * MASK VALIDATION
 * ============================================================================
 */

START_TEST(test_mask_is_valid_zero)
{
    ck_assert(bowie_cap_mask_is_valid(0u));
}
END_TEST

START_TEST(test_mask_is_valid_known)
{
    ck_assert(bowie_cap_mask_is_valid(BOWIE_CAP_ALL));
}
END_TEST

START_TEST(test_mask_is_valid_single)
{
    ck_assert(bowie_cap_mask_is_valid(
        (uint32_t)BOWIE_CAP_SOURCE));
}
END_TEST

START_TEST(test_mask_is_valid_unknown_bit)
{
    ck_assert(!bowie_cap_mask_is_valid(0x80000000u));
}
END_TEST

START_TEST(test_mask_is_valid_known_plus_unknown)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE | 0x80000000u;
    ck_assert(!bowie_cap_mask_is_valid(mask));
}
END_TEST

/*
 * ============================================================================
 * MASK TO STRING
 * ============================================================================
 */

START_TEST(test_mask_to_string_zero)
{
    char buf[32];
    int n = bowie_cap_mask_to_string(0u, buf, sizeof(buf));
    ck_assert_str_eq(buf, "none");
    ck_assert_int_eq(n, 4);
}
END_TEST

START_TEST(test_mask_to_string_source)
{
    char buf[32];
    int n = bowie_cap_mask_to_string(
        (uint32_t)BOWIE_CAP_SOURCE, buf, sizeof(buf));
    ck_assert_str_eq(buf, "source");
    ck_assert_int_eq(n, 6);
}
END_TEST

START_TEST(test_mask_to_string_source_client)
{
    char buf[32];
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE
                  | (uint32_t)BOWIE_CAP_CLIENT;
    int n = bowie_cap_mask_to_string(mask, buf, sizeof(buf));
    ck_assert_str_eq(buf, "source, client");
    ck_assert_int_eq(n, 14);
}
END_TEST

START_TEST(test_mask_to_string_all_three)
{
    char buf[64];
    int n = bowie_cap_mask_to_string(BOWIE_CAP_ALL,
                                     buf, sizeof(buf));
    ck_assert_str_eq(buf, "source, client, gateway");
    ck_assert_int_eq(n, 23);
}
END_TEST

START_TEST(test_mask_to_string_order_is_fixed)
{
    /*
     * The order is source, client, gateway regardless of the
     * order the bits were set.
     */
    char buf[64];
    uint32_t mask = (uint32_t)BOWIE_CAP_GATEWAY
                  | (uint32_t)BOWIE_CAP_SOURCE
                  | (uint32_t)BOWIE_CAP_CLIENT;
    (void)bowie_cap_mask_to_string(mask, buf, sizeof(buf));
    ck_assert_str_eq(buf, "source, client, gateway");
}
END_TEST

START_TEST(test_mask_to_string_null_buf)
{
    int n = bowie_cap_mask_to_string(
        (uint32_t)BOWIE_CAP_SOURCE, NULL, 32u);
    ck_assert_int_eq(n, 0);
}
END_TEST

START_TEST(test_mask_to_string_zero_cap)
{
    char buf[32];
    int n = bowie_cap_mask_to_string(
        (uint32_t)BOWIE_CAP_SOURCE, buf, 0u);
    ck_assert_int_eq(n, 0);
}
END_TEST

START_TEST(test_mask_to_string_truncates)
{
    /*
     * A buffer of 4 bytes holds "sou" plus a terminator.
     * The return value is the full length that would have
     * been written.
     */
    char buf[4];
    int n = bowie_cap_mask_to_string(
        (uint32_t)BOWIE_CAP_SOURCE, buf, sizeof(buf));
    ck_assert_int_eq(n, 6);
    ck_assert_str_eq(buf, "sou");
}
END_TEST

START_TEST(test_mask_to_string_ignores_unknown_bits)
{
    /*
     * Only known bits are named. An unknown bit is not
     * formatted.
     */
    char buf[32];
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE | 0x80000000u;
    int n = bowie_cap_mask_to_string(mask, buf, sizeof(buf));
    ck_assert_str_eq(buf, "source");
    ck_assert_int_eq(n, 6);
}
END_TEST

/*
 * ============================================================================
 * STRING TO MASK
 * ============================================================================
 */

START_TEST(test_mask_from_string_null_str)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string(NULL, &mask, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_mask_from_string_null_out)
{
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source", NULL, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_mask_from_string_empty)
{
    uint32_t mask = 0xFFFFFFFFu;
    size_t unknown = 99u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("", &mask, &unknown),
        BOWIE_OK);
    ck_assert_uint_eq(mask, 0u);
    ck_assert_uint_eq(unknown, 0u);
}
END_TEST

START_TEST(test_mask_from_string_source)
{
    uint32_t mask = 0u;
    size_t unknown = 99u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source", &mask, &unknown),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_SOURCE);
    ck_assert_uint_eq(unknown, 0u);
}
END_TEST

START_TEST(test_mask_from_string_client)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("client", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_CLIENT);
}
END_TEST

START_TEST(test_mask_from_string_gateway)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("gateway", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_GATEWAY);
}
END_TEST

START_TEST(test_mask_from_string_none)
{
    uint32_t mask = 0xFFFFFFFFu;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("none", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, 0u);
}
END_TEST

START_TEST(test_mask_from_string_combined)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source, client", &mask, NULL),
        BOWIE_OK);
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(mask, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_mask_from_string_case_insensitive)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("SOURCE, Client, GaTeWaY",
                                    &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, BOWIE_CAP_ALL);
}
END_TEST

START_TEST(test_mask_from_string_whitespace_ignored)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("  source  ,\tclient\t",
                                    &mask, NULL),
        BOWIE_OK);
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_CLIENT));
}
END_TEST

START_TEST(test_mask_from_string_trailing_comma)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source,", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

START_TEST(test_mask_from_string_leading_comma)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string(",source", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

START_TEST(test_mask_from_string_unknown_counted)
{
    uint32_t mask = 0u;
    size_t unknown = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source, bogus, gateway",
                                    &mask, &unknown),
        BOWIE_OK);
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_GATEWAY));
    ck_assert_uint_eq(unknown, 1u);
}
END_TEST

START_TEST(test_mask_from_string_multiple_unknown)
{
    uint32_t mask = 0u;
    size_t unknown = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("foo, bar, source",
                                    &mask, &unknown),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_SOURCE);
    ck_assert_uint_eq(unknown, 2u);
}
END_TEST

START_TEST(test_mask_from_string_all_unknown)
{
    uint32_t mask = 0xFFFFFFFFu;
    size_t unknown = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("foo, bar", &mask, &unknown),
        BOWIE_OK);
    ck_assert_uint_eq(mask, 0u);
    ck_assert_uint_eq(unknown, 2u);
}
END_TEST

START_TEST(test_mask_from_string_null_unknown_allowed)
{
    uint32_t mask = 0u;
    ck_assert_int_eq(
        bowie_cap_mask_from_string("source, bogus", &mask, NULL),
        BOWIE_OK);
    ck_assert_uint_eq(mask, (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP
 * ============================================================================
 */

START_TEST(test_round_trip_all_masks)
{
    /*
     * Formatting a mask and parsing the result must produce
     * the same mask for every valid combination.
     */
    for (uint32_t mask = 0u; mask <= BOWIE_CAP_ALL; mask++) {
        if (!bowie_cap_mask_is_valid(mask)) {
            continue;
        }

        char buf[64];
        (void)bowie_cap_mask_to_string(mask, buf, sizeof(buf));

        uint32_t parsed = 0u;
        size_t unknown = 0u;
        ck_assert_int_eq(
            bowie_cap_mask_from_string(buf, &parsed, &unknown),
            BOWIE_OK);
        ck_assert_uint_eq(parsed, mask);
        ck_assert_uint_eq(unknown, 0u);
    }
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *capabilities_suite(void)
{
    Suite *s = suite_create("Capabilities");

    TCase *tc_all = tcase_create("All");
    tcase_add_test(tc_all, test_cap_all_contains_every_known_bit);
    suite_add_tcase(s, tc_all);

    TCase *tc_name = tcase_create("Name");
    tcase_add_test(tc_name, test_cap_name_zero_is_none);
    tcase_add_test(tc_name, test_cap_name_source);
    tcase_add_test(tc_name, test_cap_name_client);
    tcase_add_test(tc_name, test_cap_name_gateway);
    tcase_add_test(tc_name, test_cap_name_multiple_known_bits);
    tcase_add_test(tc_name, test_cap_name_unknown_bit);
    tcase_add_test(tc_name, test_cap_name_unknown_with_known);
    suite_add_tcase(s, tc_name);

    TCase *tc_valid = tcase_create("Valid");
    tcase_add_test(tc_valid, test_mask_is_valid_zero);
    tcase_add_test(tc_valid, test_mask_is_valid_known);
    tcase_add_test(tc_valid, test_mask_is_valid_single);
    tcase_add_test(tc_valid, test_mask_is_valid_unknown_bit);
    tcase_add_test(tc_valid, test_mask_is_valid_known_plus_unknown);
    suite_add_tcase(s, tc_valid);

    TCase *tc_to = tcase_create("ToString");
    tcase_add_test(tc_to, test_mask_to_string_zero);
    tcase_add_test(tc_to, test_mask_to_string_source);
    tcase_add_test(tc_to, test_mask_to_string_source_client);
    tcase_add_test(tc_to, test_mask_to_string_all_three);
    tcase_add_test(tc_to, test_mask_to_string_order_is_fixed);
    tcase_add_test(tc_to, test_mask_to_string_null_buf);
    tcase_add_test(tc_to, test_mask_to_string_zero_cap);
    tcase_add_test(tc_to, test_mask_to_string_truncates);
    tcase_add_test(tc_to, test_mask_to_string_ignores_unknown_bits);
    suite_add_tcase(s, tc_to);

    TCase *tc_from = tcase_create("FromString");
    tcase_add_test(tc_from, test_mask_from_string_null_str);
    tcase_add_test(tc_from, test_mask_from_string_null_out);
    tcase_add_test(tc_from, test_mask_from_string_empty);
    tcase_add_test(tc_from, test_mask_from_string_source);
    tcase_add_test(tc_from, test_mask_from_string_client);
    tcase_add_test(tc_from, test_mask_from_string_gateway);
    tcase_add_test(tc_from, test_mask_from_string_none);
    tcase_add_test(tc_from, test_mask_from_string_combined);
    tcase_add_test(tc_from, test_mask_from_string_case_insensitive);
    tcase_add_test(tc_from, test_mask_from_string_whitespace_ignored);
    tcase_add_test(tc_from, test_mask_from_string_trailing_comma);
    tcase_add_test(tc_from, test_mask_from_string_leading_comma);
    tcase_add_test(tc_from, test_mask_from_string_unknown_counted);
    tcase_add_test(tc_from, test_mask_from_string_multiple_unknown);
    tcase_add_test(tc_from, test_mask_from_string_all_unknown);
    tcase_add_test(tc_from, test_mask_from_string_null_unknown_allowed);
    suite_add_tcase(s, tc_from);

    TCase *tc_rt = tcase_create("RoundTrip");
    tcase_add_test(tc_rt, test_round_trip_all_masks);
    suite_add_tcase(s, tc_rt);

    return s;
}

int main(void)
{
    Suite *s = capabilities_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
