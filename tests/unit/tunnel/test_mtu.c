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
 * BOWIE — TUNNEL MTU UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the MTU helpers declared in tunnel/mtu.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. The MTU helpers are pure value functions.
 *   - No platform test. The constants and the helper logic are
 *     platform-independent.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The suite is split into two cases:
 *
 *   valid      — bowie_mtu_is_valid() across boundaries
 *   suggest    — bowie_mtu_suggest() across typical and edge
 *                inputs
 *
 * Boundary values are tested explicitly. A helper that is
 * wrong exactly at a boundary is a common bug, and a boundary
 * test is cheap.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>           test framework
 *   "tunnel/mtu.h"      constants and declarations
 * ============================================================================
 */

#include <check.h>

#include "tunnel/mtu.h"

/*
 * ============================================================================
 * VALID
 * ============================================================================
 */

START_TEST(test_mtu_is_valid_below_min)
{
    ck_assert_int_eq(bowie_mtu_is_valid(0), 0);
    ck_assert_int_eq(bowie_mtu_is_valid(1), 0);
    ck_assert_int_eq(bowie_mtu_is_valid(BOWIE_TUN_MTU_MIN - 1), 0);
}
END_TEST

START_TEST(test_mtu_is_valid_at_min)
{
    ck_assert_int_eq(bowie_mtu_is_valid(BOWIE_TUN_MTU_MIN), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_mid)
{
    ck_assert_int_eq(bowie_mtu_is_valid(1500), 1);
    ck_assert_int_eq(bowie_mtu_is_valid(1400), 1);
    ck_assert_int_eq(bowie_mtu_is_valid(1280), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_at_max)
{
    ck_assert_int_eq(bowie_mtu_is_valid(BOWIE_TUN_MTU_MAX), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_above_max)
{
    ck_assert_int_eq(bowie_mtu_is_valid(BOWIE_TUN_MTU_MAX + 1), 0);
    ck_assert_int_eq(bowie_mtu_is_valid(100000), 0);
}
END_TEST

/*
 * ============================================================================
 * SUGGEST
 * ============================================================================
 */

START_TEST(test_mtu_suggest_default)
{
    /*
     * The default Ethernet MTU is 1500. Subtracting the fixed
     * overhead (100) should give the tunnel default (1400).
     */
    ck_assert_uint_eq(bowie_mtu_suggest(BOWIE_TUN_MTU_DEFAULT),
                      BOWIE_TUN_MTU_TUNNEL);
}
END_TEST

START_TEST(test_mtu_suggest_jumbo)
{
    /*
     * A jumbo frame of 9000 should give 8900, well within the
     * accepted range.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(9000), 8900);
}
END_TEST

START_TEST(test_mtu_suggest_small)
{
    /*
     * An underlying MTU that is too small after subtracting
     * the overhead should return the safe default.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(50), BOWIE_TUN_MTU_TUNNEL);
    ck_assert_uint_eq(bowie_mtu_suggest(100), BOWIE_TUN_MTU_TUNNEL);
}
END_TEST

START_TEST(test_mtu_suggest_clamp_min)
{
    /*
     * An underlying MTU of 1300 minus 100 is 1200, which is
     * below the tunnel minimum. The helper returns the default.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(1300), BOWIE_TUN_MTU_TUNNEL);
}
END_TEST

START_TEST(test_mtu_suggest_clamp_max)
{
    /*
     * An underlying MTU of 10000 minus 100 is 9900, which is
     * above the tunnel maximum. The helper returns the maximum.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(10000), BOWIE_TUN_MTU_MAX);
}
END_TEST

START_TEST(test_mtu_suggest_exact)
{
    /*
     * An underlying MTU that produces exactly the minimum or
     * the maximum should return that value, not clamp it.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(BOWIE_TUN_MTU_MIN + 100),
                      BOWIE_TUN_MTU_MIN);

    ck_assert_uint_eq(bowie_mtu_suggest(BOWIE_TUN_MTU_MAX + 100),
                      BOWIE_TUN_MTU_MAX);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *mtu_suite(void)
{
    Suite *s;
    TCase *tc_valid;
    TCase *tc_suggest;

    s = suite_create("TunnelMtu");

    tc_valid = tcase_create("Valid");
    tcase_add_test(tc_valid, test_mtu_is_valid_below_min);
    tcase_add_test(tc_valid, test_mtu_is_valid_at_min);
    tcase_add_test(tc_valid, test_mtu_is_valid_mid);
    tcase_add_test(tc_valid, test_mtu_is_valid_at_max);
    tcase_add_test(tc_valid, test_mtu_is_valid_above_max);
    suite_add_tcase(s, tc_valid);

    tc_suggest = tcase_create("Suggest");
    tcase_add_test(tc_suggest, test_mtu_suggest_default);
    tcase_add_test(tc_suggest, test_mtu_suggest_jumbo);
    tcase_add_test(tc_suggest, test_mtu_suggest_small);
    tcase_add_test(tc_suggest, test_mtu_suggest_clamp_min);
    tcase_add_test(tc_suggest, test_mtu_suggest_clamp_max);
    tcase_add_test(tc_suggest, test_mtu_suggest_exact);
    suite_add_tcase(s, tc_suggest);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = mtu_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
