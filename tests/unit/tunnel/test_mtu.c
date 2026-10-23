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
 * These tests exercise the real logic of bowie_mtu_is_valid()
 * and bowie_mtu_suggest(). Every branch of the suggestion
 * function is covered: the normal subtraction, the small
 * input case, the clamp to the minimum, the clamp to the
 * maximum, and the exact boundary values.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No device configuration.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The test values are chosen to exercise each branch of the
 * suggestion function:
 *
 *   - normal:     1500 - 100 = 1400
 *   - jumbo:      9000 - 100 = 8900
 *   - small:      50 -> default (50 <= 100)
 *   - clamp min:  1199 - 100 = 1099 -> default
 *   - clamp max:  10000 - 100 = 9900 -> max
 *   - exact min:  1200 - 100 = 1100
 *   - exact max:  9100 - 100 = 9000
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
    ck_assert_int_eq(bowie_mtu_is_valid(1099), 0);
}
END_TEST

START_TEST(test_mtu_is_valid_at_min)
{
    ck_assert_int_eq(bowie_mtu_is_valid(BOWIE_TUN_MTU_MIN), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_mid)
{
    ck_assert_int_eq(bowie_mtu_is_valid(1400), 1);
    ck_assert_int_eq(bowie_mtu_is_valid(1500), 1);
    ck_assert_int_eq(bowie_mtu_is_valid(4000), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_at_max)
{
    ck_assert_int_eq(bowie_mtu_is_valid(9000), 1);
}
END_TEST

START_TEST(test_mtu_is_valid_above_max)
{
    ck_assert_int_eq(bowie_mtu_is_valid(9001), 0);
    ck_assert_int_eq(bowie_mtu_is_valid(65535), 0);
}
END_TEST

/*
 * ============================================================================
 * SUGGEST
 * ============================================================================
 */

START_TEST(test_mtu_suggest_normal)
{
    /*
     * 1500 - 100 = 1400.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(1500), 1400);
}
END_TEST

START_TEST(test_mtu_suggest_jumbo)
{
    /*
     * 9000 - 100 = 8900, within the accepted range.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(9000), 8900);
}
END_TEST

START_TEST(test_mtu_suggest_small)
{
    /*
     * 50 <= 100, so the safe default is returned.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(50), BOWIE_TUN_MTU_TUNNEL);
    ck_assert_uint_eq(bowie_mtu_suggest(100), BOWIE_TUN_MTU_TUNNEL);
    ck_assert_uint_eq(bowie_mtu_suggest(0), BOWIE_TUN_MTU_TUNNEL);
}
END_TEST

START_TEST(test_mtu_suggest_clamp_min)
{
    /*
     * 1199 - 100 = 1099 and 1198 - 100 = 1098, below
     * the minimum supported MTU.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(1199), BOWIE_TUN_MTU_TUNNEL);
    ck_assert_uint_eq(bowie_mtu_suggest(1198), BOWIE_TUN_MTU_TUNNEL);
}
END_TEST

START_TEST(test_mtu_suggest_clamp_max)
{
    /*
     * 10000 - 100 = 9900, which is above the maximum (9000).
     * The maximum is returned.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(10000), BOWIE_TUN_MTU_MAX);
    ck_assert_uint_eq(bowie_mtu_suggest(20000), BOWIE_TUN_MTU_MAX);
}
END_TEST

START_TEST(test_mtu_suggest_exact_min)
{
    /*
     * 1200 - 100 = 1100, exactly the minimum and default.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(1200), BOWIE_TUN_MTU_MIN);
}
END_TEST

START_TEST(test_mtu_suggest_exact_max)
{
    /*
     * 9100 - 100 = 9000, exactly the maximum. The result is
     * the maximum, not the default.
     */
    ck_assert_uint_eq(bowie_mtu_suggest(9100), BOWIE_TUN_MTU_MAX);
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
    tcase_add_test(tc_suggest, test_mtu_suggest_normal);
    tcase_add_test(tc_suggest, test_mtu_suggest_jumbo);
    tcase_add_test(tc_suggest, test_mtu_suggest_small);
    tcase_add_test(tc_suggest, test_mtu_suggest_clamp_min);
    tcase_add_test(tc_suggest, test_mtu_suggest_clamp_max);
    tcase_add_test(tc_suggest, test_mtu_suggest_exact_min);
    tcase_add_test(tc_suggest, test_mtu_suggest_exact_max);
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
