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
 * Unit tests for include/net/capabilities.h.
 *
 * The capability model is declared in bowie/config.h and
 * re-exported by net/capabilities.h. These tests verify that the
 * re-export is complete and that the model behaves as documented.
 *
 * The model itself is also tested by tests/unit/api/test_config.c
 * against the configuration functions. These tests are not a
 * duplicate: they test the model through the net-layer header,
 * which is the header a net-layer caller will include.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   "net/capabilities.h"         the unit under test
 * ============================================================================
 */

#include <check.h>

#include "net/capabilities.h"

/*
 * ============================================================================
 * RE-EXPORT
 * ============================================================================
 *
 * The capability type and its functions must be visible through
 * this header without the caller including bowie/config.h.
 */

START_TEST(test_cap_none_is_zero)
{
    ck_assert_uint_eq((uint32_t)BOWIE_CAP_NONE, 0u);
}
END_TEST

START_TEST(test_cap_flags_are_distinct_bits)
{
    ck_assert_uint_ne((uint32_t)BOWIE_CAP_SOURCE,
                      (uint32_t)BOWIE_CAP_CLIENT);
    ck_assert_uint_ne((uint32_t)BOWIE_CAP_SOURCE,
                      (uint32_t)BOWIE_CAP_GATEWAY);
    ck_assert_uint_ne((uint32_t)BOWIE_CAP_CLIENT,
                      (uint32_t)BOWIE_CAP_GATEWAY);
}
END_TEST

START_TEST(test_cap_for_mode_device)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_DEVICE);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_router)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_ROUTER);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_box)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_BOX);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_unset)
{
    ck_assert_uint_eq(bowie_cap_for_mode(BOWIE_MODE_UNSET),
                      (uint32_t)BOWIE_CAP_NONE);
}
END_TEST

START_TEST(test_cap_for_mode_invalid)
{
    ck_assert_uint_eq(bowie_cap_for_mode((bowie_mode_t)999),
                      (uint32_t)BOWIE_CAP_NONE);
}
END_TEST

START_TEST(test_cap_has_none)
{
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_has_combined_mask)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE
                  | (uint32_t)BOWIE_CAP_GATEWAY;
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_GATEWAY));
    ck_assert(!bowie_cap_has(mask, BOWIE_CAP_CLIENT));
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

    TCase *tc_model = tcase_create("Model");
    tcase_add_test(tc_model, test_cap_none_is_zero);
    tcase_add_test(tc_model, test_cap_flags_are_distinct_bits);
    suite_add_tcase(s, tc_model);

    TCase *tc_preset = tcase_create("Preset");
    tcase_add_test(tc_preset, test_cap_for_mode_device);
    tcase_add_test(tc_preset, test_cap_for_mode_router);
    tcase_add_test(tc_preset, test_cap_for_mode_box);
    tcase_add_test(tc_preset, test_cap_for_mode_unset);
    tcase_add_test(tc_preset, test_cap_for_mode_invalid);
    suite_add_tcase(s, tc_preset);

    TCase *tc_has = tcase_create("Has");
    tcase_add_test(tc_has, test_cap_has_none);
    tcase_add_test(tc_has, test_cap_has_combined_mask);
    suite_add_tcase(s, tc_has);

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
