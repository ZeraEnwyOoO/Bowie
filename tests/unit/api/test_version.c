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
 * BOWIE — VERSION TESTS
 * ============================================================================
 *
 * Unit tests for src/api/version.c.
 *
 * Every public function in version.h is covered here.
 *
 * The runtime accessors must agree with the compile-time macros.
 * That agreement is asserted explicitly, because a desync
 * between the two is the failure mode this file exists to
 * catch.
 *
 * The parser grammar is tested exhaustively, including the
 * boundary between valid and invalid input. A parser is only as
 * good as its rejection cases, so the rejection cases are the
 * majority of the parser tests.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>           test framework
 *   "bowie/version.h"   the unit under test
 *   "bowie/err.h"       error codes used in assertions
 * ============================================================================
 */

#include <check.h>
#include <stdint.h>
#include <string.h>

#include "bowie/version.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * COMPILE-TIME MACROS
 * ============================================================================
 */

START_TEST(test_version_major_macro)
{
    ck_assert_uint_eq(BOWIE_VERSION_MAJOR, 0);
}
END_TEST

START_TEST(test_version_minor_macro)
{
    ck_assert_uint_eq(BOWIE_VERSION_MINOR, 1);
}
END_TEST

START_TEST(test_version_patch_macro)
{
    ck_assert_uint_eq(BOWIE_VERSION_PATCH, 0);
}
END_TEST

START_TEST(test_version_string_macro)
{
    ck_assert_str_eq(BOWIE_VERSION_STRING, "0.1.0");
}
END_TEST

START_TEST(test_version_code_macro_layout)
{
    /*
     * The packed code layout is MAJOR<<24 | MINOR<<16 | PATCH<<8.
     * For 0.1.0 that is 0x00010000.
     */
    uint32_t expected = ( (uint32_t)BOWIE_VERSION_MAJOR << 24 )
                      | ( (uint32_t)BOWIE_VERSION_MINOR << 16 )
                      | ( (uint32_t)BOWIE_VERSION_PATCH <<  8 );

    ck_assert_uint_eq((uint32_t)BOWIE_VERSION_CODE, expected);
    ck_assert_uint_eq((uint32_t)BOWIE_VERSION_CODE, 0x00010000u);
}
END_TEST

START_TEST(test_version_at_least_macro_true_for_equal)
{
    ck_assert(BOWIE_VERSION_AT_LEAST(BOWIE_VERSION_MAJOR,
                                     BOWIE_VERSION_MINOR,
                                     BOWIE_VERSION_PATCH));
}
END_TEST

START_TEST(test_version_at_least_macro_true_for_older)
{
    ck_assert(BOWIE_VERSION_AT_LEAST(0, 0, 0));
}
END_TEST

START_TEST(test_version_at_least_macro_false_for_newer)
{
    ck_assert(!BOWIE_VERSION_AT_LEAST(99, 0, 0));
}
END_TEST

START_TEST(test_version_before_macro_true_for_newer)
{
    ck_assert(BOWIE_VERSION_BEFORE(99, 0, 0));
}
END_TEST

START_TEST(test_version_before_macro_false_for_equal)
{
    ck_assert(!BOWIE_VERSION_BEFORE(BOWIE_VERSION_MAJOR,
                                    BOWIE_VERSION_MINOR,
                                    BOWIE_VERSION_PATCH));
}
END_TEST

START_TEST(test_version_before_macro_false_for_older)
{
    ck_assert(!BOWIE_VERSION_BEFORE(0, 0, 0));
}
END_TEST

/*
 * ============================================================================
 * RUNTIME ACCESSORS
 * ============================================================================
 */

START_TEST(test_version_string_matches_macro)
{
    ck_assert_str_eq(bowie_version_string(), BOWIE_VERSION_STRING);
}
END_TEST

START_TEST(test_version_string_not_null)
{
    ck_assert_ptr_nonnull(bowie_version_string());
}
END_TEST

START_TEST(test_version_code_matches_macro)
{
    ck_assert_uint_eq(bowie_version_code(),
                      (uint32_t)BOWIE_VERSION_CODE);
}
END_TEST

START_TEST(test_version_components_matches_macros)
{
    uint8_t major = 0xFFu;
    uint8_t minor = 0xFFu;
    uint8_t patch = 0xFFu;

    bowie_version_components(&major, &minor, &patch);

    ck_assert_uint_eq(major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(minor, (uint8_t)BOWIE_VERSION_MINOR);
    ck_assert_uint_eq(patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

START_TEST(test_version_components_null_major)
{
    uint8_t minor = 0xFFu;
    uint8_t patch = 0xFFu;

    bowie_version_components(NULL, &minor, &patch);

    ck_assert_uint_eq(minor, (uint8_t)BOWIE_VERSION_MINOR);
    ck_assert_uint_eq(patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

START_TEST(test_version_components_null_minor)
{
    uint8_t major = 0xFFu;
    uint8_t patch = 0xFFu;

    bowie_version_components(&major, NULL, &patch);

    ck_assert_uint_eq(major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

START_TEST(test_version_components_null_patch)
{
    uint8_t major = 0xFFu;
    uint8_t minor = 0xFFu;

    bowie_version_components(&major, &minor, NULL);

    ck_assert_uint_eq(major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(minor, (uint8_t)BOWIE_VERSION_MINOR);
}
END_TEST

START_TEST(test_version_components_all_null)
{
    /*
     * All-NULL must not crash. There is no output to check;
     * the test passes if the call returns.
     */
    bowie_version_components(NULL, NULL, NULL);
}
END_TEST

START_TEST(test_version_struct_matches_macros)
{
    bowie_version_t v = bowie_version();

    ck_assert_uint_eq(v.major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(v.minor, (uint8_t)BOWIE_VERSION_MINOR);
    ck_assert_uint_eq(v.patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

/*
 * ============================================================================
 * RUNTIME COMPARISON
 * ============================================================================
 */

START_TEST(test_at_least_runtime_true_for_equal)
{
    ck_assert(bowie_version_at_least(BOWIE_VERSION_MAJOR,
                                     BOWIE_VERSION_MINOR,
                                     BOWIE_VERSION_PATCH));
}
END_TEST

START_TEST(test_at_least_runtime_true_for_older)
{
    ck_assert(bowie_version_at_least(0, 0, 0));
}
END_TEST

START_TEST(test_at_least_runtime_false_for_newer)
{
    ck_assert(!bowie_version_at_least(99, 0, 0));
}
END_TEST

START_TEST(test_before_runtime_true_for_newer)
{
    ck_assert(bowie_version_before(99, 0, 0));
}
END_TEST

START_TEST(test_before_runtime_false_for_equal)
{
    ck_assert(!bowie_version_before(BOWIE_VERSION_MAJOR,
                                    BOWIE_VERSION_MINOR,
                                    BOWIE_VERSION_PATCH));
}
END_TEST

START_TEST(test_before_runtime_false_for_older)
{
    ck_assert(!bowie_version_before(0, 0, 0));
}
END_TEST

START_TEST(test_compare_equal)
{
    bowie_version_t a = { 1, 2, 3 };
    bowie_version_t b = { 1, 2, 3 };
    ck_assert_int_eq(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_older_major)
{
    bowie_version_t a = { 1, 2, 3 };
    bowie_version_t b = { 2, 0, 0 };
    ck_assert_int_lt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_newer_major)
{
    bowie_version_t a = { 2, 0, 0 };
    bowie_version_t b = { 1, 99, 99 };
    ck_assert_int_gt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_older_minor)
{
    bowie_version_t a = { 1, 1, 99 };
    bowie_version_t b = { 1, 2, 0 };
    ck_assert_int_lt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_newer_minor)
{
    bowie_version_t a = { 1, 2, 0 };
    bowie_version_t b = { 1, 1, 99 };
    ck_assert_int_gt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_older_patch)
{
    bowie_version_t a = { 1, 2, 2 };
    bowie_version_t b = { 1, 2, 3 };
    ck_assert_int_lt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_a_newer_patch)
{
    bowie_version_t a = { 1, 2, 3 };
    bowie_version_t b = { 1, 2, 2 };
    ck_assert_int_gt(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_zero_versions)
{
    bowie_version_t a = { 0, 0, 0 };
    bowie_version_t b = { 0, 0, 0 };
    ck_assert_int_eq(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_max_versions)
{
    bowie_version_t a = { 255, 255, 255 };
    bowie_version_t b = { 255, 255, 255 };
    ck_assert_int_eq(bowie_version_compare(a, b), 0);
}
END_TEST

START_TEST(test_compare_max_vs_zero)
{
    bowie_version_t a = { 255, 255, 255 };
    bowie_version_t b = { 0, 0, 0 };
    ck_assert_int_gt(bowie_version_compare(a, b), 0);
}
END_TEST

/*
 * ============================================================================
 * VERSION PARSING — VALID INPUTS
 * ============================================================================
 */

START_TEST(test_parse_full)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 2);
    ck_assert_uint_eq(v.patch, 3);
}
END_TEST

START_TEST(test_parse_library_version)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse(BOWIE_VERSION_STRING, &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(v.minor, (uint8_t)BOWIE_VERSION_MINOR);
    ck_assert_uint_eq(v.patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

START_TEST(test_parse_major_only)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 0);
    ck_assert_uint_eq(v.patch, 0);
}
END_TEST

START_TEST(test_parse_major_minor)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 2);
    ck_assert_uint_eq(v.patch, 0);
}
END_TEST

START_TEST(test_parse_lowercase_v_prefix)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("v1.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 2);
    ck_assert_uint_eq(v.patch, 3);
}
END_TEST

START_TEST(test_parse_uppercase_v_prefix)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("V1.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 2);
    ck_assert_uint_eq(v.patch, 3);
}
END_TEST

START_TEST(test_parse_v_prefix_major_only)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("v1", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 0);
    ck_assert_uint_eq(v.patch, 0);
}
END_TEST

START_TEST(test_parse_zero)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("0.0.0", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 0);
    ck_assert_uint_eq(v.minor, 0);
    ck_assert_uint_eq(v.patch, 0);
}
END_TEST

START_TEST(test_parse_max_components)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("255.255.255", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 255);
    ck_assert_uint_eq(v.minor, 255);
    ck_assert_uint_eq(v.patch, 255);
}
END_TEST

START_TEST(test_parse_leading_zeros)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("01.02.03", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 1);
    ck_assert_uint_eq(v.minor, 2);
    ck_assert_uint_eq(v.patch, 3);
}
END_TEST

START_TEST(test_parse_large_major)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("100.0.0", &v);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(v.major, 100);
    ck_assert_uint_eq(v.minor, 0);
    ck_assert_uint_eq(v.patch, 0);
}
END_TEST

/*
 * ============================================================================
 * VERSION PARSING — NULL AND EMPTY
 * ============================================================================
 */

START_TEST(test_parse_null_string)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse(NULL, &v);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_null_out)
{
    bowie_error_t rc = bowie_version_parse("1.2.3", NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_both_null)
{
    bowie_error_t rc = bowie_version_parse(NULL, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_empty_string)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_only_v)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("v", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_only_V)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("V", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * VERSION PARSING — INVALID FORMAT
 * ============================================================================
 */

START_TEST(test_parse_trailing_garbage)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3x", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_trailing_dot)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_trailing_whitespace)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3 ", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_leading_whitespace)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse(" 1.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_four_components)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3.4", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_empty_middle_component)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1..2", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_empty_last_component)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2..", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_leading_dot)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse(".1.2", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_negative_component)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("-1.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_non_digit_major)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("a.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_digit_then_alpha)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1a.2.3", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_prerelease_tag)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3-beta", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_build_metadata)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.3+build", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * VERSION PARSING — OUT OF RANGE
 * ============================================================================
 */

START_TEST(test_parse_major_over_255)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("256.0.0", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_parse_minor_over_255)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.256.0", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_parse_patch_over_255)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("1.2.256", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_parse_major_far_over)
{
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse("9999.0.0", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_parse_component_overflow)
{
    /*
     * A very long digit string must not overflow the
     * accumulator. The range check fires as soon as the value
     * exceeds 255, so the parse stops early.
     */
    bowie_version_t v;
    bowie_error_t rc = bowie_version_parse(
        "999999999999999999999.0.0", &v);

    ck_assert_int_eq(rc, BOWIE_ERR_RANGE);
}
END_TEST

/*
 * ============================================================================
 * ABOUT
 * ============================================================================
 */

START_TEST(test_about_not_null)
{
    ck_assert_ptr_nonnull(bowie_about());
}
END_TEST

START_TEST(test_about_starts_with_bowie)
{
    const char *s = bowie_about();
    ck_assert(strncmp(s, "Bowie", 5) == 0);
}
END_TEST

START_TEST(test_about_contains_version)
{
    const char *s = bowie_about();
    ck_assert_ptr_nonnull(strstr(s, BOWIE_VERSION_STRING));
}
END_TEST

START_TEST(test_about_stable_pointer)
{
    /*
     * bowie_about() returns a pointer to static storage.
     * Calling it twice must return the same pointer.
     */
    const char *a = bowie_about();
    const char *b = bowie_about();
    ck_assert_ptr_eq(a, b);
}
END_TEST

/*
 * ============================================================================
 * CONSISTENCY BETWEEN COMPILE-TIME AND RUNTIME
 * ============================================================================
 *
 * These tests assert the central invariant of this module: the
 * runtime accessors agree with the compile-time macros. If the
 * two ever diverge, one of these fails.
 */

START_TEST(test_string_matches_code)
{
    bowie_version_t v;
    ck_assert_int_eq(bowie_version_parse(bowie_version_string(), &v),
                     BOWIE_OK);
    ck_assert_uint_eq(v.major, (uint8_t)BOWIE_VERSION_MAJOR);
    ck_assert_uint_eq(v.minor, (uint8_t)BOWIE_VERSION_MINOR);
    ck_assert_uint_eq(v.patch, (uint8_t)BOWIE_VERSION_PATCH);
}
END_TEST

START_TEST(test_struct_code_agree)
{
    bowie_version_t v = bowie_version();
    uint32_t from_struct = ( (uint32_t)v.major << 24 )
                         | ( (uint32_t)v.minor << 16 )
                         | ( (uint32_t)v.patch <<  8 );

    ck_assert_uint_eq(from_struct, bowie_version_code());
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *version_suite(void)
{
    Suite *s = suite_create("Version");

    TCase *tc_macros = tcase_create("Macros");
    tcase_add_test(tc_macros, test_version_major_macro);
    tcase_add_test(tc_macros, test_version_minor_macro);
    tcase_add_test(tc_macros, test_version_patch_macro);
    tcase_add_test(tc_macros, test_version_string_macro);
    tcase_add_test(tc_macros, test_version_code_macro_layout);
    tcase_add_test(tc_macros, test_version_at_least_macro_true_for_equal);
    tcase_add_test(tc_macros, test_version_at_least_macro_true_for_older);
    tcase_add_test(tc_macros, test_version_at_least_macro_false_for_newer);
    tcase_add_test(tc_macros, test_version_before_macro_true_for_newer);
    tcase_add_test(tc_macros, test_version_before_macro_false_for_equal);
    tcase_add_test(tc_macros, test_version_before_macro_false_for_older);
    suite_add_tcase(s, tc_macros);

    TCase *tc_accessors = tcase_create("Accessors");
    tcase_add_test(tc_accessors, test_version_string_matches_macro);
    tcase_add_test(tc_accessors, test_version_string_not_null);
    tcase_add_test(tc_accessors, test_version_code_matches_macro);
    tcase_add_test(tc_accessors, test_version_components_matches_macros);
    tcase_add_test(tc_accessors, test_version_components_null_major);
    tcase_add_test(tc_accessors, test_version_components_null_minor);
    tcase_add_test(tc_accessors, test_version_components_null_patch);
    tcase_add_test(tc_accessors, test_version_components_all_null);
    tcase_add_test(tc_accessors, test_version_struct_matches_macros);
    suite_add_tcase(s, tc_accessors);

    TCase *tc_compare = tcase_create("Compare");
    tcase_add_test(tc_compare, test_at_least_runtime_true_for_equal);
    tcase_add_test(tc_compare, test_at_least_runtime_true_for_older);
    tcase_add_test(tc_compare, test_at_least_runtime_false_for_newer);
    tcase_add_test(tc_compare, test_before_runtime_true_for_newer);
    tcase_add_test(tc_compare, test_before_runtime_false_for_equal);
    tcase_add_test(tc_compare, test_before_runtime_false_for_older);
    tcase_add_test(tc_compare, test_compare_equal);
    tcase_add_test(tc_compare, test_compare_a_older_major);
    tcase_add_test(tc_compare, test_compare_a_newer_major);
    tcase_add_test(tc_compare, test_compare_a_older_minor);
    tcase_add_test(tc_compare, test_compare_a_newer_minor);
    tcase_add_test(tc_compare, test_compare_a_older_patch);
    tcase_add_test(tc_compare, test_compare_a_newer_patch);
    tcase_add_test(tc_compare, test_compare_zero_versions);
    tcase_add_test(tc_compare, test_compare_max_versions);
    tcase_add_test(tc_compare, test_compare_max_vs_zero);
    suite_add_tcase(s, tc_compare);

    TCase *tc_parse_valid = tcase_create("ParseValid");
    tcase_add_test(tc_parse_valid, test_parse_full);
    tcase_add_test(tc_parse_valid, test_parse_library_version);
    tcase_add_test(tc_parse_valid, test_parse_major_only);
    tcase_add_test(tc_parse_valid, test_parse_major_minor);
    tcase_add_test(tc_parse_valid, test_parse_lowercase_v_prefix);
    tcase_add_test(tc_parse_valid, test_parse_uppercase_v_prefix);
    tcase_add_test(tc_parse_valid, test_parse_v_prefix_major_only);
    tcase_add_test(tc_parse_valid, test_parse_zero);
    tcase_add_test(tc_parse_valid, test_parse_max_components);
    tcase_add_test(tc_parse_valid, test_parse_leading_zeros);
    tcase_add_test(tc_parse_valid, test_parse_large_major);
    suite_add_tcase(s, tc_parse_valid);

    TCase *tc_parse_null = tcase_create("ParseNull");
    tcase_add_test(tc_parse_null, test_parse_null_string);
    tcase_add_test(tc_parse_null, test_parse_null_out);
    tcase_add_test(tc_parse_null, test_parse_both_null);
    tcase_add_test(tc_parse_null, test_parse_empty_string);
    tcase_add_test(tc_parse_null, test_parse_only_v);
    tcase_add_test(tc_parse_null, test_parse_only_V);
    suite_add_tcase(s, tc_parse_null);

    TCase *tc_parse_bad = tcase_create("ParseBadFormat");
    tcase_add_test(tc_parse_bad, test_parse_trailing_garbage);
    tcase_add_test(tc_parse_bad, test_parse_trailing_dot);
    tcase_add_test(tc_parse_bad, test_parse_trailing_whitespace);
    tcase_add_test(tc_parse_bad, test_parse_leading_whitespace);
    tcase_add_test(tc_parse_bad, test_parse_four_components);
    tcase_add_test(tc_parse_bad, test_parse_empty_middle_component);
    tcase_add_test(tc_parse_bad, test_parse_empty_last_component);
    tcase_add_test(tc_parse_bad, test_parse_leading_dot);
    tcase_add_test(tc_parse_bad, test_parse_negative_component);
    tcase_add_test(tc_parse_bad, test_parse_non_digit_major);
    tcase_add_test(tc_parse_bad, test_parse_digit_then_alpha);
    tcase_add_test(tc_parse_bad, test_parse_prerelease_tag);
    tcase_add_test(tc_parse_bad, test_parse_build_metadata);
    suite_add_tcase(s, tc_parse_bad);

    TCase *tc_parse_range = tcase_create("ParseRange");
    tcase_add_test(tc_parse_range, test_parse_major_over_255);
    tcase_add_test(tc_parse_range, test_parse_minor_over_255);
    tcase_add_test(tc_parse_range, test_parse_patch_over_255);
    tcase_add_test(tc_parse_range, test_parse_major_far_over);
    tcase_add_test(tc_parse_range, test_parse_component_overflow);
    suite_add_tcase(s, tc_parse_range);

    TCase *tc_about = tcase_create("About");
    tcase_add_test(tc_about, test_about_not_null);
    tcase_add_test(tc_about, test_about_starts_with_bowie);
    tcase_add_test(tc_about, test_about_contains_version);
    tcase_add_test(tc_about, test_about_stable_pointer);
    suite_add_tcase(s, tc_about);

    TCase *tc_consistency = tcase_create("Consistency");
    tcase_add_test(tc_consistency, test_string_matches_code);
    tcase_add_test(tc_consistency, test_struct_code_agree);
    suite_add_tcase(s, tc_consistency);

    return s;
}

int main(void)
{
    Suite *s = version_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
