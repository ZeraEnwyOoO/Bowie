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
 * BOWIE — RANDOM TESTS
 * ============================================================================
 *
 * Unit tests for src/core/rand.c.
 *
 * Every public function declared in core/internal/rand.h is
 * covered here.
 *
 * The tests fall into three groups:
 *
 *   1. Contract tests. The function exists, returns the
 *      documented value, and accepts the documented inputs.
 *
 *   2. Statistical smoke tests. A sequence of values from the
 *      fast generator is checked for the properties a caller
 *      relies on: it is not constant, it is not obviously
 *      periodic, and the range functions stay in range.
 *
 *   3. Secure generator tests. The secure generator is
 *      checked for the properties a caller relies on: it
 *      returns BOWIE_OK, it produces non-zero values, and it
 *      stays in range. It is not tested for unpredictability;
 *      that property cannot be tested from inside the process.
 *
 * The tests do not check for a specific sequence. The
 * generators are not seedable from outside, so no specific
 * sequence is promised. A test that checked a specific
 * sequence would be a test of the implementation, not of the
 * contract.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <stdint.h>                      uint32_t, uint64_t
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "core/internal/rand.h"          the unit under test
 * ============================================================================
 */

#include <check.h>
#include <stdint.h>
#include <string.h>

#include "bowie/err.h"
#include "core/internal/rand.h"

/*
 * ============================================================================
 * FAST GENERATOR — U64
 * ============================================================================
 */

START_TEST(test_fast_u64_returns_a_value)
{
    (void)bowie_rand_fast_u64();
}
END_TEST

START_TEST(test_fast_u64_not_constant)
{
    /*
     * Ten values in a row. It is astronomically unlikely that
     * a working generator produces the same value ten times.
     * A failure here means the generator is stuck.
     */
    uint64_t first = bowie_rand_fast_u64();
    int different = 0;

    for (int i = 0; i < 10; i++) {
        if (bowie_rand_fast_u64() != first) {
            different = 1;
            break;
        }
    }

    ck_assert(different);
}
END_TEST

START_TEST(test_fast_u64_sequence_not_constant)
{
    /*
     * A longer run. No two adjacent values are equal.
     */
    uint64_t prev = bowie_rand_fast_u64();
    for (int i = 0; i < 1000; i++) {
        uint64_t now = bowie_rand_fast_u64();
        ck_assert_uint_ne(now, prev);
        prev = now;
    }
}
END_TEST

/*
 * ============================================================================
 * FAST GENERATOR — U32
 * ============================================================================
 */

START_TEST(test_fast_u32_returns_a_value)
{
    (void)bowie_rand_fast_u32();
}
END_TEST

START_TEST(test_fast_u32_not_constant)
{
    uint32_t first = bowie_rand_fast_u32();
    int different = 0;

    for (int i = 0; i < 10; i++) {
        if (bowie_rand_fast_u32() != first) {
            different = 1;
            break;
        }
    }

    ck_assert(different);
}
END_TEST

/*
 * ============================================================================
 * FAST GENERATOR — BYTES
 * ============================================================================
 */

START_TEST(test_fast_bytes_fills_buffer)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    bowie_rand_fast_bytes(buf, sizeof(buf));

    /*
     * At least one byte must differ from zero. A buffer that
     * stays all-zero would mean the generator wrote nothing.
     */
    int non_zero = 0;
    for (size_t i = 0u; i < sizeof(buf); i++) {
        if (buf[i] != 0u) {
            non_zero = 1;
            break;
        }
    }
    ck_assert(non_zero);
}
END_TEST

START_TEST(test_fast_bytes_two_buffers_differ)
{
    uint8_t a[32];
    uint8_t b[32];

    bowie_rand_fast_bytes(a, sizeof(a));
    bowie_rand_fast_bytes(b, sizeof(b));

    ck_assert_int_ne(memcmp(a, b, sizeof(a)), 0);
}
END_TEST

START_TEST(test_fast_bytes_zero_len)
{
    uint8_t buf[4] = { 1, 2, 3, 4 };
    bowie_rand_fast_bytes(buf, 0u);
    ck_assert_uint_eq(buf[0], 1u);
}
END_TEST

START_TEST(test_fast_bytes_null_is_noop)
{
    bowie_rand_fast_bytes(NULL, 32u);
    /* No crash. */
}
END_TEST

/*
 * ============================================================================
 * FAST GENERATOR — BELOW
 * ============================================================================
 */

START_TEST(test_fast_below_zero_returns_zero)
{
    ck_assert_uint_eq(bowie_rand_fast_below(0u), 0u);
}
END_TEST

START_TEST(test_fast_below_one_returns_zero)
{
    ck_assert_uint_eq(bowie_rand_fast_below(1u), 0u);
}
END_TEST

START_TEST(test_fast_below_range)
{
    /*
     * A long run of values in the range [0, 100). Every value
     * must be less than the bound.
     */
    for (int i = 0; i < 1000; i++) {
        uint64_t v = bowie_rand_fast_below(100u);
        ck_assert_uint_lt(v, 100u);
    }
}
END_TEST

START_TEST(test_fast_below_covers_range)
{
    /*
     * With 10000 samples from [0, 10), every value should
     * appear at least once. A generator that returned only
     * one value would fail this.
     */
    int seen[10] = { 0 };

    for (int i = 0; i < 10000; i++) {
        uint64_t v = bowie_rand_fast_below(10u);
        seen[v]++;
    }

    for (int i = 0; i < 10; i++) {
        ck_assert_int_gt(seen[i], 0);
    }
}
END_TEST

START_TEST(test_fast_below_two_returns_zero_or_one)
{
    for (int i = 0; i < 100; i++) {
        uint64_t v = bowie_rand_fast_below(2u);
        ck_assert(v == 0u || v == 1u);
    }
}
END_TEST

/*
 * ============================================================================
 * SECURE GENERATOR — BYTES
 * ============================================================================
 */

START_TEST(test_secure_bytes_basic)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));

    ck_assert_int_eq(bowie_rand_secure_bytes(buf, sizeof(buf)),
                     BOWIE_OK);

    /*
     * At least one byte must differ from zero.
     */
    int non_zero = 0;
    for (size_t i = 0u; i < sizeof(buf); i++) {
        if (buf[i] != 0u) {
            non_zero = 1;
            break;
        }
    }
    ck_assert(non_zero);
}
END_TEST

START_TEST(test_secure_bytes_zero_len)
{
    uint8_t buf[4] = { 1, 2, 3, 4 };
    ck_assert_int_eq(bowie_rand_secure_bytes(buf, 0u), BOWIE_OK);
    ck_assert_uint_eq(buf[0], 1u);
}
END_TEST

START_TEST(test_secure_bytes_null_with_len)
{
    ck_assert_int_eq(bowie_rand_secure_bytes(NULL, 32u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_secure_bytes_null_zero_len)
{
    ck_assert_int_eq(bowie_rand_secure_bytes(NULL, 0u), BOWIE_OK);
}
END_TEST

START_TEST(test_secure_bytes_two_buffers_differ)
{
    uint8_t a[32];
    uint8_t b[32];

    ck_assert_int_eq(bowie_rand_secure_bytes(a, sizeof(a)),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_rand_secure_bytes(b, sizeof(b)),
                     BOWIE_OK);

    ck_assert_int_ne(memcmp(a, b, sizeof(a)), 0);
}
END_TEST

/*
 * ============================================================================
 * SECURE GENERATOR — U64
 * ============================================================================
 */

START_TEST(test_secure_u64_basic)
{
    uint64_t v = 0u;
    ck_assert_int_eq(bowie_rand_secure_u64(&v), BOWIE_OK);
    ck_assert_uint_ne(v, 0u);
}
END_TEST

START_TEST(test_secure_u64_null)
{
    ck_assert_int_eq(bowie_rand_secure_u64(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_secure_u64_not_constant)
{
    uint64_t first = 0u;
    ck_assert_int_eq(bowie_rand_secure_u64(&first), BOWIE_OK);

    int different = 0;
    for (int i = 0; i < 10; i++) {
        uint64_t v = 0u;
        ck_assert_int_eq(bowie_rand_secure_u64(&v), BOWIE_OK);
        if (v != first) {
            different = 1;
            break;
        }
    }
    ck_assert(different);
}
END_TEST

/*
 * ============================================================================
 * SECURE GENERATOR — U32
 * ============================================================================
 */

START_TEST(test_secure_u32_basic)
{
    uint32_t v = 0u;
    ck_assert_int_eq(bowie_rand_secure_u32(&v), BOWIE_OK);
    ck_assert_uint_ne(v, 0u);
}
END_TEST

START_TEST(test_secure_u32_null)
{
    ck_assert_int_eq(bowie_rand_secure_u32(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * SECURE GENERATOR — BELOW
 * ============================================================================
 */

START_TEST(test_secure_below_zero_bound)
{
    uint64_t out = 99u;
    ck_assert_int_eq(bowie_rand_secure_below(0u, &out),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_secure_below_one_bound)
{
    uint64_t out = 99u;
    ck_assert_int_eq(bowie_rand_secure_below(1u, &out), BOWIE_OK);
    ck_assert_uint_eq(out, 0u);
}
END_TEST

START_TEST(test_secure_below_null_out)
{
    ck_assert_int_eq(bowie_rand_secure_below(10u, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_secure_below_range)
{
    for (int i = 0; i < 100; i++) {
        uint64_t v = 0u;
        ck_assert_int_eq(bowie_rand_secure_below(100u, &v),
                         BOWIE_OK);
        ck_assert_uint_lt(v, 100u);
    }
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *rand_suite(void)
{
    Suite *s = suite_create("Rand");

    TCase *tc_fu64 = tcase_create("FastU64");
    tcase_add_test(tc_fu64, test_fast_u64_returns_a_value);
    tcase_add_test(tc_fu64, test_fast_u64_not_constant);
    tcase_add_test(tc_fu64, test_fast_u64_sequence_not_constant);
    suite_add_tcase(s, tc_fu64);

    TCase *tc_fu32 = tcase_create("FastU32");
    tcase_add_test(tc_fu32, test_fast_u32_returns_a_value);
    tcase_add_test(tc_fu32, test_fast_u32_not_constant);
    suite_add_tcase(s, tc_fu32);

    TCase *tc_fb = tcase_create("FastBytes");
    tcase_add_test(tc_fb, test_fast_bytes_fills_buffer);
    tcase_add_test(tc_fb, test_fast_bytes_two_buffers_differ);
    tcase_add_test(tc_fb, test_fast_bytes_zero_len);
    tcase_add_test(tc_fb, test_fast_bytes_null_is_noop);
    suite_add_tcase(s, tc_fb);

    TCase *tc_fbelow = tcase_create("FastBelow");
    tcase_add_test(tc_fbelow, test_fast_below_zero_returns_zero);
    tcase_add_test(tc_fbelow, test_fast_below_one_returns_zero);
    tcase_add_test(tc_fbelow, test_fast_below_range);
    tcase_add_test(tc_fbelow, test_fast_below_covers_range);
    tcase_add_test(tc_fbelow, test_fast_below_two_returns_zero_or_one);
    suite_add_tcase(s, tc_fbelow);

    TCase *tc_sb = tcase_create("SecureBytes");
    tcase_add_test(tc_sb, test_secure_bytes_basic);
    tcase_add_test(tc_sb, test_secure_bytes_zero_len);
    tcase_add_test(tc_sb, test_secure_bytes_null_with_len);
    tcase_add_test(tc_sb, test_secure_bytes_null_zero_len);
    tcase_add_test(tc_sb, test_secure_bytes_two_buffers_differ);
    suite_add_tcase(s, tc_sb);

    TCase *tc_su64 = tcase_create("SecureU64");
    tcase_add_test(tc_su64, test_secure_u64_basic);
    tcase_add_test(tc_su64, test_secure_u64_null);
    tcase_add_test(tc_su64, test_secure_u64_not_constant);
    suite_add_tcase(s, tc_su64);

    TCase *tc_su32 = tcase_create("SecureU32");
    tcase_add_test(tc_su32, test_secure_u32_basic);
    tcase_add_test(tc_su32, test_secure_u32_null);
    suite_add_tcase(s, tc_su32);

    TCase *tc_sbelow = tcase_create("SecureBelow");
    tcase_add_test(tc_sbelow, test_secure_below_zero_bound);
    tcase_add_test(tc_sbelow, test_secure_below_one_bound);
    tcase_add_test(tc_sbelow, test_secure_below_null_out);
    tcase_add_test(tc_sbelow, test_secure_below_range);
    suite_add_tcase(s, tc_sbelow);

    return s;
}

int main(void)
{
    Suite *s = rand_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
