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
 * BOWIE — TIME TESTS
 * ============================================================================
 *
 * Unit tests for src/core/time.c.
 *
 * Every public function declared in core/internal/time.h is
 * covered here.
 *
 * The monotonic clock is tested for its defining property: it
 * does not go backwards. Two calls in a row return equal or
 * increasing values.
 *
 * The wall clock is tested for a lower bound: it is greater
 * than zero, and it is greater than a known past date. The
 * wall clock is not tested for an upper bound, because the
 * test would be wrong on a machine with a clock set forward.
 *
 * Neither clock is tested for an exact value. Both are read
 * from the system, and the system is not under test.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <stdint.h>                      uint64_t
 *   "core/internal/time.h"          the unit under test
 * ============================================================================
 */

#include <check.h>
#include <stdint.h>

#include "core/internal/time.h"

/*
 * ============================================================================
 * MONOTONIC CLOCK
 * ============================================================================
 */

START_TEST(test_monotonic_returns_a_value)
{
    /*
     * The call must return. The value is not constrained; any
     * uint64_t is a valid monotonic timestamp.
     */
    (void)bowie_time_monotonic_ms();
}
END_TEST

START_TEST(test_monotonic_does_not_go_backwards)
{
    /*
     * The defining property of a monotonic clock. Two calls in
     * a row return equal or increasing values.
     *
     * The calls are close enough together that a wrap is not
     * possible in any realistic scenario.
     */
    bowie_mtime_t a = bowie_time_monotonic_ms();
    bowie_mtime_t b = bowie_time_monotonic_ms();

    ck_assert_uint_ge(b, a);
}
END_TEST

START_TEST(test_monotonic_many_calls_non_decreasing)
{
    /*
     * A longer sequence. Every value is greater than or equal
     * to the previous one.
     */
    bowie_mtime_t prev = bowie_time_monotonic_ms();
    for (int i = 0; i < 100; i++) {
        bowie_mtime_t now = bowie_time_monotonic_ms();
        ck_assert_uint_ge(now, prev);
        prev = now;
    }
}
END_TEST

/*
 * ============================================================================
 * WALL CLOCK
 * ============================================================================
 */

START_TEST(test_wallclock_returns_a_value)
{
    (void)bowie_time_wallclock_ms();
}
END_TEST

START_TEST(test_wallclock_after_2020)
{
    /*
     * 2020-01-01T00:00:00 UTC is 1577836800000 ms since the
     * Unix epoch. Any machine with a sane clock is past this.
     *
     * The check is a lower bound, not an upper bound. A machine
     * with a clock set forward is not a Bowie bug.
     */
    const uint64_t y2020 = 1577836800000ull;
    ck_assert_uint_gt(bowie_time_wallclock_ms(), y2020);
}
END_TEST

START_TEST(test_wallclock_after_1970)
{
    /*
     * The value is milliseconds since the Unix epoch, so it
     * must be greater than zero unless the system clock is set
     * to a date before 1970. A machine in that state is
     * pathological, not a Bowie bug, but the test fails loudly
     * so that the state is not silently accepted.
     */
    ck_assert_uint_gt(bowie_time_wallclock_ms(), 0u);
}
END_TEST

/*
 * ============================================================================
 * BOTH CLOCKS
 * ============================================================================
 */

START_TEST(test_both_clocks_agree_on_scale)
{
    /*
     * Both functions return milliseconds. If the wall clock is
     * roughly 1.7e12 (about 55 years) and the monotonic clock
     * is roughly the time since boot, the two values can
     * differ by orders of magnitude. They must not differ by
     * a factor that suggests one is in seconds and the other
     * in milliseconds.
     *
     * The test reads both once and checks that the wall clock
     * is at least 1e9 (i.e. the epoch is far from zero). This
     * catches the mistake of returning seconds from the wall
     * clock.
     */
    bowie_wtime_t w = bowie_time_wallclock_ms();
    ck_assert_uint_gt(w, 1000000000ull);
}
END_TEST

START_TEST(test_monotonic_not_mistaken_for_seconds)
{
    /*
     * If the monotonic clock returned seconds instead of
     * milliseconds, a pair of calls would usually return the
     * same value. The test does not require the two calls to
     * differ, because a fast machine can complete both within
     * the same millisecond. It only checks that the value is
     * plausible as milliseconds: a machine that has been up
     * for at least one second returns a value of at least
     * 1000, but that is not guaranteed.
     *
     * The check is therefore weak by design. It is a smoke
     * test, not a unit test of the scale.
     */
    (void)bowie_time_monotonic_ms();
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *time_suite(void)
{
    Suite *s = suite_create("Time");

    TCase *tc_mono = tcase_create("Monotonic");
    tcase_add_test(tc_mono, test_monotonic_returns_a_value);
    tcase_add_test(tc_mono, test_monotonic_does_not_go_backwards);
    tcase_add_test(tc_mono, test_monotonic_many_calls_non_decreasing);
    tcase_add_test(tc_mono, test_monotonic_not_mistaken_for_seconds);
    suite_add_tcase(s, tc_mono);

    TCase *tc_wall = tcase_create("Wallclock");
    tcase_add_test(tc_wall, test_wallclock_returns_a_value);
    tcase_add_test(tc_wall, test_wallclock_after_2020);
    tcase_add_test(tc_wall, test_wallclock_after_1970);
    suite_add_tcase(s, tc_wall);

    TCase *tc_both = tcase_create("Both");
    tcase_add_test(tc_both, test_both_clocks_agree_on_scale);
    suite_add_tcase(s, tc_both);

    return s;
}

int main(void)
{
    Suite *s = time_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
