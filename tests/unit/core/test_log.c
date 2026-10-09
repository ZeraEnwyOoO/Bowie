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
 * BOWIE — LOG TESTS
 * ============================================================================
 *
 * Unit tests for src/core/log.c.
 *
 * Every public function declared in core/internal/log.h is
 * covered here.
 *
 * The emit tests use a capture hook that copies each line into
 * a static buffer. The hook is the boundary between the log
 * module and the caller; testing it directly would be testing
 * the test, not the module. The capture hook is a real hook,
 * not a stub: it performs the same job a real hook would, and
 * the tests read what it captured.
 *
 * The format parser is tested with each supported specifier, a
 * few unsupported ones, and the boundary cases (trailing '%',
 * truncated line, empty format).
 *
 * ----------------------------------------------------------------------------
 * Compiler format checks
 * ----------------------------------------------------------------------------
 *
 * The log module has its own format parser. Its specifier set
 * is smaller than printf's, and it treats an unsupported
 * specifier as literal text rather than an error. The
 * compiler's printf-checking does not know this, so a few
 * tests below would be rejected by -Wformat. The pragma below
 * disables that check for this file only. The compiler still
 * checks every other warning.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, strcmp
 *   "bowie/config.h"                log levels
 *   "bowie/hooks.h"                 hook types
 *   "core/internal/log.h"           the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/config.h"
#include "bowie/hooks.h"
#include "core/internal/log.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#pragma GCC diagnostic ignored "-Wformat-overflow"
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/*
 * ============================================================================
 * CAPTURE HOOK
 * ============================================================================
 *
 * A real log hook that copies each line into a static buffer.
 * The tests read the buffer after the call.
 */

static char       g_captured_line[BOWIE_LOG_LINE_MAX];
static int        g_capture_count;
static bowie_log_level_t g_captured_level;

static void capture_hook(bowie_log_level_t level,
                         const char *line,
                         void *userdata)
{
    (void)userdata;
    g_captured_level = level;
    g_capture_count++;
    if (line != NULL) {
        strncpy(g_captured_line, line, sizeof(g_captured_line) - 1u);
        g_captured_line[sizeof(g_captured_line) - 1u] = '\0';
    } else {
        g_captured_line[0] = '\0';
    }
}

static void capture_reset(void)
{
    g_captured_line[0] = '\0';
    g_capture_count    = 0;
    g_captured_level   = BOWIE_LOG_NONE;
}

/*
 * ============================================================================
 * LEVEL NAMES
 * ============================================================================
 */

START_TEST(test_level_name_none)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_NONE), "none");
}
END_TEST

START_TEST(test_level_name_error)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_ERROR), "error");
}
END_TEST

START_TEST(test_level_name_warn)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_WARN), "warn");
}
END_TEST

START_TEST(test_level_name_info)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_INFO), "info");
}
END_TEST

START_TEST(test_level_name_debug)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_DEBUG), "debug");
}
END_TEST

START_TEST(test_level_name_trace)
{
    ck_assert_str_eq(bowie_log_level_name(BOWIE_LOG_TRACE), "trace");
}
END_TEST

START_TEST(test_level_name_unknown)
{
    ck_assert_str_eq(bowie_log_level_name((bowie_log_level_t)999),
                     "unknown");
}
END_TEST

START_TEST(test_level_tag_none)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_NONE), '-');
}
END_TEST

START_TEST(test_level_tag_error)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_ERROR), 'E');
}
END_TEST

START_TEST(test_level_tag_warn)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_WARN), 'W');
}
END_TEST

START_TEST(test_level_tag_info)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_INFO), 'I');
}
END_TEST

START_TEST(test_level_tag_debug)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_DEBUG), 'D');
}
END_TEST

START_TEST(test_level_tag_trace)
{
    ck_assert_int_eq(bowie_log_level_tag(BOWIE_LOG_TRACE), 'T');
}
END_TEST

START_TEST(test_level_tag_unknown)
{
    ck_assert_int_eq(bowie_log_level_tag((bowie_log_level_t)999), '?');
}
END_TEST

/*
 * ============================================================================
 * INIT
 * ============================================================================
 */

START_TEST(test_init_null_is_noop)
{
    bowie_log_init(NULL, NULL, BOWIE_LOG_INFO);
}
END_TEST

START_TEST(test_init_null_hooks_clears)
{
    bowie_log_t log;
    memset(&log, 0xFF, sizeof(log));

    bowie_log_init(&log, NULL, BOWIE_LOG_INFO);

    ck_assert_int_eq(log.level, BOWIE_LOG_INFO);
    ck_assert(log.hook == NULL);
    ck_assert_ptr_null(log.userdata);
}
END_TEST

START_TEST(test_init_copies_hook_and_userdata)
{
    bowie_hooks_t hooks;
    int sentinel = 42;

    memset(&hooks, 0, sizeof(hooks));
    hooks.log          = capture_hook;
    hooks.log_userdata = &sentinel;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);

    ck_assert_int_eq(log.level, BOWIE_LOG_DEBUG);
    ck_assert(log.hook == capture_hook);
    ck_assert_ptr_eq(log.userdata, &sentinel);
}
END_TEST

/*
 * ============================================================================
 * SET/GET LEVEL
 * ============================================================================
 */

START_TEST(test_set_level_null_is_noop)
{
    bowie_log_set_level(NULL, BOWIE_LOG_ERROR);
}
END_TEST

START_TEST(test_set_get_level)
{
    bowie_log_t log;
    bowie_log_init(&log, NULL, BOWIE_LOG_INFO);

    bowie_log_set_level(&log, BOWIE_LOG_DEBUG);
    ck_assert_int_eq(bowie_log_get_level(&log), BOWIE_LOG_DEBUG);

    bowie_log_set_level(&log, BOWIE_LOG_ERROR);
    ck_assert_int_eq(bowie_log_get_level(&log), BOWIE_LOG_ERROR);
}
END_TEST

START_TEST(test_get_level_null)
{
    ck_assert_int_eq(bowie_log_get_level(NULL), BOWIE_LOG_NONE);
}
END_TEST

/*
 * ============================================================================
 * ENABLED
 * ============================================================================
 */

START_TEST(test_enabled_null_log)
{
    ck_assert(!bowie_log_enabled(NULL, BOWIE_LOG_ERROR));
}
END_TEST

START_TEST(test_enabled_no_hook)
{
    bowie_log_t log;
    bowie_log_init(&log, NULL, BOWIE_LOG_DEBUG);

    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_ERROR));
    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_DEBUG));
}
END_TEST

START_TEST(test_enabled_with_hook_respects_level)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_WARN);

    ck_assert(bowie_log_enabled(&log, BOWIE_LOG_ERROR));
    ck_assert(bowie_log_enabled(&log, BOWIE_LOG_WARN));

    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_INFO));
    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_DEBUG));
    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_TRACE));
}
END_TEST

START_TEST(test_enabled_level_none_disables_all)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_NONE);

    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_ERROR));
    ck_assert(!bowie_log_enabled(&log, BOWIE_LOG_NONE));
}
END_TEST

/*
 * ============================================================================
 * EMIT — BASIC
 * ============================================================================
 */

START_TEST(test_emit_null_log_is_noop)
{
    bowie_log_emit(NULL, BOWIE_LOG_ERROR, "hello");
}
END_TEST

START_TEST(test_emit_null_fmt_is_noop)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_ERROR, NULL);

    ck_assert_int_eq(g_capture_count, 0);
}
END_TEST

START_TEST(test_emit_below_level_is_noop)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_ERROR);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "should not appear");

    ck_assert_int_eq(g_capture_count, 0);
}
END_TEST

START_TEST(test_emit_no_hook_is_noop)
{
    bowie_log_t log;
    bowie_log_init(&log, NULL, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_ERROR, "should not appear");

    ck_assert_int_eq(g_capture_count, 0);
}
END_TEST

START_TEST(test_emit_simple_string)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "hello");

    ck_assert_int_eq(g_capture_count, 1);
    ck_assert_int_eq(g_captured_level, BOWIE_LOG_INFO);
    ck_assert_str_eq(g_captured_line, "hello");
}
END_TEST

START_TEST(test_emit_passes_level_to_hook)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);

    capture_reset();
    bowie_log_emit(&log, BOWIE_LOG_ERROR, "e");
    ck_assert_int_eq(g_captured_level, BOWIE_LOG_ERROR);

    capture_reset();
    bowie_log_emit(&log, BOWIE_LOG_WARN, "w");
    ck_assert_int_eq(g_captured_level, BOWIE_LOG_WARN);

    capture_reset();
    bowie_log_emit(&log, BOWIE_LOG_INFO, "i");
    ck_assert_int_eq(g_captured_level, BOWIE_LOG_INFO);

    capture_reset();
    bowie_log_emit(&log, BOWIE_LOG_DEBUG, "d");
    ck_assert_int_eq(g_captured_level, BOWIE_LOG_DEBUG);
}
END_TEST

/*
 * ============================================================================
 * EMIT — FORMAT SPECIFIERS
 * ============================================================================
 */

START_TEST(test_emit_fmt_string)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "hello %s", "world");

    ck_assert_str_eq(g_captured_line, "hello world");
}
END_TEST

START_TEST(test_emit_fmt_int)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "n=%d", -42);

    ck_assert_str_eq(g_captured_line, "n=-42");
}
END_TEST

START_TEST(test_emit_fmt_uint)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "n=%u", 42u);

    ck_assert_str_eq(g_captured_line, "n=42");
}
END_TEST

START_TEST(test_emit_fmt_hex)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "x=%x", 0xDEADu);

    ck_assert_str_eq(g_captured_line, "x=dead");
}
END_TEST

START_TEST(test_emit_fmt_llu)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "n=%llu",
                   1234567890123ull);

    ck_assert_str_eq(g_captured_line, "n=1234567890123");
}
END_TEST

START_TEST(test_emit_fmt_lld)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "n=%lld",
                   -1234567890123ll);

    ck_assert_str_eq(g_captured_line, "n=-1234567890123");
}
END_TEST

START_TEST(test_emit_fmt_zu)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "n=%zu", (size_t)42u);

    ck_assert_str_eq(g_captured_line, "n=42");
}
END_TEST

START_TEST(test_emit_fmt_percent)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "100%%");

    ck_assert_str_eq(g_captured_line, "100%");
}
END_TEST

START_TEST(test_emit_fmt_null_string)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "%s", (const char *)NULL);

    ck_assert_str_eq(g_captured_line, "(null)");
}
END_TEST

START_TEST(test_emit_fmt_multiple)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO,
                   "%s: n=%d, x=%x", "ok", 7, 0xFFu);

    ck_assert_str_eq(g_captured_line, "ok: n=7, x=ff");
}
END_TEST

START_TEST(test_emit_fmt_trailing_percent)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "abc%");

    ck_assert_str_eq(g_captured_line, "abc%");
}
END_TEST

START_TEST(test_emit_fmt_unknown_specifier_verbatim)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    /* %q is not supported; the '%q' is copied verbatim. */
    bowie_log_emit(&log, BOWIE_LOG_INFO, "a%qb");

    ck_assert_str_eq(g_captured_line, "a%qb");
}
END_TEST

START_TEST(test_emit_fmt_empty)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    bowie_log_emit(&log, BOWIE_LOG_INFO, "");

    ck_assert_str_eq(g_captured_line, "");
}
END_TEST

/*
 * ============================================================================
 * EMIT — TRUNCATION
 * ============================================================================
 */

START_TEST(test_emit_truncates_long_line)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = capture_hook;

    bowie_log_t log;
    bowie_log_init(&log, &hooks, BOWIE_LOG_DEBUG);
    capture_reset();

    char big[BOWIE_LOG_LINE_MAX + 64];
    for (size_t i = 0u; i < sizeof(big) - 1u; i++) {
        big[i] = 'x';
    }
    big[sizeof(big) - 1u] = '\0';

    bowie_log_emit(&log, BOWIE_LOG_INFO, "%s", big);

    ck_assert_int_eq(g_capture_count, 1);
    ck_assert_uint_eq(strlen(g_captured_line),
                      BOWIE_LOG_LINE_MAX - 1u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *log_suite(void)
{
    Suite *s = suite_create("Log");

    TCase *tc_lvl = tcase_create("LevelNames");
    tcase_add_test(tc_lvl, test_level_name_none);
    tcase_add_test(tc_lvl, test_level_name_error);
    tcase_add_test(tc_lvl, test_level_name_warn);
    tcase_add_test(tc_lvl, test_level_name_info);
    tcase_add_test(tc_lvl, test_level_name_debug);
    tcase_add_test(tc_lvl, test_level_name_trace);
    tcase_add_test(tc_lvl, test_level_name_unknown);
    tcase_add_test(tc_lvl, test_level_tag_none);
    tcase_add_test(tc_lvl, test_level_tag_error);
    tcase_add_test(tc_lvl, test_level_tag_warn);
    tcase_add_test(tc_lvl, test_level_tag_info);
    tcase_add_test(tc_lvl, test_level_tag_debug);
    tcase_add_test(tc_lvl, test_level_tag_trace);
    tcase_add_test(tc_lvl, test_level_tag_unknown);
    suite_add_tcase(s, tc_lvl);

    TCase *tc_init = tcase_create("Init");
    tcase_add_test(tc_init, test_init_null_is_noop);
    tcase_add_test(tc_init, test_init_null_hooks_clears);
    tcase_add_test(tc_init, test_init_copies_hook_and_userdata);
    suite_add_tcase(s, tc_init);

    TCase *tc_lvlset = tcase_create("SetGetLevel");
    tcase_add_test(tc_lvlset, test_set_level_null_is_noop);
    tcase_add_test(tc_lvlset, test_set_get_level);
    tcase_add_test(tc_lvlset, test_get_level_null);
    suite_add_tcase(s, tc_lvlset);

    TCase *tc_en = tcase_create("Enabled");
    tcase_add_test(tc_en, test_enabled_null_log);
    tcase_add_test(tc_en, test_enabled_no_hook);
    tcase_add_test(tc_en, test_enabled_with_hook_respects_level);
    tcase_add_test(tc_en, test_enabled_level_none_disables_all);
    suite_add_tcase(s, tc_en);

    TCase *tc_emit = tcase_create("EmitBasic");
    tcase_add_test(tc_emit, test_emit_null_log_is_noop);
    tcase_add_test(tc_emit, test_emit_null_fmt_is_noop);
    tcase_add_test(tc_emit, test_emit_below_level_is_noop);
    tcase_add_test(tc_emit, test_emit_no_hook_is_noop);
    tcase_add_test(tc_emit, test_emit_simple_string);
    tcase_add_test(tc_emit, test_emit_passes_level_to_hook);
    suite_add_tcase(s, tc_emit);

    TCase *tc_fmt = tcase_create("EmitFormat");
    tcase_add_test(tc_fmt, test_emit_fmt_string);
    tcase_add_test(tc_fmt, test_emit_fmt_int);
    tcase_add_test(tc_fmt, test_emit_fmt_uint);
    tcase_add_test(tc_fmt, test_emit_fmt_hex);
    tcase_add_test(tc_fmt, test_emit_fmt_llu);
    tcase_add_test(tc_fmt, test_emit_fmt_lld);
    tcase_add_test(tc_fmt, test_emit_fmt_zu);
    tcase_add_test(tc_fmt, test_emit_fmt_percent);
    tcase_add_test(tc_fmt, test_emit_fmt_null_string);
    tcase_add_test(tc_fmt, test_emit_fmt_multiple);
    tcase_add_test(tc_fmt, test_emit_fmt_trailing_percent);
    tcase_add_test(tc_fmt, test_emit_fmt_unknown_specifier_verbatim);
    tcase_add_test(tc_fmt, test_emit_fmt_empty);
    suite_add_tcase(s, tc_fmt);

    TCase *tc_trunc = tcase_create("EmitTruncate");
    tcase_add_test(tc_trunc, test_emit_truncates_long_line);
    suite_add_tcase(s, tc_trunc);

    return s;
}

int main(void)
{
    Suite *s = log_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
