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
 * BOWIE — HOOKS TESTS
 * ============================================================================
 *
 * Unit tests for src/api/hooks.c.
 *
 * Every public function declared in bowie/hooks.h is covered.
 *
 * The event-name tests assert that every name is non-NULL,
 * unique, and stable across calls. The event list is currently
 * a PROPOSAL; these tests assert the properties the function
 * promises, not the specific values, so that the list can be
 * extended without rewriting the tests.
 *
 * ----------------------------------------------------------------------------
 * Design note: function pointers and ck_assert_ptr_null
 * ----------------------------------------------------------------------------
 *
 * ck_assert_ptr_null() takes a void pointer. A function pointer
 * is not convertible to void * under ISO C, and -Wpedantic
 * rejects the conversion. The tests therefore compare a
 * function pointer to NULL directly with ck_assert(), which is
 * well-defined and portable. Object pointers (userdata) still
 * use ck_assert_ptr_null(), because those are convertible.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>        test framework
 *   <string.h>       memset
 *   "bowie/hooks.h"  the unit under test
 *   "bowie/err.h"    error codes
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/hooks.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * DUMMY HOOK FUNCTIONS
 * ============================================================================
 *
 * These are never called by the tests. They exist so that a
 * hook field can be set to a non-NULL function pointer without
 * pulling in real behavior.
 */

static void dummy_log_hook(bowie_log_level_t level,
                           const char *line,
                           void *userdata)
{
    (void)level;
    (void)line;
    (void)userdata;
}

static void dummy_event_hook(const bowie_event_record_t *rec,
                             void *userdata)
{
    (void)rec;
    (void)userdata;
}

static bowie_error_t dummy_storage_read(const char *key,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len,
                                        void *userdata)
{
    (void)key;
    (void)buf;
    (void)cap;
    (void)out_len;
    (void)userdata;
    return BOWIE_OK;
}

static bowie_error_t dummy_storage_write(const char *key,
                                         const uint8_t *buf,
                                         size_t len,
                                         void *userdata)
{
    (void)key;
    (void)buf;
    (void)len;
    (void)userdata;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * CLEAR
 * ============================================================================
 */

START_TEST(test_clear_null)
{
    ck_assert_int_eq(bowie_hooks_clear(NULL), BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_clear_zeroed_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));

    ck_assert_int_eq(bowie_hooks_clear(&hooks), BOWIE_OK);

    ck_assert(hooks.log == NULL);
    ck_assert_ptr_null(hooks.log_userdata);
    ck_assert(hooks.event == NULL);
    ck_assert_ptr_null(hooks.event_userdata);
    ck_assert(hooks.storage_read == NULL);
    ck_assert(hooks.storage_write == NULL);
    ck_assert_ptr_null(hooks.storage_userdata);
}
END_TEST

START_TEST(test_clear_nonzero_ok)
{
    bowie_hooks_t hooks;
    int sentinel = 42;

    hooks.log              = dummy_log_hook;
    hooks.log_userdata     = &sentinel;
    hooks.event            = dummy_event_hook;
    hooks.event_userdata   = &sentinel;
    hooks.storage_read     = dummy_storage_read;
    hooks.storage_write    = dummy_storage_write;
    hooks.storage_userdata = &sentinel;

    ck_assert_int_eq(bowie_hooks_clear(&hooks), BOWIE_OK);

    ck_assert(hooks.log == NULL);
    ck_assert_ptr_null(hooks.log_userdata);
    ck_assert(hooks.event == NULL);
    ck_assert_ptr_null(hooks.event_userdata);
    ck_assert(hooks.storage_read == NULL);
    ck_assert(hooks.storage_write == NULL);
    ck_assert_ptr_null(hooks.storage_userdata);
}
END_TEST

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

START_TEST(test_validate_null)
{
    ck_assert_int_eq(bowie_hooks_validate(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_validate_empty_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_log_function_without_userdata_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log = dummy_log_hook;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_log_userdata_without_function_bad)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_validate_event_function_without_userdata_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.event = dummy_event_hook;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_event_userdata_without_function_bad)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.event_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_validate_storage_read_only_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_read = dummy_storage_read;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_storage_write_only_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_write = dummy_storage_write;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_storage_both_ok)
{
    bowie_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_read  = dummy_storage_read;
    hooks.storage_write = dummy_storage_write;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_storage_userdata_without_functions_bad)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_validate_storage_userdata_with_read_ok)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_read     = dummy_storage_read;
    hooks.storage_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_storage_userdata_with_write_ok)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.storage_write    = dummy_storage_write;
    hooks.storage_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_full_set_ok)
{
    bowie_hooks_t hooks;
    int sentinel = 42;
    memset(&hooks, 0, sizeof(hooks));
    hooks.log              = dummy_log_hook;
    hooks.log_userdata     = &sentinel;
    hooks.event            = dummy_event_hook;
    hooks.event_userdata   = &sentinel;
    hooks.storage_read     = dummy_storage_read;
    hooks.storage_write    = dummy_storage_write;
    hooks.storage_userdata = &sentinel;
    ck_assert_int_eq(bowie_hooks_validate(&hooks), BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * EVENT NAMES
 * ============================================================================
 */

START_TEST(test_event_name_none)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_NONE), "NONE");
}
END_TEST

START_TEST(test_event_name_engine_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_ENGINE_STARTING),
                     "ENGINE_STARTING");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_ENGINE_STARTED),
                     "ENGINE_STARTED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_ENGINE_STOPPING),
                     "ENGINE_STOPPING");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_ENGINE_STOPPED),
                     "ENGINE_STOPPED");
}
END_TEST

START_TEST(test_event_name_peer_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_PEER_FOUND),
                     "PEER_FOUND");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_PEER_CONNECTED),
                     "PEER_CONNECTED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_PEER_DISCONNECTED),
                     "PEER_DISCONNECTED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_PEER_FAILED),
                     "PEER_FAILED");
}
END_TEST

START_TEST(test_event_name_session_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_SESSION_OPENED),
                     "SESSION_OPENED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_SESSION_CLOSED),
                     "SESSION_CLOSED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_SESSION_DENIED),
                     "SESSION_DENIED");
}
END_TEST

START_TEST(test_event_name_grant_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GRANT_CREATED),
                     "GRANT_CREATED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GRANT_REVOKED),
                     "GRANT_REVOKED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GRANT_EXPIRED),
                     "GRANT_EXPIRED");
}
END_TEST

START_TEST(test_event_name_tunnel_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_TUNNEL_UP),
                     "TUNNEL_UP");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_TUNNEL_DOWN),
                     "TUNNEL_DOWN");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_TUNNEL_ERROR),
                     "TUNNEL_ERROR");
}
END_TEST

START_TEST(test_event_name_gateway_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GATEWAY_UP),
                     "GATEWAY_UP");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GATEWAY_DOWN),
                     "GATEWAY_DOWN");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_GATEWAY_ERROR),
                     "GATEWAY_ERROR");
}
END_TEST

START_TEST(test_event_name_nat_lifecycle)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_NAT_STARTED),
                     "NAT_STARTED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_NAT_SUCCEEDED),
                     "NAT_SUCCEEDED");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_NAT_FAILED),
                     "NAT_FAILED");
}
END_TEST

START_TEST(test_event_name_generic)
{
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_ERROR),
                     "ERROR");
    ck_assert_str_eq(bowie_event_name(BOWIE_EVENT_WARNING),
                     "WARNING");
}
END_TEST

START_TEST(test_event_name_unknown)
{
    ck_assert_str_eq(bowie_event_name((bowie_event_t)9999),
                     "UNKNOWN");
    ck_assert_str_eq(bowie_event_name((bowie_event_t)-1),
                     "UNKNOWN");
}
END_TEST

START_TEST(test_event_name_never_null)
{
    /*
     * Sweep every event code declared in the header. The list
     * is currently a PROPOSAL; a value that is not yet declared
     * still returns a valid pointer.
     */
    const bowie_event_t events[] = {
        BOWIE_EVENT_NONE,
        BOWIE_EVENT_ENGINE_STARTING,
        BOWIE_EVENT_ENGINE_STARTED,
        BOWIE_EVENT_ENGINE_STOPPING,
        BOWIE_EVENT_ENGINE_STOPPED,
        BOWIE_EVENT_PEER_FOUND,
        BOWIE_EVENT_PEER_CONNECTED,
        BOWIE_EVENT_PEER_DISCONNECTED,
        BOWIE_EVENT_PEER_FAILED,
        BOWIE_EVENT_SESSION_OPENED,
        BOWIE_EVENT_SESSION_CLOSED,
        BOWIE_EVENT_SESSION_DENIED,
        BOWIE_EVENT_GRANT_CREATED,
        BOWIE_EVENT_GRANT_REVOKED,
        BOWIE_EVENT_GRANT_EXPIRED,
        BOWIE_EVENT_TUNNEL_UP,
        BOWIE_EVENT_TUNNEL_DOWN,
        BOWIE_EVENT_TUNNEL_ERROR,
        BOWIE_EVENT_GATEWAY_UP,
        BOWIE_EVENT_GATEWAY_DOWN,
        BOWIE_EVENT_GATEWAY_ERROR,
        BOWIE_EVENT_NAT_STARTED,
        BOWIE_EVENT_NAT_SUCCEEDED,
        BOWIE_EVENT_NAT_FAILED,
        BOWIE_EVENT_ERROR,
        BOWIE_EVENT_WARNING,
        (bowie_event_t)9999,
    };
    size_t n = sizeof(events) / sizeof(events[0]);

    for (size_t i = 0u; i < n; i++) {
        ck_assert_ptr_nonnull(bowie_event_name(events[i]));
    }
}
END_TEST

START_TEST(test_event_name_stable_pointer)
{
    /*
     * Calling bowie_event_name() twice for the same event must
     * return the same pointer.
     */
    const char *a = bowie_event_name(BOWIE_EVENT_ENGINE_STARTED);
    const char *b = bowie_event_name(BOWIE_EVENT_ENGINE_STARTED);
    ck_assert_ptr_eq(a, b);
}
END_TEST

START_TEST(test_event_name_unique_for_known)
{
    /*
     * The declared event codes must have unique names. A
     * duplicate name would make a log line ambiguous.
     */
    const bowie_event_t events[] = {
        BOWIE_EVENT_NONE,
        BOWIE_EVENT_ENGINE_STARTING,
        BOWIE_EVENT_ENGINE_STARTED,
        BOWIE_EVENT_ENGINE_STOPPING,
        BOWIE_EVENT_ENGINE_STOPPED,
        BOWIE_EVENT_PEER_FOUND,
        BOWIE_EVENT_PEER_CONNECTED,
        BOWIE_EVENT_PEER_DISCONNECTED,
        BOWIE_EVENT_PEER_FAILED,
        BOWIE_EVENT_SESSION_OPENED,
        BOWIE_EVENT_SESSION_CLOSED,
        BOWIE_EVENT_SESSION_DENIED,
        BOWIE_EVENT_GRANT_CREATED,
        BOWIE_EVENT_GRANT_REVOKED,
        BOWIE_EVENT_GRANT_EXPIRED,
        BOWIE_EVENT_TUNNEL_UP,
        BOWIE_EVENT_TUNNEL_DOWN,
        BOWIE_EVENT_TUNNEL_ERROR,
        BOWIE_EVENT_GATEWAY_UP,
        BOWIE_EVENT_GATEWAY_DOWN,
        BOWIE_EVENT_GATEWAY_ERROR,
        BOWIE_EVENT_NAT_STARTED,
        BOWIE_EVENT_NAT_SUCCEEDED,
        BOWIE_EVENT_NAT_FAILED,
        BOWIE_EVENT_ERROR,
        BOWIE_EVENT_WARNING,
    };
    size_t n = sizeof(events) / sizeof(events[0]);

    for (size_t i = 0u; i < n; i++) {
        const char *ni = bowie_event_name(events[i]);
        for (size_t j = i + 1u; j < n; j++) {
            const char *nj = bowie_event_name(events[j]);
            ck_assert_str_ne(ni, nj);
        }
    }
}
END_TEST

START_TEST(test_event_name_uppercase)
{
    /*
     * Every known name uses uppercase letters and underscores
     * only. This is a convention, and it is checked so that a
     * later edit that introduces a lower-case character is
     * caught.
     */
    const bowie_event_t events[] = {
        BOWIE_EVENT_NONE,
        BOWIE_EVENT_ENGINE_STARTED,
        BOWIE_EVENT_PEER_CONNECTED,
        BOWIE_EVENT_SESSION_OPENED,
        BOWIE_EVENT_GRANT_CREATED,
        BOWIE_EVENT_TUNNEL_UP,
        BOWIE_EVENT_GATEWAY_UP,
        BOWIE_EVENT_NAT_SUCCEEDED,
        BOWIE_EVENT_ERROR,
        BOWIE_EVENT_WARNING,
    };
    size_t n = sizeof(events) / sizeof(events[0]);

    for (size_t i = 0u; i < n; i++) {
        const char *name = bowie_event_name(events[i]);
        for (size_t k = 0u; name[k] != '\0'; k++) {
            char c = name[k];
            int ok = (c >= 'A' && c <= 'Z') || c == '_';
            ck_assert(ok);
        }
    }
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *hooks_suite(void)
{
    Suite *s = suite_create("Hooks");

    TCase *tc_clear = tcase_create("Clear");
    tcase_add_test(tc_clear, test_clear_null);
    tcase_add_test(tc_clear, test_clear_zeroed_ok);
    tcase_add_test(tc_clear, test_clear_nonzero_ok);
    suite_add_tcase(s, tc_clear);

    TCase *tc_val = tcase_create("Validate");
    tcase_add_test(tc_val, test_validate_null);
    tcase_add_test(tc_val, test_validate_empty_ok);
    tcase_add_test(tc_val,
                   test_validate_log_function_without_userdata_ok);
    tcase_add_test(tc_val,
                   test_validate_log_userdata_without_function_bad);
    tcase_add_test(tc_val,
                   test_validate_event_function_without_userdata_ok);
    tcase_add_test(tc_val,
                   test_validate_event_userdata_without_function_bad);
    tcase_add_test(tc_val, test_validate_storage_read_only_ok);
    tcase_add_test(tc_val, test_validate_storage_write_only_ok);
    tcase_add_test(tc_val, test_validate_storage_both_ok);
    tcase_add_test(tc_val,
                   test_validate_storage_userdata_without_functions_bad);
    tcase_add_test(tc_val,
                   test_validate_storage_userdata_with_read_ok);
    tcase_add_test(tc_val,
                   test_validate_storage_userdata_with_write_ok);
    tcase_add_test(tc_val, test_validate_full_set_ok);
    suite_add_tcase(s, tc_val);

    TCase *tc_ev = tcase_create("EventNames");
    tcase_add_test(tc_ev, test_event_name_none);
    tcase_add_test(tc_ev, test_event_name_engine_lifecycle);
    tcase_add_test(tc_ev, test_event_name_peer_lifecycle);
    tcase_add_test(tc_ev, test_event_name_session_lifecycle);
    tcase_add_test(tc_ev, test_event_name_grant_lifecycle);
    tcase_add_test(tc_ev, test_event_name_tunnel_lifecycle);
    tcase_add_test(tc_ev, test_event_name_gateway_lifecycle);
    tcase_add_test(tc_ev, test_event_name_nat_lifecycle);
    tcase_add_test(tc_ev, test_event_name_generic);
    tcase_add_test(tc_ev, test_event_name_unknown);
    tcase_add_test(tc_ev, test_event_name_never_null);
    tcase_add_test(tc_ev, test_event_name_stable_pointer);
    tcase_add_test(tc_ev, test_event_name_unique_for_known);
    tcase_add_test(tc_ev, test_event_name_uppercase);
    suite_add_tcase(s, tc_ev);

    return s;
}

int main(void)
{
    Suite *s = hooks_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
