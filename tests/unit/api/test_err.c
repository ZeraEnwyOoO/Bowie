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
 * BOWIE — ERROR TESTS
 * ============================================================================
 *
 * Unit tests for src/api/err.c.
 *
 * Every public function declared in bowie/err.h is covered here.
 *
 * The table tests assert properties of the table itself (codes
 * unique, names unique, first row is OK). These catch a mistake
 * that a per-function test would miss: a duplicate row that
 * makes the lookup return the wrong entry.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>        test framework
 *   <errno.h>        errno constants
 *   "bowie/err.h"    the unit under test
 * ============================================================================
 */

#include <check.h>
#include <errno.h>

#include "bowie/err.h"

/*
 * ============================================================================
 * STRINGS
 * ============================================================================
 */

START_TEST(test_strerror_ok)
{
    ck_assert_str_eq(bowie_err_strerror(BOWIE_OK), "success");
}
END_TEST

START_TEST(test_strerror_timeout)
{
    ck_assert_str_eq(bowie_err_strerror(BOWIE_ERR_TIMEOUT),
                     "operation timed out");
}
END_TEST

START_TEST(test_strerror_never_null_known)
{
    /* A sample of known errors. */
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_OK));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_INVAL));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_NOMEM));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_TIMEOUT));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_CRYPTO));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_DHT));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_TUNNEL));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_PERMISSION));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_GATEWAY));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_STATE));
    ck_assert_ptr_nonnull(bowie_err_strerror(BOWIE_ERR_NONE));
}
END_TEST

START_TEST(test_strerror_unknown_negative)
{
    ck_assert_str_eq(bowie_err_strerror(-9999), "unknown error");
}
END_TEST

START_TEST(test_strerror_positive_is_not_error)
{
    ck_assert_str_eq(bowie_err_strerror(1), "not an error");
}
END_TEST

START_TEST(test_name_ok)
{
    ck_assert_str_eq(bowie_err_name(BOWIE_OK), "OK");
}
END_TEST

START_TEST(test_name_timeout)
{
    ck_assert_str_eq(bowie_err_name(BOWIE_ERR_TIMEOUT), "TIMEOUT");
}
END_TEST

START_TEST(test_name_none)
{
    ck_assert_str_eq(bowie_err_name(BOWIE_ERR_NONE), "NONE");
}
END_TEST

START_TEST(test_name_unknown)
{
    ck_assert_str_eq(bowie_err_name(-9999), "UNKNOWN");
}
END_TEST

START_TEST(test_name_positive_is_ok)
{
    ck_assert_str_eq(bowie_err_name(1), "OK");
}
END_TEST

/*
 * ============================================================================
 * TABLE PROPERTIES
 * ============================================================================
 *
 * These tests do not call a specific function; they assert
 * invariants of the table that the functions rely on. A
 * duplicate code or a duplicate name is a bug that would not
 * show up in a single-row test.
 */

START_TEST(test_table_codes_unique)
{
    /*
     * Walk every pair of known codes. The list here is drawn
     * from the table; adding a code to the table without
     * adding it here is caught by the per-row tests.
     */
    const bowie_error_t codes[] = {
        BOWIE_OK,
        BOWIE_ERR_GENERAL, BOWIE_ERR_NOT_IMPLEMENTED,
        BOWIE_ERR_NOT_SUPPORTED, BOWIE_ERR_INTERNAL,
        BOWIE_ERR_UNKNOWN, BOWIE_ERR_CANCELLED,
        BOWIE_ERR_ALREADY_EXISTS, BOWIE_ERR_NOT_FOUND,
        BOWIE_ERR_INVAL, BOWIE_ERR_NULL_ARG, BOWIE_ERR_RANGE,
        BOWIE_ERR_TYPE, BOWIE_ERR_FORMAT, BOWIE_ERR_TOO_SMALL,
        BOWIE_ERR_TOO_LARGE, BOWIE_ERR_NOT_TERMINATED,
        BOWIE_ERR_NOMEM, BOWIE_ERR_OVERFLOW,
        BOWIE_ERR_NETWORK, BOWIE_ERR_TIMEOUT,
        BOWIE_ERR_CONN_REFUSED, BOWIE_ERR_CONN_RESET,
        BOWIE_ERR_HOST_UNREACH, BOWIE_ERR_NET_UNREACH,
        BOWIE_ERR_ADDR_IN_USE, BOWIE_ERR_ADDR_NOT_AVAIL,
        BOWIE_ERR_WOULD_BLOCK, BOWIE_ERR_BROKEN_PIPE,
        BOWIE_ERR_AGAIN, BOWIE_ERR_SOCKET, BOWIE_ERR_PROTOCOL,
        BOWIE_ERR_CRYPTO, BOWIE_ERR_KEY_INVALID,
        BOWIE_ERR_SIGN_INVALID, BOWIE_ERR_DECRYPT_FAILED,
        BOWIE_ERR_ENCRYPT_FAILED, BOWIE_ERR_HASH_MISMATCH,
        BOWIE_ERR_KEY_EXPIRED, BOWIE_ERR_KEY_MISSING,
        BOWIE_ERR_DHT, BOWIE_ERR_DHT_NO_NODE,
        BOWIE_ERR_DHT_BAD_MESSAGE, BOWIE_ERR_DHT_TIMEOUT,
        BOWIE_ERR_DHT_TOKEN, BOWIE_ERR_DHT_SECURITY,
        BOWIE_ERR_DHT_STORAGE, BOWIE_ERR_DHT_ROUTING,
        BOWIE_ERR_TUNNEL, BOWIE_ERR_TUN_OPEN,
        BOWIE_ERR_TUN_READ, BOWIE_ERR_TUN_WRITE,
        BOWIE_ERR_PACKET_MALFORMED, BOWIE_ERR_PACKET_TOO_BIG,
        BOWIE_ERR_MTU, BOWIE_ERR_FRAGMENT,
        BOWIE_ERR_PERMISSION, BOWIE_ERR_GRANT_INVALID,
        BOWIE_ERR_GRANT_EXPIRED, BOWIE_ERR_GRANT_REVOKED,
        BOWIE_ERR_SESSION_INVALID, BOWIE_ERR_SESSION_EXPIRED,
        BOWIE_ERR_OWNER_MISMATCH, BOWIE_ERR_SUBJECT_MISMATCH,
        BOWIE_ERR_GATEWAY, BOWIE_ERR_ROUTE,
        BOWIE_ERR_CONNTRACK, BOWIE_ERR_IP_FORWARD,
        BOWIE_ERR_NAT, BOWIE_ERR_FORWARD_DENIED,
        BOWIE_ERR_QUOTA, BOWIE_ERR_POLICY,
        BOWIE_ERR_STATE, BOWIE_ERR_STATE_INVALID,
        BOWIE_ERR_STATE_TRANSITION, BOWIE_ERR_NOT_INITIALIZED,
        BOWIE_ERR_ALREADY_STARTED, BOWIE_ERR_NOT_STARTED,
        BOWIE_ERR_ALREADY_STOPPED, BOWIE_ERR_BUSY,
        BOWIE_ERR_NONE,
    };

    size_t n = sizeof(codes) / sizeof(codes[0]);
    for (size_t i = 0u; i < n; i++) {
        for (size_t j = i + 1u; j < n; j++) {
            ck_assert_int_ne(codes[i], codes[j]);
        }
    }
}
END_TEST

START_TEST(test_table_names_unique)
{
    const bowie_error_t codes[] = {
        BOWIE_OK,
        BOWIE_ERR_GENERAL, BOWIE_ERR_NOT_IMPLEMENTED,
        BOWIE_ERR_NOT_SUPPORTED, BOWIE_ERR_INTERNAL,
        BOWIE_ERR_UNKNOWN, BOWIE_ERR_CANCELLED,
        BOWIE_ERR_ALREADY_EXISTS, BOWIE_ERR_NOT_FOUND,
        BOWIE_ERR_INVAL, BOWIE_ERR_NULL_ARG, BOWIE_ERR_RANGE,
        BOWIE_ERR_TYPE, BOWIE_ERR_FORMAT, BOWIE_ERR_TOO_SMALL,
        BOWIE_ERR_TOO_LARGE, BOWIE_ERR_NOT_TERMINATED,
        BOWIE_ERR_NOMEM, BOWIE_ERR_OVERFLOW,
        BOWIE_ERR_NETWORK, BOWIE_ERR_TIMEOUT,
        BOWIE_ERR_CONN_REFUSED, BOWIE_ERR_CONN_RESET,
        BOWIE_ERR_HOST_UNREACH, BOWIE_ERR_NET_UNREACH,
        BOWIE_ERR_ADDR_IN_USE, BOWIE_ERR_ADDR_NOT_AVAIL,
        BOWIE_ERR_WOULD_BLOCK, BOWIE_ERR_BROKEN_PIPE,
        BOWIE_ERR_AGAIN, BOWIE_ERR_SOCKET, BOWIE_ERR_PROTOCOL,
        BOWIE_ERR_CRYPTO, BOWIE_ERR_KEY_INVALID,
        BOWIE_ERR_SIGN_INVALID, BOWIE_ERR_DECRYPT_FAILED,
        BOWIE_ERR_ENCRYPT_FAILED, BOWIE_ERR_HASH_MISMATCH,
        BOWIE_ERR_KEY_EXPIRED, BOWIE_ERR_KEY_MISSING,
        BOWIE_ERR_DHT, BOWIE_ERR_DHT_NO_NODE,
        BOWIE_ERR_DHT_BAD_MESSAGE, BOWIE_ERR_DHT_TIMEOUT,
        BOWIE_ERR_DHT_TOKEN, BOWIE_ERR_DHT_SECURITY,
        BOWIE_ERR_DHT_STORAGE, BOWIE_ERR_DHT_ROUTING,
        BOWIE_ERR_TUNNEL, BOWIE_ERR_TUN_OPEN,
        BOWIE_ERR_TUN_READ, BOWIE_ERR_TUN_WRITE,
        BOWIE_ERR_PACKET_MALFORMED, BOWIE_ERR_PACKET_TOO_BIG,
        BOWIE_ERR_MTU, BOWIE_ERR_FRAGMENT,
        BOWIE_ERR_PERMISSION, BOWIE_ERR_GRANT_INVALID,
        BOWIE_ERR_GRANT_EXPIRED, BOWIE_ERR_GRANT_REVOKED,
        BOWIE_ERR_SESSION_INVALID, BOWIE_ERR_SESSION_EXPIRED,
        BOWIE_ERR_OWNER_MISMATCH, BOWIE_ERR_SUBJECT_MISMATCH,
        BOWIE_ERR_GATEWAY, BOWIE_ERR_ROUTE,
        BOWIE_ERR_CONNTRACK, BOWIE_ERR_IP_FORWARD,
        BOWIE_ERR_NAT, BOWIE_ERR_FORWARD_DENIED,
        BOWIE_ERR_QUOTA, BOWIE_ERR_POLICY,
        BOWIE_ERR_STATE, BOWIE_ERR_STATE_INVALID,
        BOWIE_ERR_STATE_TRANSITION, BOWIE_ERR_NOT_INITIALIZED,
        BOWIE_ERR_ALREADY_STARTED, BOWIE_ERR_NOT_STARTED,
        BOWIE_ERR_ALREADY_STOPPED, BOWIE_ERR_BUSY,
        BOWIE_ERR_NONE,
    };

    size_t n = sizeof(codes) / sizeof(codes[0]);
    for (size_t i = 0u; i < n; i++) {
        const char *ni = bowie_err_name(codes[i]);
        for (size_t j = i + 1u; j < n; j++) {
            const char *nj = bowie_err_name(codes[j]);
            ck_assert_str_ne(ni, nj);
        }
    }
}
END_TEST

/*
 * ============================================================================
 * CLASSIFICATION
 * ============================================================================
 */

START_TEST(test_class_ok)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_OK),
                     BOWIE_ERR_CLASS_OK);
}
END_TEST

START_TEST(test_class_general)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_GENERAL),
                     BOWIE_ERR_CLASS_GENERAL);
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_NOT_FOUND),
                     BOWIE_ERR_CLASS_GENERAL);
}
END_TEST

START_TEST(test_class_argument)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_INVAL),
                     BOWIE_ERR_CLASS_ARGUMENT);
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_NULL_ARG),
                     BOWIE_ERR_CLASS_ARGUMENT);
}
END_TEST

START_TEST(test_class_memory)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_NOMEM),
                     BOWIE_ERR_CLASS_MEMORY);
}
END_TEST

START_TEST(test_class_network)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_NETWORK),
                     BOWIE_ERR_CLASS_NETWORK);
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_TIMEOUT),
                     BOWIE_ERR_CLASS_NETWORK);
}
END_TEST

START_TEST(test_class_crypto)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_CRYPTO),
                     BOWIE_ERR_CLASS_CRYPTO);
}
END_TEST

START_TEST(test_class_dht)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_DHT),
                     BOWIE_ERR_CLASS_DHT);
}
END_TEST

START_TEST(test_class_tunnel)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_TUNNEL),
                     BOWIE_ERR_CLASS_TUNNEL);
}
END_TEST

START_TEST(test_class_permission)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_PERMISSION),
                     BOWIE_ERR_CLASS_PERMISSION);
}
END_TEST

START_TEST(test_class_gateway)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_GATEWAY),
                     BOWIE_ERR_CLASS_GATEWAY);
}
END_TEST

START_TEST(test_class_state)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_STATE),
                     BOWIE_ERR_CLASS_STATE);
}
END_TEST

START_TEST(test_class_sentinel)
{
    ck_assert_int_eq(bowie_err_class(BOWIE_ERR_NONE),
                     BOWIE_ERR_CLASS_SENTINEL);
}
END_TEST

START_TEST(test_class_unknown)
{
    ck_assert_int_eq(bowie_err_class(-9999),
                     BOWIE_ERR_CLASS_UNKNOWN);
}
END_TEST

START_TEST(test_class_name_all)
{
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_OK), "OK");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_GENERAL), "GENERAL");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_ARGUMENT), "ARGUMENT");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_MEMORY), "MEMORY");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_NETWORK), "NETWORK");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_CRYPTO), "CRYPTO");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_DHT), "DHT");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_TUNNEL), "TUNNEL");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_PERMISSION), "PERMISSION");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_GATEWAY), "GATEWAY");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_STATE), "STATE");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_SENTINEL), "SENTINEL");
    ck_assert_str_eq(bowie_err_class_name(BOWIE_ERR_CLASS_UNKNOWN), "UNKNOWN");
}
END_TEST

/*
 * ============================================================================
 * PREDICATES
 * ============================================================================
 */

START_TEST(test_is_argument_true)
{
    ck_assert(bowie_err_is_argument(BOWIE_ERR_INVAL));
    ck_assert(bowie_err_is_argument(BOWIE_ERR_NULL_ARG));
    ck_assert(bowie_err_is_argument(BOWIE_ERR_RANGE));
}
END_TEST

START_TEST(test_is_argument_false)
{
    ck_assert(!bowie_err_is_argument(BOWIE_OK));
    ck_assert(!bowie_err_is_argument(BOWIE_ERR_NOMEM));
    ck_assert(!bowie_err_is_argument(BOWIE_ERR_TIMEOUT));
}
END_TEST

START_TEST(test_is_retryable_true)
{
    ck_assert(bowie_err_is_retryable(BOWIE_ERR_TIMEOUT));
    ck_assert(bowie_err_is_retryable(BOWIE_ERR_AGAIN));
    ck_assert(bowie_err_is_retryable(BOWIE_ERR_WOULD_BLOCK));
    ck_assert(bowie_err_is_retryable(BOWIE_ERR_BUSY));
}
END_TEST

START_TEST(test_is_retryable_false)
{
    ck_assert(!bowie_err_is_retryable(BOWIE_OK));
    ck_assert(!bowie_err_is_retryable(BOWIE_ERR_INVAL));
    ck_assert(!bowie_err_is_retryable(BOWIE_ERR_NOMEM));
}
END_TEST

START_TEST(test_is_fatal_true)
{
    ck_assert(bowie_err_is_fatal(BOWIE_ERR_NOMEM));
    ck_assert(bowie_err_is_fatal(BOWIE_ERR_INTERNAL));
    ck_assert(bowie_err_is_fatal(BOWIE_ERR_OVERFLOW));
    ck_assert(bowie_err_is_fatal(BOWIE_ERR_STATE));
    ck_assert(bowie_err_is_fatal(BOWIE_ERR_NOT_INITIALIZED));
}
END_TEST

START_TEST(test_is_fatal_false)
{
    ck_assert(!bowie_err_is_fatal(BOWIE_OK));
    ck_assert(!bowie_err_is_fatal(BOWIE_ERR_TIMEOUT));
    ck_assert(!bowie_err_is_fatal(BOWIE_ERR_INVAL));
}
END_TEST

START_TEST(test_is_benign_true)
{
    ck_assert(bowie_err_is_benign(BOWIE_OK));
    ck_assert(bowie_err_is_benign(BOWIE_ERR_NOT_FOUND));
    ck_assert(bowie_err_is_benign(BOWIE_ERR_ALREADY_EXISTS));
}
END_TEST

START_TEST(test_is_benign_false)
{
    ck_assert(!bowie_err_is_benign(BOWIE_ERR_INVAL));
    ck_assert(!bowie_err_is_benign(BOWIE_ERR_NOMEM));
    ck_assert(!bowie_err_is_benign(BOWIE_ERR_TIMEOUT));
}
END_TEST

START_TEST(test_is_ok)
{
    ck_assert(bowie_err_is_ok(BOWIE_OK));
    ck_assert(!bowie_err_is_ok(BOWIE_ERR_INVAL));
    ck_assert(!bowie_err_is_ok(BOWIE_ERR_NONE));
}
END_TEST

START_TEST(test_is_error)
{
    ck_assert(!bowie_err_is_error(BOWIE_OK));
    ck_assert(!bowie_err_is_error(BOWIE_ERR_NONE));
    ck_assert(bowie_err_is_error(BOWIE_ERR_INVAL));
    ck_assert(bowie_err_is_error(BOWIE_ERR_NOMEM));
    ck_assert(!bowie_err_is_error(1));
}
END_TEST

/*
 * ============================================================================
 * LAST ERROR
 * ============================================================================
 */

START_TEST(test_last_starts_clear)
{
    bowie_err_clear_last();
    ck_assert_int_eq(bowie_err_last(), BOWIE_ERR_NONE);
}
END_TEST

START_TEST(test_last_set_get)
{
    bowie_err_clear_last();
    bowie_err_set_last(BOWIE_ERR_TIMEOUT);
    ck_assert_int_eq(bowie_err_last(), BOWIE_ERR_TIMEOUT);
}
END_TEST

START_TEST(test_last_overwrites)
{
    bowie_err_clear_last();
    bowie_err_set_last(BOWIE_ERR_TIMEOUT);
    bowie_err_set_last(BOWIE_ERR_INVAL);
    ck_assert_int_eq(bowie_err_last(), BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_last_ok_clears)
{
    bowie_err_set_last(BOWIE_ERR_TIMEOUT);
    bowie_err_set_last(BOWIE_OK);
    ck_assert_int_eq(bowie_err_last(), BOWIE_ERR_NONE);
}
END_TEST

/*
 * ============================================================================
 * CONTEXT
 * ============================================================================
 */

START_TEST(test_context_starts_empty)
{
    bowie_err_context_clear();
    ck_assert_uint_eq(bowie_err_context_count(), 0u);
}
END_TEST

START_TEST(test_context_push_pop)
{
    bowie_err_context_clear();
    bowie_err_context_push("alpha");
    ck_assert_uint_eq(bowie_err_context_count(), 1u);
    ck_assert_str_eq(bowie_err_context_at(0u), "alpha");

    bowie_err_context_push("beta");
    ck_assert_uint_eq(bowie_err_context_count(), 2u);
    ck_assert_str_eq(bowie_err_context_at(0u), "alpha");
    ck_assert_str_eq(bowie_err_context_at(1u), "beta");

    bowie_err_context_pop();
    ck_assert_uint_eq(bowie_err_context_count(), 1u);
    ck_assert_str_eq(bowie_err_context_at(0u), "alpha");
}
END_TEST

START_TEST(test_context_push_null_is_noop)
{
    bowie_err_context_clear();
    bowie_err_context_push(NULL);
    ck_assert_uint_eq(bowie_err_context_count(), 0u);
}
END_TEST

START_TEST(test_context_push_truncates_label)
{
    bowie_err_context_clear();

    /*
     * A label longer than the slot is truncated and terminated.
     * The slot holds BOWIE_ERR_CONTEXT_LABEL bytes including
     * the terminator.
     */
    char big[BOWIE_ERR_CONTEXT_LABEL + 32];
    for (size_t i = 0u; i < sizeof(big) - 1u; i++) {
        big[i] = 'x';
    }
    big[sizeof(big) - 1u] = '\0';

    bowie_err_context_push(big);

    const char *got = bowie_err_context_at(0u);
    ck_assert_uint_eq(strlen(got), BOWIE_ERR_CONTEXT_LABEL - 1u);
}
END_TEST

START_TEST(test_context_push_bounded)
{
    /*
     * Pushing more labels than the ring can hold keeps the most
     * recent ones.
     */
    bowie_err_context_clear();
    for (unsigned int i = 0u; i < BOWIE_ERR_CONTEXT_MAX + 5u; i++) {
        char label[16];
        (void)snprintf(label, sizeof(label), "L%u", i);
        bowie_err_context_push(label);
    }
    ck_assert_uint_eq(bowie_err_context_count(),
                      BOWIE_ERR_CONTEXT_MAX);
}
END_TEST

START_TEST(test_context_at_out_of_range)
{
    bowie_err_context_clear();
    ck_assert_ptr_null(bowie_err_context_at(0u));
    bowie_err_context_push("only");
    ck_assert_ptr_null(bowie_err_context_at(1u));
}
END_TEST

START_TEST(test_context_pop_empty_is_noop)
{
    bowie_err_context_clear();
    bowie_err_context_pop();
    ck_assert_uint_eq(bowie_err_context_count(), 0u);
}
END_TEST

START_TEST(test_context_format_empty)
{
    bowie_err_context_clear();
    char buf[64];
    int n = bowie_err_context_format(buf, sizeof(buf));
    ck_assert_int_eq(n, 0);
    ck_assert_str_eq(buf, "");
}
END_TEST

START_TEST(test_context_format_single)
{
    bowie_err_context_clear();
    bowie_err_context_push("one");
    char buf[64];
    (void)bowie_err_context_format(buf, sizeof(buf));
    ck_assert_str_eq(buf, "one");
}
END_TEST

START_TEST(test_context_format_chain)
{
    bowie_err_context_clear();
    bowie_err_context_push("one");
    bowie_err_context_push("two");
    bowie_err_context_push("three");
    char buf[64];
    (void)bowie_err_context_format(buf, sizeof(buf));
    ck_assert_str_eq(buf, "one -> two -> three");
}
END_TEST

START_TEST(test_context_format_null_buf)
{
    bowie_err_context_clear();
    ck_assert_int_eq(bowie_err_context_format(NULL, 64), 0);
}
END_TEST

START_TEST(test_context_format_zero_cap)
{
    bowie_err_context_clear();
    char buf[1] = { 'X' };
    ck_assert_int_eq(bowie_err_context_format(buf, 0u), 0);
}
END_TEST

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 */

START_TEST(test_from_errno_zero_is_ok)
{
    ck_assert_int_eq(bowie_err_from_errno(0), BOWIE_OK);
}
END_TEST

START_TEST(test_from_errno_common)
{
    ck_assert_int_eq(bowie_err_from_errno(EINVAL), BOWIE_ERR_INVAL);
    ck_assert_int_eq(bowie_err_from_errno(ENOMEM), BOWIE_ERR_NOMEM);
    ck_assert_int_eq(bowie_err_from_errno(EAGAIN), BOWIE_ERR_AGAIN);
    ck_assert_int_eq(bowie_err_from_errno(ETIMEDOUT),
                     BOWIE_ERR_TIMEOUT);
    ck_assert_int_eq(bowie_err_from_errno(ECONNREFUSED),
                     BOWIE_ERR_CONN_REFUSED);
}
END_TEST

START_TEST(test_from_errno_unknown_falls_back)
{
    /* An errno value not in the table maps to NETWORK. */
    ck_assert_int_eq(bowie_err_from_errno(99999),
                     BOWIE_ERR_NETWORK);
}
END_TEST

START_TEST(test_to_errno_ok)
{
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_OK), 0);
}
END_TEST

START_TEST(test_to_errno_common)
{
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_ERR_INVAL), EINVAL);
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_ERR_NOMEM), ENOMEM);
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_ERR_TIMEOUT),
                     ETIMEDOUT);
}
END_TEST

START_TEST(test_to_errno_unknown_falls_back)
{
    /* A bowie error not in the table maps to EIO. */
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_ERR_DHT_TOKEN), EIO);
    ck_assert_int_eq(bowie_err_to_errno(BOWIE_ERR_GRANT_EXPIRED), EIO);
}
END_TEST

START_TEST(test_errno_roundtrip)
{
    /* For mapped pairs, from(to(x)) == x. */
    const bowie_error_t pairs[] = {
        BOWIE_OK, BOWIE_ERR_INVAL, BOWIE_ERR_NOMEM,
        BOWIE_ERR_AGAIN, BOWIE_ERR_TIMEOUT,
        BOWIE_ERR_CONN_REFUSED, BOWIE_ERR_CONN_RESET,
        BOWIE_ERR_HOST_UNREACH, BOWIE_ERR_NET_UNREACH,
        BOWIE_ERR_ADDR_IN_USE, BOWIE_ERR_ADDR_NOT_AVAIL,
        BOWIE_ERR_BROKEN_PIPE,
    };
    size_t n = sizeof(pairs) / sizeof(pairs[0]);
    for (size_t i = 0u; i < n; i++) {
        int e = bowie_err_to_errno(pairs[i]);
        ck_assert_int_eq(bowie_err_from_errno(e), pairs[i]);
    }
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *err_suite(void)
{
    Suite *s = suite_create("Err");

    TCase *tc_str = tcase_create("Strings");
    tcase_add_test(tc_str, test_strerror_ok);
    tcase_add_test(tc_str, test_strerror_timeout);
    tcase_add_test(tc_str, test_strerror_never_null_known);
    tcase_add_test(tc_str, test_strerror_unknown_negative);
    tcase_add_test(tc_str, test_strerror_positive_is_not_error);
    tcase_add_test(tc_str, test_name_ok);
    tcase_add_test(tc_str, test_name_timeout);
    tcase_add_test(tc_str, test_name_none);
    tcase_add_test(tc_str, test_name_unknown);
    tcase_add_test(tc_str, test_name_positive_is_ok);
    suite_add_tcase(s, tc_str);

    TCase *tc_table = tcase_create("Table");
    tcase_add_test(tc_table, test_table_codes_unique);
    tcase_add_test(tc_table, test_table_names_unique);
    suite_add_tcase(s, tc_table);

    TCase *tc_class = tcase_create("Class");
    tcase_add_test(tc_class, test_class_ok);
    tcase_add_test(tc_class, test_class_general);
    tcase_add_test(tc_class, test_class_argument);
    tcase_add_test(tc_class, test_class_memory);
    tcase_add_test(tc_class, test_class_network);
    tcase_add_test(tc_class, test_class_crypto);
    tcase_add_test(tc_class, test_class_dht);
    tcase_add_test(tc_class, test_class_tunnel);
    tcase_add_test(tc_class, test_class_permission);
    tcase_add_test(tc_class, test_class_gateway);
    tcase_add_test(tc_class, test_class_state);
    tcase_add_test(tc_class, test_class_sentinel);
    tcase_add_test(tc_class, test_class_unknown);
    tcase_add_test(tc_class, test_class_name_all);
    suite_add_tcase(s, tc_class);

    TCase *tc_pred = tcase_create("Predicates");
    tcase_add_test(tc_pred, test_is_argument_true);
    tcase_add_test(tc_pred, test_is_argument_false);
    tcase_add_test(tc_pred, test_is_retryable_true);
    tcase_add_test(tc_pred, test_is_retryable_false);
    tcase_add_test(tc_pred, test_is_fatal_true);
    tcase_add_test(tc_pred, test_is_fatal_false);
    tcase_add_test(tc_pred, test_is_benign_true);
    tcase_add_test(tc_pred, test_is_benign_false);
    tcase_add_test(tc_pred, test_is_ok);
    tcase_add_test(tc_pred, test_is_error);
    suite_add_tcase(s, tc_pred);

    TCase *tc_last = tcase_create("Last");
    tcase_add_test(tc_last, test_last_starts_clear);
    tcase_add_test(tc_last, test_last_set_get);
    tcase_add_test(tc_last, test_last_overwrites);
    tcase_add_test(tc_last, test_last_ok_clears);
    suite_add_tcase(s, tc_last);

    TCase *tc_ctx = tcase_create("Context");
    tcase_add_test(tc_ctx, test_context_starts_empty);
    tcase_add_test(tc_ctx, test_context_push_pop);
    tcase_add_test(tc_ctx, test_context_push_null_is_noop);
    tcase_add_test(tc_ctx, test_context_push_truncates_label);
    tcase_add_test(tc_ctx, test_context_push_bounded);
    tcase_add_test(tc_ctx, test_context_at_out_of_range);
    tcase_add_test(tc_ctx, test_context_pop_empty_is_noop);
    tcase_add_test(tc_ctx, test_context_format_empty);
    tcase_add_test(tc_ctx, test_context_format_single);
    tcase_add_test(tc_ctx, test_context_format_chain);
    tcase_add_test(tc_ctx, test_context_format_null_buf);
    tcase_add_test(tc_ctx, test_context_format_zero_cap);
    suite_add_tcase(s, tc_ctx);

    TCase *tc_errno = tcase_create("Errno");
    tcase_add_test(tc_errno, test_from_errno_zero_is_ok);
    tcase_add_test(tc_errno, test_from_errno_common);
    tcase_add_test(tc_errno, test_from_errno_unknown_falls_back);
    tcase_add_test(tc_errno, test_to_errno_ok);
    tcase_add_test(tc_errno, test_to_errno_common);
    tcase_add_test(tc_errno, test_to_errno_unknown_falls_back);
    tcase_add_test(tc_errno, test_errno_roundtrip);
    suite_add_tcase(s, tc_errno);

    return s;
}

int main(void)
{
    Suite *s = err_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
