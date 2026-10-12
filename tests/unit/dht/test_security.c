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
 * BOWIE — DHT SECURITY TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/security.c.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/security.h"             the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/security.h"

/*
 * ============================================================================
 * FIXTURE
 * ============================================================================
 */

#define TEST_LIMITS_CAP 4

static bowie_dht_rate_limit_t g_limits[TEST_LIMITS_CAP];

static void make_addr4(bowie_addr_t *a, uint8_t last_octet,
                       uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->family = BOWIE_AF_INET;
    a->addr[0] = 10u;
    a->addr[1] = 0u;
    a->addr[2] = 0u;
    a->addr[3] = last_octet;
    a->port = port;
}

static void make_addr6(bowie_addr_t *a)
{
    memset(a, 0, sizeof(*a));
    a->family = BOWIE_AF_INET6;
    a->port = 6881u;
}

static void make_id(bowie_dht_node_id_t *id, uint8_t first_byte)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0] = first_byte;
}

static bowie_dht_security_t make_state(bowie_dht_sec_level_t level,
                                       uint32_t max_req,
                                       uint32_t window_ms)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_security_init(&s, level, g_limits,
                                  TEST_LIMITS_CAP,
                                  max_req, window_ms);
    return s;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null)
{
    ck_assert_int_eq(
        bowie_dht_security_init(NULL, BOWIE_DHT_SEC_NONE,
                                NULL, 0u, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_invalid_level)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_security_init(&s, (bowie_dht_sec_level_t)99,
                                NULL, 0u, 0u, 0u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_init_strict_requires_table)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_security_init(&s, BOWIE_DHT_SEC_STRICT,
                                NULL, 0u, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_none_no_table)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_security_init(&s, BOWIE_DHT_SEC_NONE,
                                NULL, 0u, 0u, 0u),
        BOWIE_OK);
}
END_TEST

START_TEST(test_init_basic_no_table)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_security_init(&s, BOWIE_DHT_SEC_BASIC,
                                NULL, 0u, 0u, 0u),
        BOWIE_OK);
}
END_TEST

START_TEST(test_init_defaults)
{
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_security_init(&s, BOWIE_DHT_SEC_STRICT,
                                  g_limits, TEST_LIMITS_CAP,
                                  0u, 0u);
    ck_assert_uint_eq(s.max_requests_per_window,
                      BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS);
    ck_assert_uint_eq(s.window_ms,
                      BOWIE_DHT_SEC_DEFAULT_WINDOW_MS);
}
END_TEST

START_TEST(test_clear)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    bowie_dht_security_clear(&s);
    ck_assert_int_eq(s.level, BOWIE_DHT_SEC_NONE);
    ck_assert_ptr_null(s.limits);
    ck_assert_uint_eq(s.limits_used, 0u);
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_dht_security_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * ID BYTE HELPER
 * ============================================================================
 */

START_TEST(test_id_byte_null)
{
    ck_assert_uint_eq(bowie_dht_sec_id_byte_for_addr(NULL), 0u);
}
END_TEST

START_TEST(test_id_byte_ipv6)
{
    bowie_addr_t a;
    make_addr6(&a);
    ck_assert_uint_eq(bowie_dht_sec_id_byte_for_addr(&a), 0u);
}
END_TEST

START_TEST(test_id_byte_low_three)
{
    /* 0x0A = 10. Low three bits = 010 = 2. */
    bowie_addr_t a;
    make_addr4(&a, 0x0Au, 6881u);
    ck_assert_uint_eq(bowie_dht_sec_id_byte_for_addr(&a), 2u);
}
END_TEST

START_TEST(test_id_byte_all_bits)
{
    /* 0xFF = 255. Low three bits = 111 = 7. */
    bowie_addr_t a;
    make_addr4(&a, 0xFFu, 6881u);
    ck_assert_uint_eq(bowie_dht_sec_id_byte_for_addr(&a), 7u);
}
END_TEST

START_TEST(test_id_byte_zero)
{
    bowie_addr_t a;
    make_addr4(&a, 0x00u, 6881u);
    ck_assert_uint_eq(bowie_dht_sec_id_byte_for_addr(&a), 0u);
}
END_TEST

/*
 * ============================================================================
 * NODE ID VERIFICATION
 * ============================================================================
 */

START_TEST(test_node_id_ok_null)
{
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0x02u);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(!bowie_dht_sec_node_id_ok(NULL, &id, &a));
    ck_assert(!bowie_dht_sec_node_id_ok(NULL, &id, NULL));
    ck_assert(!bowie_dht_sec_node_id_ok(NULL, NULL, &a));
}
END_TEST

START_TEST(test_node_id_ok_level_none)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_NONE,
                                        0u, 0u);
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0x05u);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(bowie_dht_sec_node_id_ok(&s, &id, &a));
}
END_TEST

START_TEST(test_node_id_ok_basic_match)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_BASIC,
                                        0u, 0u);
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0x02u);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(bowie_dht_sec_node_id_ok(&s, &id, &a));
}
END_TEST

START_TEST(test_node_id_ok_basic_mismatch)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_BASIC,
                                        0u, 0u);
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0x05u);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(!bowie_dht_sec_node_id_ok(&s, &id, &a));
}
END_TEST

START_TEST(test_node_id_ok_high_bits_ignored)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_BASIC,
                                        0u, 0u);
    bowie_dht_node_id_t id1;
    bowie_dht_node_id_t id2;
    bowie_addr_t a;
    make_id(&id1, 0x02u);
    make_id(&id2, 0xFAu);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(bowie_dht_sec_node_id_ok(&s, &id1, &a));
    ck_assert(bowie_dht_sec_node_id_ok(&s, &id2, &a));
}
END_TEST

START_TEST(test_node_id_ok_ipv6_skip)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_BASIC,
                                        0u, 0u);
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0xFFu);
    make_addr6(&a);

    ck_assert(bowie_dht_sec_node_id_ok(&s, &id, &a));
}
END_TEST

START_TEST(test_node_id_ok_strict_same_as_basic)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    bowie_dht_node_id_t id;
    bowie_addr_t a;
    make_id(&id, 0x02u);
    make_addr4(&a, 0x0Au, 6881u);

    ck_assert(bowie_dht_sec_node_id_ok(&s, &id, &a));
}
END_TEST

/*
 * ============================================================================
 * RATE LIMITING
 * ============================================================================
 */

START_TEST(test_rate_null)
{
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(NULL, &a, 1000u),
        BOWIE_ERR_NULL_ARG);

    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, NULL, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_rate_no_table)
{
    /*
     * A state with no rate-limit table. The check_rate
     * function reports BOWIE_ERR_INVAL because there is no
     * table to use.
     */
    bowie_dht_security_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_security_init(&s, BOWIE_DHT_SEC_NONE,
                                  NULL, 0u, 0u, 0u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_rate_first_request)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_sec_rate_count(&s), 1u);
}
END_TEST

START_TEST(test_rate_increments)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    for (int i = 0; i < 10; i++) {
        ck_assert_int_eq(
            bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    }

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u),
        BOWIE_ERR_BUSY);
}
END_TEST

START_TEST(test_rate_different_addrs)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        2u, 1000u);
    bowie_addr_t a1;
    bowie_addr_t a2;
    make_addr4(&a1, 1u, 6881u);
    make_addr4(&a2, 2u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a1, 1000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a1, 1000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a1, 1000u), BOWIE_ERR_BUSY);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a2, 1000u), BOWIE_OK);
}
END_TEST

START_TEST(test_rate_window_expires)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        2u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_ERR_BUSY);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 3000u), BOWIE_OK);
}
END_TEST

START_TEST(test_rate_backward_clock)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        2u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 5000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a, 2000u), BOWIE_ERR_BUSY);
}
END_TEST

START_TEST(test_rate_table_full)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);

    for (uint8_t i = 1u; i <= TEST_LIMITS_CAP; i++) {
        bowie_addr_t a;
        make_addr4(&a, i, 6881u);
        ck_assert_int_eq(
            bowie_dht_sec_check_rate(&s, &a, 1000u), BOWIE_OK);
    }

    bowie_addr_t extra;
    make_addr4(&extra, 100u, 6881u);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &extra, 1000u),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_rate_existing_addr_when_full)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);

    for (uint8_t i = 1u; i <= TEST_LIMITS_CAP; i++) {
        bowie_addr_t a;
        make_addr4(&a, i, 6881u);
        (void)bowie_dht_sec_check_rate(&s, &a, 1000u);
    }

    bowie_addr_t a1;
    make_addr4(&a1, 1u, 6881u);
    ck_assert_int_eq(
        bowie_dht_sec_check_rate(&s, &a1, 1000u), BOWIE_OK);
}
END_TEST

START_TEST(test_rate_clear)
{
    bowie_dht_security_t s = make_state(BOWIE_DHT_SEC_STRICT,
                                        10u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    (void)bowie_dht_sec_check_rate(&s, &a, 1000u);
    ck_assert_uint_eq(bowie_dht_sec_rate_count(&s), 1u);

    bowie_dht_sec_rate_clear(&s);
    ck_assert_uint_eq(bowie_dht_sec_rate_count(&s), 0u);
}
END_TEST

START_TEST(test_rate_clear_null)
{
    bowie_dht_sec_rate_clear(NULL);
}
END_TEST

START_TEST(test_rate_count_null)
{
    ck_assert_uint_eq(bowie_dht_sec_rate_count(NULL), 0u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *security_suite(void)
{
    Suite *s = suite_create("DhtSecurity");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null);
    tcase_add_test(tc_life, test_init_invalid_level);
    tcase_add_test(tc_life, test_init_strict_requires_table);
    tcase_add_test(tc_life, test_init_none_no_table);
    tcase_add_test(tc_life, test_init_basic_no_table);
    tcase_add_test(tc_life, test_init_defaults);
    tcase_add_test(tc_life, test_clear);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_byte = tcase_create("IdByte");
    tcase_add_test(tc_byte, test_id_byte_null);
    tcase_add_test(tc_byte, test_id_byte_ipv6);
    tcase_add_test(tc_byte, test_id_byte_low_three);
    tcase_add_test(tc_byte, test_id_byte_all_bits);
    tcase_add_test(tc_byte, test_id_byte_zero);
    suite_add_tcase(s, tc_byte);

    TCase *tc_nid = tcase_create("NodeIdCheck");
    tcase_add_test(tc_nid, test_node_id_ok_null);
    tcase_add_test(tc_nid, test_node_id_ok_level_none);
    tcase_add_test(tc_nid, test_node_id_ok_basic_match);
    tcase_add_test(tc_nid, test_node_id_ok_basic_mismatch);
    tcase_add_test(tc_nid, test_node_id_ok_high_bits_ignored);
    tcase_add_test(tc_nid, test_node_id_ok_ipv6_skip);
    tcase_add_test(tc_nid, test_node_id_ok_strict_same_as_basic);
    suite_add_tcase(s, tc_nid);

    TCase *tc_rate = tcase_create("RateLimit");
    tcase_add_test(tc_rate, test_rate_null);
    tcase_add_test(tc_rate, test_rate_no_table);
    tcase_add_test(tc_rate, test_rate_first_request);
    tcase_add_test(tc_rate, test_rate_increments);
    tcase_add_test(tc_rate, test_rate_different_addrs);
    tcase_add_test(tc_rate, test_rate_window_expires);
    tcase_add_test(tc_rate, test_rate_backward_clock);
    tcase_add_test(tc_rate, test_rate_table_full);
    tcase_add_test(tc_rate, test_rate_existing_addr_when_full);
    tcase_add_test(tc_rate, test_rate_clear);
    tcase_add_test(tc_rate, test_rate_clear_null);
    tcase_add_test(tc_rate, test_rate_count_null);
    suite_add_tcase(s, tc_rate);

    return s;
}

int main(void)
{
    Suite *s = security_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
