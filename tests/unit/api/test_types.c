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
 * BOWIE — TYPE HELPER TESTS
 * ============================================================================
 *
 * Unit tests for src/api/types.c.
 *
 * Every public helper declared in bowie/types.h is covered here.
 * The NULL contract of each pointer-taking function is tested,
 * because it is part of the declared contract and not an
 * accident of the implementation.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>         test framework
 *   <string.h>        memset, memcmp
 *   "bowie/types.h"   the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"

/*
 * ============================================================================
 * SPANS
 * ============================================================================
 */

START_TEST(test_span_is_empty_zero_len)
{
    bowie_span_t s = { NULL, 0u };
    ck_assert(bowie_span_is_empty(s));
}
END_TEST

START_TEST(test_span_is_empty_data_but_zero_len)
{
    const uint8_t data[4] = { 1, 2, 3, 4 };
    bowie_span_t s = { data, 0u };
    ck_assert(bowie_span_is_empty(s));
}
END_TEST

START_TEST(test_span_is_empty_nonzero_len)
{
    const uint8_t data[4] = { 1, 2, 3, 4 };
    bowie_span_t s = { data, 4u };
    ck_assert(!bowie_span_is_empty(s));
}
END_TEST

START_TEST(test_span_equal_empty_empty)
{
    bowie_span_t a = { NULL, 0u };
    bowie_span_t b = { NULL, 0u };
    ck_assert(bowie_span_equal(a, b));
}
END_TEST

START_TEST(test_span_equal_empty_different_data)
{
    const uint8_t x[4] = { 1, 2, 3, 4 };
    bowie_span_t a = { NULL, 0u };
    bowie_span_t b = { x, 0u };
    ck_assert(bowie_span_equal(a, b));
}
END_TEST

START_TEST(test_span_equal_same_bytes)
{
    const uint8_t x[4] = { 1, 2, 3, 4 };
    const uint8_t y[4] = { 1, 2, 3, 4 };
    bowie_span_t a = { x, 4u };
    bowie_span_t b = { y, 4u };
    ck_assert(bowie_span_equal(a, b));
}
END_TEST

START_TEST(test_span_equal_different_bytes)
{
    const uint8_t x[4] = { 1, 2, 3, 4 };
    const uint8_t y[4] = { 1, 2, 3, 5 };
    bowie_span_t a = { x, 4u };
    bowie_span_t b = { y, 4u };
    ck_assert(!bowie_span_equal(a, b));
}
END_TEST

START_TEST(test_span_equal_different_len)
{
    const uint8_t x[4] = { 1, 2, 3, 4 };
    bowie_span_t a = { x, 4u };
    bowie_span_t b = { x, 3u };
    ck_assert(!bowie_span_equal(a, b));
}
END_TEST

START_TEST(test_span_equal_malformed_with_len)
{
    bowie_span_t a = { NULL, 4u };
    bowie_span_t b = { NULL, 4u };
    ck_assert(!bowie_span_equal(a, b));
}
END_TEST

/*
 * ============================================================================
 * STRINGS
 * ============================================================================
 */

START_TEST(test_str_is_empty_zero_len)
{
    bowie_str_t s = { NULL, 0u };
    ck_assert(bowie_str_is_empty(s));
}
END_TEST

START_TEST(test_str_is_empty_nonzero_len)
{
    bowie_str_t s = { "hello", 5u };
    ck_assert(!bowie_str_is_empty(s));
}
END_TEST

START_TEST(test_str_equal_empty_empty)
{
    bowie_str_t a = { NULL, 0u };
    bowie_str_t b = { NULL, 0u };
    ck_assert(bowie_str_equal(a, b));
}
END_TEST

START_TEST(test_str_equal_same)
{
    bowie_str_t a = { "hello", 5u };
    bowie_str_t b = { "hello", 5u };
    ck_assert(bowie_str_equal(a, b));
}
END_TEST

START_TEST(test_str_equal_different)
{
    bowie_str_t a = { "hello", 5u };
    bowie_str_t b = { "world", 5u };
    ck_assert(!bowie_str_equal(a, b));
}
END_TEST

START_TEST(test_str_equal_prefix_only)
{
    bowie_str_t a = { "hello", 5u };
    bowie_str_t b = { "help",  4u };
    ck_assert(!bowie_str_equal(a, b));
}
END_TEST

START_TEST(test_str_equal_no_nul_needed)
{
    /*
     * The comparison is byte-wise over the declared length.
     * Neither slice is NUL-terminated.
     */
    const char x[3] = { 'a', 'b', 'c' };
    const char y[3] = { 'a', 'b', 'c' };
    bowie_str_t a = { x, 3u };
    bowie_str_t b = { y, 3u };
    ck_assert(bowie_str_equal(a, b));
}
END_TEST

/*
 * ============================================================================
 * BUFFERS
 * ============================================================================
 */

START_TEST(test_buf_clear_resets_len)
{
    bowie_buf_t buf;
    memset(&buf, 0xAA, sizeof(buf));
    buf.len = 100u;
    bowie_buf_clear(&buf);
    ck_assert_uint_eq(buf.len, 0u);
}
END_TEST

START_TEST(test_buf_clear_does_not_touch_capacity)
{
    bowie_buf_t buf;
    memset(&buf, 0xAA, sizeof(buf));
    buf.len = 100u;
    bowie_buf_clear(&buf);
    ck_assert_uint_eq(sizeof(buf.data), BOWIE_BUF_CAP);
}
END_TEST

START_TEST(test_buf_clear_null_is_noop)
{
    bowie_buf_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * ADDRESSES
 * ============================================================================
 */

START_TEST(test_addr_clear_zeroes_everything)
{
    bowie_addr_t a;
    a.family = BOWIE_AF_INET;
    memset(a.addr, 0xFF, sizeof(a.addr));
    a.port = 12345u;

    bowie_addr_clear(&a);

    ck_assert_int_eq(a.family, BOWIE_AF_UNSPEC);
    ck_assert_uint_eq(a.port, 0u);
    for (size_t i = 0u; i < sizeof(a.addr); i++) {
        ck_assert_uint_eq(a.addr[i], 0u);
    }
}
END_TEST

START_TEST(test_addr_clear_null_is_noop)
{
    bowie_addr_clear(NULL);
}
END_TEST

START_TEST(test_addr_is_set_unspec)
{
    bowie_addr_t a;
    bowie_addr_clear(&a);
    ck_assert(!bowie_addr_is_set(&a));
}
END_TEST

START_TEST(test_addr_is_set_ipv4)
{
    bowie_addr_t a;
    bowie_addr_clear(&a);
    a.family = BOWIE_AF_INET;
    ck_assert(bowie_addr_is_set(&a));
}
END_TEST

START_TEST(test_addr_is_set_ipv6)
{
    bowie_addr_t a;
    bowie_addr_clear(&a);
    a.family = BOWIE_AF_INET6;
    ck_assert(bowie_addr_is_set(&a));
}
END_TEST

START_TEST(test_addr_is_set_null)
{
    ck_assert(!bowie_addr_is_set(NULL));
}
END_TEST

START_TEST(test_addr_equal_null_null)
{
    ck_assert(bowie_addr_equal(NULL, NULL));
}
END_TEST

START_TEST(test_addr_equal_null_non_null)
{
    bowie_addr_t a;
    bowie_addr_clear(&a);
    ck_assert(!bowie_addr_equal(NULL, &a));
    ck_assert(!bowie_addr_equal(&a, NULL));
}
END_TEST

START_TEST(test_addr_equal_both_unspec)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    ck_assert(bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_ipv4_same)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET;
    b.family = BOWIE_AF_INET;
    a.addr[0] = 192; a.addr[1] = 168; a.addr[2] = 1; a.addr[3] = 1;
    b.addr[0] = 192; b.addr[1] = 168; b.addr[2] = 1; b.addr[3] = 1;
    a.port = 80u;
    b.port = 80u;
    ck_assert(bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_ipv4_different_port)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET;
    b.family = BOWIE_AF_INET;
    a.addr[0] = 192; a.addr[1] = 168; a.addr[2] = 1; a.addr[3] = 1;
    b.addr[0] = 192; b.addr[1] = 168; b.addr[2] = 1; b.addr[3] = 1;
    a.port = 80u;
    b.port = 81u;
    ck_assert(!bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_ipv4_ignores_unused_bytes)
{
    /*
     * Only the first four bytes matter for BOWIE_AF_INET.
     * The remaining twelve may differ and the addresses are
     * still equal.
     */
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET;
    b.family = BOWIE_AF_INET;
    a.addr[0] = 10; a.addr[1] = 0; a.addr[2] = 0; a.addr[3] = 1;
    b.addr[0] = 10; b.addr[1] = 0; b.addr[2] = 0; b.addr[3] = 1;
    a.addr[12] = 0xFF;
    b.addr[12] = 0x00;
    a.port = 443u;
    b.port = 443u;
    ck_assert(bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_different_family)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET;
    b.family = BOWIE_AF_INET6;
    ck_assert(!bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_ipv6_same)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET6;
    b.family = BOWIE_AF_INET6;
    for (size_t i = 0u; i < BOWIE_IPV6_LEN; i++) {
        a.addr[i] = (uint8_t)i;
        b.addr[i] = (uint8_t)i;
    }
    a.port = 8080u;
    b.port = 8080u;
    ck_assert(bowie_addr_equal(&a, &b));
}
END_TEST

START_TEST(test_addr_equal_ipv6_different)
{
    bowie_addr_t a;
    bowie_addr_t b;
    bowie_addr_clear(&a);
    bowie_addr_clear(&b);
    a.family = BOWIE_AF_INET6;
    b.family = BOWIE_AF_INET6;
    for (size_t i = 0u; i < BOWIE_IPV6_LEN; i++) {
        a.addr[i] = (uint8_t)i;
        b.addr[i] = (uint8_t)i;
    }
    b.addr[15] = 0xFFu;
    a.port = 8080u;
    b.port = 8080u;
    ck_assert(!bowie_addr_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * PEER ID
 * ============================================================================
 */

START_TEST(test_peer_id_clear_zeroes)
{
    bowie_peer_id_t id;
    memset(&id, 0xFF, sizeof(id));
    bowie_peer_id_clear(&id);
    ck_assert(bowie_peer_id_is_zero(&id));
}
END_TEST

START_TEST(test_peer_id_clear_null_is_noop)
{
    bowie_peer_id_clear(NULL);
}
END_TEST

START_TEST(test_peer_id_is_zero_true)
{
    bowie_peer_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_peer_id_is_zero(&id));
}
END_TEST

START_TEST(test_peer_id_is_zero_false)
{
    bowie_peer_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[5] = 1u;
    ck_assert(!bowie_peer_id_is_zero(&id));
}
END_TEST

START_TEST(test_peer_id_is_zero_null)
{
    ck_assert(bowie_peer_id_is_zero(NULL));
}
END_TEST

START_TEST(test_peer_id_equal_null_null)
{
    ck_assert(bowie_peer_id_equal(NULL, NULL));
}
END_TEST

START_TEST(test_peer_id_equal_null_zero)
{
    bowie_peer_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_peer_id_equal(NULL, &id));
    ck_assert(bowie_peer_id_equal(&id, NULL));
}
END_TEST

START_TEST(test_peer_id_equal_null_nonzero)
{
    bowie_peer_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 1u;
    ck_assert(!bowie_peer_id_equal(NULL, &id));
}
END_TEST

START_TEST(test_peer_id_equal_same)
{
    bowie_peer_id_t a;
    bowie_peer_id_t b;
    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) {
        a.bytes[i] = (uint8_t)i;
        b.bytes[i] = (uint8_t)i;
    }
    ck_assert(bowie_peer_id_equal(&a, &b));
}
END_TEST

START_TEST(test_peer_id_equal_different)
{
    bowie_peer_id_t a;
    bowie_peer_id_t b;
    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) {
        a.bytes[i] = (uint8_t)i;
        b.bytes[i] = (uint8_t)i;
    }
    b.bytes[BOWIE_PEER_ID_LEN - 1u] ^= 0xFFu;
    ck_assert(!bowie_peer_id_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * PUBLIC ID
 * ============================================================================
 */

START_TEST(test_public_id_clear_zeroes)
{
    bowie_public_id_t id;
    memset(&id, 0xFF, sizeof(id));
    bowie_public_id_clear(&id);
    ck_assert(bowie_public_id_is_zero(&id));
}
END_TEST

START_TEST(test_public_id_clear_null_is_noop)
{
    bowie_public_id_clear(NULL);
}
END_TEST

START_TEST(test_public_id_is_zero_true)
{
    bowie_public_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_public_id_is_zero(&id));
}
END_TEST

START_TEST(test_public_id_is_zero_false)
{
    bowie_public_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[31] = 1u;
    ck_assert(!bowie_public_id_is_zero(&id));
}
END_TEST

START_TEST(test_public_id_is_zero_null)
{
    ck_assert(bowie_public_id_is_zero(NULL));
}
END_TEST

START_TEST(test_public_id_equal_same)
{
    bowie_public_id_t a;
    bowie_public_id_t b;
    for (size_t i = 0u; i < BOWIE_PUBLIC_ID_LEN; i++) {
        a.bytes[i] = (uint8_t)(i * 3u);
        b.bytes[i] = (uint8_t)(i * 3u);
    }
    ck_assert(bowie_public_id_equal(&a, &b));
}
END_TEST

START_TEST(test_public_id_equal_different)
{
    bowie_public_id_t a;
    bowie_public_id_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    b.bytes[0] = 1u;
    ck_assert(!bowie_public_id_equal(&a, &b));
}
END_TEST

START_TEST(test_public_id_equal_null_null)
{
    ck_assert(bowie_public_id_equal(NULL, NULL));
}
END_TEST

START_TEST(test_public_id_equal_null_zero)
{
    bowie_public_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_public_id_equal(NULL, &id));
}
END_TEST

/*
 * ============================================================================
 * SESSION ID
 * ============================================================================
 */

START_TEST(test_session_id_clear_zeroes)
{
    bowie_session_id_t id;
    memset(&id, 0xFF, sizeof(id));
    bowie_session_id_clear(&id);
    ck_assert(bowie_session_id_is_zero(&id));
}
END_TEST

START_TEST(test_session_id_clear_null_is_noop)
{
    bowie_session_id_clear(NULL);
}
END_TEST

START_TEST(test_session_id_is_zero_true)
{
    bowie_session_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_session_id_is_zero(&id));
}
END_TEST

START_TEST(test_session_id_is_zero_false)
{
    bowie_session_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[0] = 1u;
    ck_assert(!bowie_session_id_is_zero(&id));
}
END_TEST

START_TEST(test_session_id_is_zero_null)
{
    ck_assert(bowie_session_id_is_zero(NULL));
}
END_TEST

START_TEST(test_session_id_equal_same)
{
    bowie_session_id_t a;
    bowie_session_id_t b;
    for (size_t i = 0u; i < BOWIE_SESSION_ID_LEN; i++) {
        a.bytes[i] = (uint8_t)(i + 1u);
        b.bytes[i] = (uint8_t)(i + 1u);
    }
    ck_assert(bowie_session_id_equal(&a, &b));
}
END_TEST

START_TEST(test_session_id_equal_different)
{
    bowie_session_id_t a;
    bowie_session_id_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    b.bytes[15] = 0xFFu;
    ck_assert(!bowie_session_id_equal(&a, &b));
}
END_TEST

START_TEST(test_session_id_equal_null_null)
{
    ck_assert(bowie_session_id_equal(NULL, NULL));
}
END_TEST

START_TEST(test_session_id_equal_null_zero)
{
    bowie_session_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_session_id_equal(NULL, &id));
}
END_TEST

/*
 * ============================================================================
 * GRANT ID
 * ============================================================================
 */

START_TEST(test_grant_id_clear_zeroes)
{
    bowie_grant_id_t id;
    memset(&id, 0xFF, sizeof(id));
    bowie_grant_id_clear(&id);
    ck_assert(bowie_grant_id_is_zero(&id));
}
END_TEST

START_TEST(test_grant_id_clear_null_is_noop)
{
    bowie_grant_id_clear(NULL);
}
END_TEST

START_TEST(test_grant_id_is_zero_true)
{
    bowie_grant_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_grant_id_is_zero(&id));
}
END_TEST

START_TEST(test_grant_id_is_zero_false)
{
    bowie_grant_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[7] = 1u;
    ck_assert(!bowie_grant_id_is_zero(&id));
}
END_TEST

START_TEST(test_grant_id_is_zero_null)
{
    ck_assert(bowie_grant_id_is_zero(NULL));
}
END_TEST

START_TEST(test_grant_id_equal_same)
{
    bowie_grant_id_t a;
    bowie_grant_id_t b;
    for (size_t i = 0u; i < BOWIE_GRANT_ID_LEN; i++) {
        a.bytes[i] = (uint8_t)(i * 7u);
        b.bytes[i] = (uint8_t)(i * 7u);
    }
    ck_assert(bowie_grant_id_equal(&a, &b));
}
END_TEST

START_TEST(test_grant_id_equal_different)
{
    bowie_grant_id_t a;
    bowie_grant_id_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    b.bytes[3] = 0x42u;
    ck_assert(!bowie_grant_id_equal(&a, &b));
}
END_TEST

START_TEST(test_grant_id_equal_null_null)
{
    ck_assert(bowie_grant_id_equal(NULL, NULL));
}
END_TEST

START_TEST(test_grant_id_equal_null_zero)
{
    bowie_grant_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_grant_id_equal(NULL, &id));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *types_suite(void)
{
    Suite *s = suite_create("Types");

    TCase *tc_span = tcase_create("Span");
    tcase_add_test(tc_span, test_span_is_empty_zero_len);
    tcase_add_test(tc_span, test_span_is_empty_data_but_zero_len);
    tcase_add_test(tc_span, test_span_is_empty_nonzero_len);
    tcase_add_test(tc_span, test_span_equal_empty_empty);
    tcase_add_test(tc_span, test_span_equal_empty_different_data);
    tcase_add_test(tc_span, test_span_equal_same_bytes);
    tcase_add_test(tc_span, test_span_equal_different_bytes);
    tcase_add_test(tc_span, test_span_equal_different_len);
    tcase_add_test(tc_span, test_span_equal_malformed_with_len);
    suite_add_tcase(s, tc_span);

    TCase *tc_str = tcase_create("Str");
    tcase_add_test(tc_str, test_str_is_empty_zero_len);
    tcase_add_test(tc_str, test_str_is_empty_nonzero_len);
    tcase_add_test(tc_str, test_str_equal_empty_empty);
    tcase_add_test(tc_str, test_str_equal_same);
    tcase_add_test(tc_str, test_str_equal_different);
    tcase_add_test(tc_str, test_str_equal_prefix_only);
    tcase_add_test(tc_str, test_str_equal_no_nul_needed);
    suite_add_tcase(s, tc_str);

    TCase *tc_buf = tcase_create("Buf");
    tcase_add_test(tc_buf, test_buf_clear_resets_len);
    tcase_add_test(tc_buf, test_buf_clear_does_not_touch_capacity);
    tcase_add_test(tc_buf, test_buf_clear_null_is_noop);
    suite_add_tcase(s, tc_buf);

    TCase *tc_addr = tcase_create("Addr");
    tcase_add_test(tc_addr, test_addr_clear_zeroes_everything);
    tcase_add_test(tc_addr, test_addr_clear_null_is_noop);
    tcase_add_test(tc_addr, test_addr_is_set_unspec);
    tcase_add_test(tc_addr, test_addr_is_set_ipv4);
    tcase_add_test(tc_addr, test_addr_is_set_ipv6);
    tcase_add_test(tc_addr, test_addr_is_set_null);
    tcase_add_test(tc_addr, test_addr_equal_null_null);
    tcase_add_test(tc_addr, test_addr_equal_null_non_null);
    tcase_add_test(tc_addr, test_addr_equal_both_unspec);
    tcase_add_test(tc_addr, test_addr_equal_ipv4_same);
    tcase_add_test(tc_addr, test_addr_equal_ipv4_different_port);
    tcase_add_test(tc_addr, test_addr_equal_ipv4_ignores_unused_bytes);
    tcase_add_test(tc_addr, test_addr_equal_different_family);
    tcase_add_test(tc_addr, test_addr_equal_ipv6_same);
    tcase_add_test(tc_addr, test_addr_equal_ipv6_different);
    suite_add_tcase(s, tc_addr);

    TCase *tc_peer = tcase_create("PeerId");
    tcase_add_test(tc_peer, test_peer_id_clear_zeroes);
    tcase_add_test(tc_peer, test_peer_id_clear_null_is_noop);
    tcase_add_test(tc_peer, test_peer_id_is_zero_true);
    tcase_add_test(tc_peer, test_peer_id_is_zero_false);
    tcase_add_test(tc_peer, test_peer_id_is_zero_null);
    tcase_add_test(tc_peer, test_peer_id_equal_null_null);
    tcase_add_test(tc_peer, test_peer_id_equal_null_zero);
    tcase_add_test(tc_peer, test_peer_id_equal_null_nonzero);
    tcase_add_test(tc_peer, test_peer_id_equal_same);
    tcase_add_test(tc_peer, test_peer_id_equal_different);
    suite_add_tcase(s, tc_peer);

    TCase *tc_pub = tcase_create("PublicId");
    tcase_add_test(tc_pub, test_public_id_clear_zeroes);
    tcase_add_test(tc_pub, test_public_id_clear_null_is_noop);
    tcase_add_test(tc_pub, test_public_id_is_zero_true);
    tcase_add_test(tc_pub, test_public_id_is_zero_false);
    tcase_add_test(tc_pub, test_public_id_is_zero_null);
    tcase_add_test(tc_pub, test_public_id_equal_same);
    tcase_add_test(tc_pub, test_public_id_equal_different);
    tcase_add_test(tc_pub, test_public_id_equal_null_null);
    tcase_add_test(tc_pub, test_public_id_equal_null_zero);
    suite_add_tcase(s, tc_pub);

    TCase *tc_sess = tcase_create("SessionId");
    tcase_add_test(tc_sess, test_session_id_clear_zeroes);
    tcase_add_test(tc_sess, test_session_id_clear_null_is_noop);
    tcase_add_test(tc_sess, test_session_id_is_zero_true);
    tcase_add_test(tc_sess, test_session_id_is_zero_false);
    tcase_add_test(tc_sess, test_session_id_is_zero_null);
    tcase_add_test(tc_sess, test_session_id_equal_same);
    tcase_add_test(tc_sess, test_session_id_equal_different);
    tcase_add_test(tc_sess, test_session_id_equal_null_null);
    tcase_add_test(tc_sess, test_session_id_equal_null_zero);
    suite_add_tcase(s, tc_sess);

    TCase *tc_grant = tcase_create("GrantId");
    tcase_add_test(tc_grant, test_grant_id_clear_zeroes);
    tcase_add_test(tc_grant, test_grant_id_clear_null_is_noop);
    tcase_add_test(tc_grant, test_grant_id_is_zero_true);
    tcase_add_test(tc_grant, test_grant_id_is_zero_false);
    tcase_add_test(tc_grant, test_grant_id_is_zero_null);
    tcase_add_test(tc_grant, test_grant_id_equal_same);
    tcase_add_test(tc_grant, test_grant_id_equal_different);
    tcase_add_test(tc_grant, test_grant_id_equal_null_null);
    tcase_add_test(tc_grant, test_grant_id_equal_null_zero);
    suite_add_tcase(s, tc_grant);

    return s;
}

int main(void)
{
    Suite *s = types_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
