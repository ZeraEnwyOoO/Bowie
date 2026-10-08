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
 * BOWIE — SOCKET TESTS
 * ============================================================================
 *
 * Unit tests for src/core/sock.c.
 *
 * Every public function declared in core/internal/sock.h is
 * covered here.
 *
 * The tests do not exercise the network. There is no send to a
 * remote host, no receive from a remote host, and no
 * connection setup. The socket primitives are tested against
 * the local loopback address, which the operating system
 * provides without any network path. A test that depended on a
 * remote host would fail in a sandbox and would be testing the
 * sandbox, not the module.
 *
 * The test suite creates real sockets. Each test that opens a
 * socket closes it before returning. A leak here would be
 * visible in the process's file descriptor table, but the
 * tests are short-lived and the process exits at the end of
 * the suite.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset
 *   "bowie/types.h"                 bowie_addr_t
 *   "bowie/err.h"                   error codes
 *   "core/internal/sock.h"          the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/sock.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_loopback4(bowie_addr_t *addr, uint16_t port)
{
    memset(addr, 0, sizeof(*addr));
    addr->family = BOWIE_AF_INET;
    addr->addr[0] = 127u;
    addr->addr[1] = 0u;
    addr->addr[2] = 0u;
    addr->addr[3] = 1u;
    addr->port = port;
}

/*
 * ============================================================================
 * OPEN
 * ============================================================================
 */

START_TEST(test_open_null_out)
{
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_open_unspec_family)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_UNSPEC,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_ERR_INVAL);
    ck_assert_int_eq(fd, BOWIE_SOCK_INVALID);
}
END_TEST

START_TEST(test_open_bad_type)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     999, &fd),
                     BOWIE_ERR_INVAL);
    ck_assert_int_eq(fd, BOWIE_SOCK_INVALID);
}
END_TEST

START_TEST(test_open_udp4)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_ne(fd, BOWIE_SOCK_INVALID);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_open_udp6)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET6,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_ne(fd, BOWIE_SOCK_INVALID);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_open_tcp4)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_STREAM, &fd),
                     BOWIE_OK);
    ck_assert_int_ne(fd, BOWIE_SOCK_INVALID);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_open_out_zeroed_on_inval)
{
    int fd = 42;
    (void)bowie_sock_open(BOWIE_AF_UNSPEC,
                          BOWIE_SOCK_DGRAM, &fd);
    ck_assert_int_eq(fd, BOWIE_SOCK_INVALID);
}
END_TEST

/*
 * ============================================================================
 * CLOSE
 * ============================================================================
 */

START_TEST(test_close_invalid_is_noop)
{
    bowie_sock_close(BOWIE_SOCK_INVALID);
    /* No crash. */
}
END_TEST

/*
 * ============================================================================
 * SET REUSEADDR
 * ============================================================================
 */

START_TEST(test_set_reuseaddr_invalid)
{
    ck_assert_int_eq(
        bowie_sock_set_reuseaddr(BOWIE_SOCK_INVALID),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_set_reuseaddr_ok)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_sock_set_reuseaddr(fd), BOWIE_OK);
    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * SET NONBLOCKING
 * ============================================================================
 */

START_TEST(test_set_nonblocking_invalid)
{
    ck_assert_int_eq(
        bowie_sock_set_nonblocking(BOWIE_SOCK_INVALID),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_set_nonblocking_ok)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_sock_set_nonblocking(fd), BOWIE_OK);
    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * BIND
 * ============================================================================
 */

START_TEST(test_bind_invalid_handle)
{
    bowie_addr_t addr;
    make_loopback4(&addr, 0u);
    ck_assert_int_eq(
        bowie_sock_bind(BOWIE_SOCK_INVALID, &addr),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_bind_null_addr)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_sock_bind(fd, NULL),
                     BOWIE_ERR_NULL_ARG);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_bind_unspec_family)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    addr.family = BOWIE_AF_UNSPEC;

    ck_assert_int_eq(bowie_sock_bind(fd, &addr),
                     BOWIE_ERR_INVAL);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_bind_loopback_ephemeral)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t addr;
    make_loopback4(&addr, 0u);

    ck_assert_int_eq(bowie_sock_bind(fd, &addr), BOWIE_OK);
    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * LOCAL
 * ============================================================================
 */

START_TEST(test_local_invalid_handle)
{
    bowie_addr_t addr;
    ck_assert_int_eq(
        bowie_sock_local(BOWIE_SOCK_INVALID, &addr),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_local_null_out)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_sock_local(fd, NULL),
                     BOWIE_ERR_NULL_ARG);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_local_after_bind)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t bind_addr;
    make_loopback4(&bind_addr, 0u);
    ck_assert_int_eq(bowie_sock_bind(fd, &bind_addr), BOWIE_OK);

    bowie_addr_t local;
    ck_assert_int_eq(bowie_sock_local(fd, &local), BOWIE_OK);

    ck_assert_int_eq(local.family, BOWIE_AF_INET);
    ck_assert_uint_ne(local.port, 0u);
    ck_assert_uint_eq(local.addr[0], 127u);
    ck_assert_uint_eq(local.addr[1], 0u);
    ck_assert_uint_eq(local.addr[2], 0u);
    ck_assert_uint_eq(local.addr[3], 1u);

    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * SENDTO
 * ============================================================================
 */

START_TEST(test_sendto_invalid_handle)
{
    bowie_addr_t addr;
    make_loopback4(&addr, 1u);
    ck_assert_int_eq(
        (int)bowie_sock_sendto(BOWIE_SOCK_INVALID, &addr,
                               "x", 1u),
        -(int)BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_sendto_null_addr)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(
        (int)bowie_sock_sendto(fd, NULL, "x", 1u),
        -(int)BOWIE_ERR_NULL_ARG);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_sendto_null_buf)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t addr;
    make_loopback4(&addr, 1u);

    ck_assert_int_eq(
        (int)bowie_sock_sendto(fd, &addr, NULL, 1u),
        -(int)BOWIE_ERR_NULL_ARG);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_sendto_zero_len)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t addr;
    make_loopback4(&addr, 1u);

    ck_assert_int_eq(
        (int)bowie_sock_sendto(fd, &addr, "x", 0u),
        0);
    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * RECVFROM
 * ============================================================================
 */

START_TEST(test_recvfrom_invalid_handle)
{
    char buf[16];
    ck_assert_int_eq(
        (int)bowie_sock_recvfrom(BOWIE_SOCK_INVALID, NULL,
                                 buf, sizeof(buf)),
        -(int)BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_recvfrom_null_buf)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(
        (int)bowie_sock_recvfrom(fd, NULL, NULL, 16u),
        -(int)BOWIE_ERR_NULL_ARG);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_recvfrom_zero_cap)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    char buf[16];
    ck_assert_int_eq(
        (int)bowie_sock_recvfrom(fd, NULL, buf, 0u),
        0);
    bowie_sock_close(fd);
}
END_TEST

START_TEST(test_recvfrom_nonblocking_no_data)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_sock_set_nonblocking(fd), BOWIE_OK);

    bowie_addr_t bind_addr;
    make_loopback4(&bind_addr, 0u);
    ck_assert_int_eq(bowie_sock_bind(fd, &bind_addr), BOWIE_OK);

    char buf[16];
    long got = bowie_sock_recvfrom(fd, NULL, buf, sizeof(buf));
    ck_assert(got < 0);
    ck_assert_int_eq((int)(-got), (int)BOWIE_ERR_AGAIN);

    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * LOOPBACK ROUND TRIP
 * ============================================================================
 *
 * A datagram sent to the local loopback address is received by
 * the same socket. This tests the send and receive paths
 * without involving the network stack.
 */

START_TEST(test_loopback_roundtrip)
{
    int fd = 0;
    ck_assert_int_eq(bowie_sock_open(BOWIE_AF_INET,
                                     BOWIE_SOCK_DGRAM, &fd),
                     BOWIE_OK);

    bowie_addr_t bind_addr;
    make_loopback4(&bind_addr, 0u);
    ck_assert_int_eq(bowie_sock_bind(fd, &bind_addr), BOWIE_OK);

    bowie_addr_t local;
    ck_assert_int_eq(bowie_sock_local(fd, &local), BOWIE_OK);

    const char *msg = "hello";
    long sent = bowie_sock_sendto(fd, &local, msg, 5u);
    ck_assert_int_eq((int)sent, 5);

    char buf[16];
    memset(buf, 0, sizeof(buf));

    bowie_addr_t from;
    long got = bowie_sock_recvfrom(fd, &from, buf, sizeof(buf));
    ck_assert_int_eq((int)got, 5);
    ck_assert_int_eq(buf[0], 'h');
    ck_assert_int_eq(buf[4], 'o');

    ck_assert_int_eq(from.family, BOWIE_AF_INET);

    bowie_sock_close(fd);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *sock_suite(void)
{
    Suite *s = suite_create("Sock");

    TCase *tc_open = tcase_create("Open");
    tcase_add_test(tc_open, test_open_null_out);
    tcase_add_test(tc_open, test_open_unspec_family);
    tcase_add_test(tc_open, test_open_bad_type);
    tcase_add_test(tc_open, test_open_udp4);
    tcase_add_test(tc_open, test_open_udp6);
    tcase_add_test(tc_open, test_open_tcp4);
    tcase_add_test(tc_open, test_open_out_zeroed_on_inval);
    suite_add_tcase(s, tc_open);

    TCase *tc_close = tcase_create("Close");
    tcase_add_test(tc_close, test_close_invalid_is_noop);
    suite_add_tcase(s, tc_close);

    TCase *tc_reuse = tcase_create("ReuseAddr");
    tcase_add_test(tc_reuse, test_set_reuseaddr_invalid);
    tcase_add_test(tc_reuse, test_set_reuseaddr_ok);
    suite_add_tcase(s, tc_reuse);

    TCase *tc_nb = tcase_create("NonBlocking");
    tcase_add_test(tc_nb, test_set_nonblocking_invalid);
    tcase_add_test(tc_nb, test_set_nonblocking_ok);
    suite_add_tcase(s, tc_nb);

    TCase *tc_bind = tcase_create("Bind");
    tcase_add_test(tc_bind, test_bind_invalid_handle);
    tcase_add_test(tc_bind, test_bind_null_addr);
    tcase_add_test(tc_bind, test_bind_unspec_family);
    tcase_add_test(tc_bind, test_bind_loopback_ephemeral);
    suite_add_tcase(s, tc_bind);

    TCase *tc_local = tcase_create("Local");
    tcase_add_test(tc_local, test_local_invalid_handle);
    tcase_add_test(tc_local, test_local_null_out);
    tcase_add_test(tc_local, test_local_after_bind);
    suite_add_tcase(s, tc_local);

    TCase *tc_send = tcase_create("Sendto");
    tcase_add_test(tc_send, test_sendto_invalid_handle);
    tcase_add_test(tc_send, test_sendto_null_addr);
    tcase_add_test(tc_send, test_sendto_null_buf);
    tcase_add_test(tc_send, test_sendto_zero_len);
    suite_add_tcase(s, tc_send);

    TCase *tc_recv = tcase_create("Recvfrom");
    tcase_add_test(tc_recv, test_recvfrom_invalid_handle);
    tcase_add_test(tc_recv, test_recvfrom_null_buf);
    tcase_add_test(tc_recv, test_recvfrom_zero_cap);
    tcase_add_test(tc_recv, test_recvfrom_nonblocking_no_data);
    suite_add_tcase(s, tc_recv);

    TCase *tc_rt = tcase_create("LoopbackRoundtrip");
    tcase_add_test(tc_rt, test_loopback_roundtrip);
    suite_add_tcase(s, tc_rt);

    return s;
}

int main(void)
{
    Suite *s = sock_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
