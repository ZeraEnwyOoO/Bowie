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
 * BOWIE — TUNNEL TUN (LINUX) UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the Linux TUN device interface declared in
 * tunnel/tun_linux.h.
 *
 * These tests exercise the contract: argument validation and
 * error handling for the functions that can fail. They do not
 * create a real TUN device, because that requires elevated
 * privileges and would modify the host's network state. A
 * real device test is an integration test and belongs in
 * tests/integration/.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No real device. bowie_tun_open() is only called with
 *     parameters that fail before the kernel is touched.
 *   - No I/O. bowie_tun_read() and bowie_tun_write() are only
 *     checked for their NULL contracts.
 *   - No privilege test. Whether the caller has CAP_NET_ADMIN
 *     is not checked; the tests must pass for any user.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The suite is split into three cases:
 *
 *   contract   — NULL arguments and invalid values
 *   lifecycle  — close and fd on a NULL handle
 *   io         — read and write NULL contracts
 *
 * Every test is expected to pass without root. A test that
 * needs to open a real device is not here on purpose.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   "bowie/types.h"         bowie_tun_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "tunnel/tun_linux.h"    public contract
 * ============================================================================
 */

#include <check.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/tun_linux.h"

/*
 * ============================================================================
 * CONTRACT — NULL AND INVALID ARGUMENTS
 * ============================================================================
 */

START_TEST(test_tun_open_null_out)
{
    bowie_error_t rc;

    rc = bowie_tun_open(NULL, "tun0", 0);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_tun_open_invalid_mtu)
{
    bowie_tun_t  *tun = NULL;
    bowie_error_t rc;

    /*
     * An MTU below the accepted minimum must be rejected before
     * any kernel resource is touched.
     */
    rc = bowie_tun_open(&tun, "tun0", 1);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(tun);
}
END_TEST

START_TEST(test_tun_open_mtu_too_large)
{
    bowie_tun_t  *tun = NULL;
    bowie_error_t rc;

    rc = bowie_tun_open(&tun, "tun0", 100000);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(tun);
}
END_TEST

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_tun_close_null)
{
    bowie_tun_close(NULL);
    /* no crash is the assertion */
}
END_TEST

START_TEST(test_tun_fd_null)
{
    int fd;

    fd = bowie_tun_fd(NULL);

    ck_assert_int_eq(fd, -1);
}
END_TEST

/*
 * ============================================================================
 * I/O — NULL CONTRACTS
 * ============================================================================
 */

START_TEST(test_tun_read_null_tun)
{
    uint8_t buf[8] = {0};
    long    rc;

    rc = bowie_tun_read(NULL, buf, sizeof(buf));

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_tun_read_null_buf)
{
    bowie_tun_t *tun = NULL;
    long         rc;

    /*
     * A NULL handle is rejected before the buffer is looked at,
     * so the test does not need a real device.
     */
    rc = bowie_tun_read(tun, NULL, 0);

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_tun_write_null_tun)
{
    uint8_t buf[8] = {0};
    long    rc;

    rc = bowie_tun_write(NULL, buf, sizeof(buf));

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_tun_write_null_buf)
{
    bowie_tun_t *tun = NULL;
    long         rc;

    rc = bowie_tun_write(tun, NULL, 8);

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *tun_linux_suite(void)
{
    Suite *s;
    TCase *tc_contract;
    TCase *tc_lifecycle;
    TCase *tc_io;

    s = suite_create("TunnelTunLinux");

    tc_contract = tcase_create("Contract");
    tcase_add_test(tc_contract, test_tun_open_null_out);
    tcase_add_test(tc_contract, test_tun_open_invalid_mtu);
    tcase_add_test(tc_contract, test_tun_open_mtu_too_large);
    suite_add_tcase(s, tc_contract);

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_tun_close_null);
    tcase_add_test(tc_lifecycle, test_tun_fd_null);
    suite_add_tcase(s, tc_lifecycle);

    tc_io = tcase_create("IO");
    tcase_add_test(tc_io, test_tun_read_null_tun);
    tcase_add_test(tc_io, test_tun_read_null_buf);
    tcase_add_test(tc_io, test_tun_write_null_tun);
    tcase_add_test(tc_io, test_tun_write_null_buf);
    suite_add_tcase(s, tc_io);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = tun_linux_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
