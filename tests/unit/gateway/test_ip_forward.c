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

#include <check.h>

#include "bowie/err.h"
#include "gateway/ip_forward.h"

/*
 * These tests do not change the host's sysctl. They only
 * call the read function, which is safe.
 */

START_TEST(test_ip_forward_read_v4)
{
    int rc = bowie_ip_forward_is_enabled();

    ck_assert_int_ge(rc, BOWIE_ERR_NONE);
}
END_TEST

START_TEST(test_ip_forward_read_v6)
{
    int rc = bowie_ip_forward_is_enabled_v6();

    ck_assert_int_ge(rc, BOWIE_ERR_NONE);
}
END_TEST

static Suite *ip_forward_suite(void)
{
    Suite *s;
    TCase *tc_read;

    s = suite_create("GatewayIpForward");

    tc_read = tcase_create("Read");
    tcase_add_test(tc_read, test_ip_forward_read_v4);
    tcase_add_test(tc_read, test_ip_forward_read_v6);
    suite_add_tcase(s, tc_read);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = ip_forward_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
