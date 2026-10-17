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
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/gateway.h"

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

START_TEST(test_gateway_default_config)
{
    bowie_gateway_config_t cfg;

    memset(&cfg, 0xFF, sizeof(cfg));
    bowie_gateway_default_config(&cfg);

    ck_assert_uint_eq(cfg.mtu, 0);
    ck_assert_uint_eq(cfg.conntrack_capacity, 0);
    ck_assert_int_eq(cfg.allow_private, 0);
    ck_assert_int_eq(cfg.allow_ipv6, 0);
}
END_TEST

START_TEST(test_gateway_default_config_null)
{
    bowie_gateway_default_config(NULL);
}
END_TEST

/*
 * ============================================================================
 * CONTRACT
 * ============================================================================
 */

START_TEST(test_gateway_open_null)
{
    bowie_gateway_t       *gw = NULL;
    bowie_gateway_config_t cfg;
    bowie_error_t          rc;

    bowie_gateway_default_config(&cfg);

    rc = bowie_gateway_open(&gw, &cfg, NULL);
    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
    ck_assert_ptr_null(gw);
}
END_TEST

START_TEST(test_gateway_open_invalid_config)
{
    bowie_gateway_t       *gw = NULL;
    bowie_gateway_config_t cfg;
    bowie_error_t          rc;

    bowie_gateway_default_config(&cfg);
    cfg.allow_private = 2;

    rc = bowie_gateway_open(&gw, &cfg, (bowie_tun_t *)0x1);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(gw);
}
END_TEST

START_TEST(test_gateway_close_null)
{
    bowie_gateway_close(NULL);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *gateway_suite(void)
{
    Suite *s;
    TCase *tc_config;
    TCase *tc_contract;

    s = suite_create("GatewayGateway");

    tc_config = tcase_create("Config");
    tcase_add_test(tc_config, test_gateway_default_config);
    tcase_add_test(tc_config, test_gateway_default_config_null);
    suite_add_tcase(s, tc_config);

    tc_contract = tcase_create("Contract");
    tcase_add_test(tc_contract, test_gateway_open_null);
    tcase_add_test(tc_contract, test_gateway_open_invalid_config);
    tcase_add_test(tc_contract, test_gateway_close_null);
    suite_add_tcase(s, tc_contract);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = gateway_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
