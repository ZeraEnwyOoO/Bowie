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
 * BOWIE — CONFIG TESTS
 * ============================================================================
 *
 * Unit tests for src/api/config.c.
 *
 * Every public function declared in bowie/config.h is covered.
 *
 * The normalize/validate pair is tested for the invariant that
 * says: a normalized configuration is always valid. That is the
 * central contract of this module, and it is checked directly.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>         test framework
 *   <string.h>        memset
 *   "bowie/config.h"  the unit under test
 *   "bowie/err.h"     error codes
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/config.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

START_TEST(test_defaults_null)
{
    ck_assert_int_eq(bowie_config_defaults(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_defaults_zero_fills_everything)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    ck_assert_int_eq(bowie_config_defaults(&cfg), BOWIE_OK);

    /* Mode is preserved (UNSET). */
    ck_assert_int_eq(cfg.mode, BOWIE_MODE_UNSET);

    /* Capabilities follow the mode preset (UNSET -> NONE). */
    ck_assert_uint_eq(cfg.capabilities,
                      (uint32_t)BOWIE_CAP_NONE);

    /* Network defaults. */
    ck_assert_int_eq(cfg.dht_enabled, 1);
    ck_assert_int_eq(cfg.nat_enabled, 1);
    ck_assert_int_eq(cfg.tunnel_enabled, 1);
    ck_assert_int_eq(cfg.gateway_enabled, 0);

    /* Security defaults. */
    ck_assert_uint_gt(cfg.grant_lifetime_sec, 0u);
    ck_assert_int_eq(cfg.revocation_enabled, 1);

    /* Runtime defaults. */
    ck_assert_int_eq(cfg.log_level, BOWIE_LOG_INFO);
    ck_assert_uint_eq(cfg.max_peers, BOWIE_MAX_PEERS);
    ck_assert_uint_eq(cfg.max_sessions, BOWIE_MAX_SESSIONS);
    ck_assert_uint_gt(cfg.connect_timeout_ms, 0u);
    ck_assert_uint_gt(cfg.operation_timeout_ms, 0u);
    ck_assert_uint_eq(cfg.worker_threads, 0u);
}
END_TEST

START_TEST(test_defaults_preserves_mode)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = BOWIE_MODE_ROUTER;

    ck_assert_int_eq(bowie_config_defaults(&cfg), BOWIE_OK);
    ck_assert_int_eq(cfg.mode, BOWIE_MODE_ROUTER);
}
END_TEST

START_TEST(test_defaults_preserves_capabilities)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = BOWIE_MODE_DEVICE;
    cfg.capabilities = (uint32_t)BOWIE_CAP_SOURCE;

    ck_assert_int_eq(bowie_config_defaults(&cfg), BOWIE_OK);
    ck_assert_uint_eq(cfg.capabilities,
                      (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

START_TEST(test_defaults_mode_fills_capabilities_when_unset)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = BOWIE_MODE_ROUTER;
    cfg.capabilities = BOWIE_CAP_NONE;

    ck_assert_int_eq(bowie_config_defaults(&cfg), BOWIE_OK);

    ck_assert(bowie_cap_has(cfg.capabilities, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(cfg.capabilities, BOWIE_CAP_GATEWAY));
    ck_assert(!bowie_cap_has(cfg.capabilities, BOWIE_CAP_CLIENT));
}
END_TEST

/*
 * ============================================================================
 * CAPABILITY HELPERS
 * ============================================================================
 */

START_TEST(test_cap_has_true)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE
                  | (uint32_t)BOWIE_CAP_GATEWAY;
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(mask, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_has_false)
{
    uint32_t mask = (uint32_t)BOWIE_CAP_SOURCE;
    ck_assert(!bowie_cap_has(mask, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(mask, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_has_none)
{
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(BOWIE_CAP_NONE, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_device)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_DEVICE);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_router)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_ROUTER);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_box)
{
    uint32_t caps = bowie_cap_for_mode(BOWIE_MODE_BOX);
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_cap_has(caps, BOWIE_CAP_CLIENT));
    ck_assert(bowie_cap_has(caps, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_cap_for_mode_unset)
{
    ck_assert_uint_eq(bowie_cap_for_mode(BOWIE_MODE_UNSET),
                      (uint32_t)BOWIE_CAP_NONE);
}
END_TEST

START_TEST(test_cap_for_mode_invalid)
{
    ck_assert_uint_eq(bowie_cap_for_mode((bowie_mode_t)999),
                      (uint32_t)BOWIE_CAP_NONE);
}
END_TEST

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

START_TEST(test_validate_null)
{
    ck_assert_int_eq(bowie_config_validate(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_validate_default_is_valid)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_normalized_is_valid)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_normalize(&cfg);
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_bad_mode)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.mode = (bowie_mode_t)999;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_bad_capabilities)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.capabilities = 0x80000000u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_bad_log_level)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.log_level = (bowie_log_level_t)999;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_zero_max_peers)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.max_peers = 0u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_max_peers_too_large)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.max_peers = BOWIE_MAX_PEERS + 1u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_zero_max_sessions)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.max_sessions = 0u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_zero_connect_timeout)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.connect_timeout_ms = 0u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_zero_operation_timeout)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.operation_timeout_ms = 0u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_no_expiry_no_revocation)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.grant_lifetime_sec = 0u;
    cfg.revocation_enabled = 0;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_no_expiry_with_revocation_ok)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.grant_lifetime_sec = 0u;
    cfg.revocation_enabled = 1;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_interface_not_terminated)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);

    /*
     * Fill the interface with non-zero bytes so that the last
     * byte is not a terminator.
     */
    memset(cfg.interface, 'x', sizeof(cfg.interface));

    ck_assert_int_eq(bowie_config_validate(&cfg),
                     BOWIE_ERR_NOT_TERMINATED);
}
END_TEST

START_TEST(test_validate_bootstrap_peer_count_too_large)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)bowie_config_defaults(&cfg);
    cfg.bootstrap_peer_count = BOWIE_CONFIG_PEER_MAX + 1u;
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_ERR_RANGE);
}
END_TEST

/*
 * ============================================================================
 * NORMALIZE
 * ============================================================================
 */

START_TEST(test_normalize_null)
{
    ck_assert_int_eq(bowie_config_normalize(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_normalize_zeroed_is_valid)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ck_assert_int_eq(bowie_config_normalize(&cfg), BOWIE_OK);
    ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_OK);
}
END_TEST

START_TEST(test_normalize_bad_mode_becomes_unset)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = (bowie_mode_t)999;
    (void)bowie_config_normalize(&cfg);
    ck_assert_int_eq(cfg.mode, BOWIE_MODE_UNSET);
}
END_TEST

START_TEST(test_normalize_bad_log_level_becomes_info)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.log_level = (bowie_log_level_t)999;
    (void)bowie_config_normalize(&cfg);
    ck_assert_int_eq(cfg.log_level, BOWIE_LOG_INFO);
}
END_TEST

START_TEST(test_normalize_clamps_max_peers_high)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_peers = BOWIE_MAX_PEERS + 100u;
    (void)bowie_config_normalize(&cfg);
    ck_assert_uint_eq(cfg.max_peers, BOWIE_MAX_PEERS);
}
END_TEST

START_TEST(test_normalize_fills_zero_max_peers)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_peers = 0u;
    (void)bowie_config_normalize(&cfg);
    ck_assert_uint_eq(cfg.max_peers, BOWIE_MAX_PEERS);
}
END_TEST

START_TEST(test_normalize_fills_zero_timeouts)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.connect_timeout_ms = 0u;
    cfg.operation_timeout_ms = 0u;
    (void)bowie_config_normalize(&cfg);
    ck_assert_uint_gt(cfg.connect_timeout_ms, 0u);
    ck_assert_uint_gt(cfg.operation_timeout_ms, 0u);
}
END_TEST

START_TEST(test_normalize_strips_unknown_capabilities)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.capabilities = 0xFFFFFFFFu;
    (void)bowie_config_normalize(&cfg);

    const uint32_t allowed = (uint32_t)BOWIE_CAP_SOURCE
                           | (uint32_t)BOWIE_CAP_CLIENT
                           | (uint32_t)BOWIE_CAP_GATEWAY;
    ck_assert_uint_eq(cfg.capabilities & ~allowed, 0u);
}
END_TESTSTART_TEST(test_normalize_applies_mode_preset)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = BOWIE_MODE_ROUTER;
    cfg.capabilities = BOWIE_CAP_NONE;
    (void)bowie_config_normalize(&cfg);

    ck_assert(bowie_cap_has(cfg.capabilities, BOWIE_CAP_SOURCE));
    ck_assert(bowie_cap_has(cfg.capabilities, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_normalize_keeps_explicit_capabilities)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = BOWIE_MODE_ROUTER;
    cfg.capabilities = (uint32_t)BOWIE_CAP_CLIENT;
    (void)bowie_config_normalize(&cfg);

    ck_assert_uint_eq(cfg.capabilities,
                      (uint32_t)BOWIE_CAP_CLIENT);
}
END_TEST

START_TEST(test_normalize_terminates_interface)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memset(cfg.interface, 'x', sizeof(cfg.interface));
    (void)bowie_config_normalize(&cfg);
    ck_assert_int_eq(cfg.interface[BOWIE_CONFIG_INTERFACE_MAX - 1u],
                     '\0');
}
END_TEST

START_TEST(test_normalize_clamps_bootstrap_count)
{
    bowie_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bootstrap_peer_count = BOWIE_CONFIG_PEER_MAX + 5u;
    (void)bowie_config_normalize(&cfg);
    ck_assert_uint_eq(cfg.bootstrap_peer_count,
                      BOWIE_CONFIG_PEER_MAX);
}
END_TEST

START_TEST(test_normalize_is_idempotent)
{
    bowie_config_t a;
    bowie_config_t b;
    memset(&a, 0, sizeof(a));
    a.mode = BOWIE_MODE_ROUTER;

    (void)bowie_config_normalize(&a);
    b = a;
    (void)bowie_config_normalize(&b);

    ck_assert_int_eq(a.mode, b.mode);
    ck_assert_uint_eq(a.capabilities, b.capabilities);
    ck_assert_uint_eq(a.max_peers, b.max_peers);
    ck_assert_uint_eq(a.max_sessions, b.max_sessions);
    ck_assert_uint_eq(a.connect_timeout_ms, b.connect_timeout_ms);
    ck_assert_uint_eq(a.operation_timeout_ms, b.operation_timeout_ms);
    ck_assert_int_eq(a.log_level, b.log_level);
    ck_assert_int_eq(a.grant_lifetime_sec, b.grant_lifetime_sec);
}
END_TEST

/*
 * ============================================================================
 * INVARIANT: NORMALIZE PRODUCES A VALID CONFIG
 * ============================================================================
 */

START_TEST(test_normalize_then_validate_for_each_mode)
{
    const bowie_mode_t modes[] = {
        BOWIE_MODE_UNSET,
        BOWIE_MODE_DEVICE,
        BOWIE_MODE_ROUTER,
        BOWIE_MODE_BOX,
        (bowie_mode_t)999,
    };
    size_t n = sizeof(modes) / sizeof(modes[0]);

    for (size_t i = 0u; i < n; i++) {
        bowie_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.mode = modes[i];

        ck_assert_int_eq(bowie_config_normalize(&cfg), BOWIE_OK);
        ck_assert_int_eq(bowie_config_validate(&cfg), BOWIE_OK);
    }
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *config_suite(void)
{
    Suite *s = suite_create("Config");

    TCase *tc_def = tcase_create("Defaults");
    tcase_add_test(tc_def, test_defaults_null);
    tcase_add_test(tc_def, test_defaults_zero_fills_everything);
    tcase_add_test(tc_def, test_defaults_preserves_mode);
    tcase_add_test(tc_def, test_defaults_preserves_capabilities);
    tcase_add_test(tc_def, test_defaults_mode_fills_capabilities_when_unset);
    suite_add_tcase(s, tc_def);

    TCase *tc_cap = tcase_create("Capabilities");
    tcase_add_test(tc_cap, test_cap_has_true);
    tcase_add_test(tc_cap, test_cap_has_false);
    tcase_add_test(tc_cap, test_cap_has_none);
    tcase_add_test(tc_cap, test_cap_for_mode_device);
    tcase_add_test(tc_cap, test_cap_for_mode_router);
    tcase_add_test(tc_cap, test_cap_for_mode_box);
    tcase_add_test(tc_cap, test_cap_for_mode_unset);
    tcase_add_test(tc_cap, test_cap_for_mode_invalid);
    suite_add_tcase(s, tc_cap);

    TCase *tc_val = tcase_create("Validate");
    tcase_add_test(tc_val, test_validate_null);
    tcase_add_test(tc_val, test_validate_default_is_valid);
    tcase_add_test(tc_val, test_validate_normalized_is_valid);
    tcase_add_test(tc_val, test_validate_bad_mode);
    tcase_add_test(tc_val, test_validate_bad_capabilities);
    tcase_add_test(tc_val, test_validate_bad_log_level);
    tcase_add_test(tc_val, test_validate_zero_max_peers);
    tcase_add_test(tc_val, test_validate_max_peers_too_large);
    tcase_add_test(tc_val, test_validate_zero_max_sessions);
    tcase_add_test(tc_val, test_validate_zero_connect_timeout);
    tcase_add_test(tc_val, test_validate_zero_operation_timeout);
    tcase_add_test(tc_val, test_validate_no_expiry_no_revocation);
    tcase_add_test(tc_val, test_validate_no_expiry_with_revocation_ok);
    tcase_add_test(tc_val, test_validate_interface_not_terminated);
    tcase_add_test(tc_val, test_validate_bootstrap_peer_count_too_large);
    suite_add_tcase(s, tc_val);

    TCase *tc_norm = tcase_create("Normalize");
    tcase_add_test(tc_norm, test_normalize_null);
    tcase_add_test(tc_norm, test_normalize_zeroed_is_valid);
    tcase_add_test(tc_norm, test_normalize_bad_mode_becomes_unset);
    tcase_add_test(tc_norm, test_normalize_bad_log_level_becomes_info);
    tcase_add_test(tc_norm, test_normalize_clamps_max_peers_high);
    tcase_add_test(tc_norm, test_normalize_fills_zero_max_peers);
    tcase_add_test(tc_norm, test_normalize_fills_zero_timeouts);
    tcase_add_test(tc_norm, test_normalize_strips_unknown_capabilities);
    tcase_add_test(tc_norm, test_normalize_applies_mode_preset);
    tcase_add_test(tc_norm, test_normalize_keeps_explicit_capabilities);
    tcase_add_test(tc_norm, test_normalize_terminates_interface);
    tcase_add_test(tc_norm, test_normalize_clamps_bootstrap_count);
    tcase_add_test(tc_norm, test_normalize_is_idempotent);
    tcase_add_test(tc_norm, test_normalize_then_validate_for_each_mode);
    suite_add_tcase(s, tc_norm);

    return s;
}

int main(void)
{
    Suite *s = config_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
