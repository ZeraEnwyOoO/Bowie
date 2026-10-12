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
 * BOWIE — DHT CONFIG TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/config.c.
 *
 * The tests cover:
 *
 *   - Defaults: null, zero, preserves non-zero.
 *   - Validate: null, defaults, bad fields, cross-field,
 *     bootstrap list.
 *   - Normalize: null, zero, clamping, cross-field,
 *     bootstrap termination.
 *   - Invariant: normalize produces a valid config.
 *   - Bootstrap helpers: add, clear, length, full.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset, strlen
 *   "bowie/err.h"                error codes
 *   "dht/config.h"               the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/config.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static bowie_dht_config_t zeroed(void)
{
    bowie_dht_config_t c;
    memset(&c, 0, sizeof(c));
    return c;
}

static bowie_dht_config_t defaulted(void)
{
    bowie_dht_config_t c = zeroed();
    (void)bowie_dht_config_defaults(&c);
    return c;
}

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

START_TEST(test_defaults_null)
{
    ck_assert_int_eq(bowie_dht_config_defaults(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_defaults_zeroed)
{
    bowie_dht_config_t c = zeroed();
    ck_assert_int_eq(bowie_dht_config_defaults(&c), BOWIE_OK);

    ck_assert_uint_eq(c.max_buckets,
                      BOWIE_DHT_DEFAULT_MAX_BUCKETS);
    ck_assert_uint_eq(c.max_nodes_per_bucket,
                      BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET);
    ck_assert_uint_eq(c.max_hashes,
                      BOWIE_DHT_DEFAULT_MAX_HASHES);
    ck_assert_uint_eq(c.max_peers_per_hash,
                      BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH);
    ck_assert_uint_eq(c.max_storage_peers,
                      BOWIE_DHT_DEFAULT_MAX_STORAGE_PEERS);
    ck_assert_uint_eq(c.refresh_interval_s,
                      BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S);
    ck_assert_uint_eq(c.peer_lifetime_s,
                      BOWIE_DHT_DEFAULT_PEER_LIFETIME_S);
    ck_assert_uint_eq(c.token_rotate_s,
                      BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S);
    ck_assert_uint_eq(c.search_timeout_ms,
                      BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS);
    ck_assert_uint_eq(c.max_requests_per_window,
                      BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS);
    ck_assert_int_eq(c.sec_level, BOWIE_DHT_SEC_NONE);
}
END_TEST

START_TEST(test_defaults_preserves_nonzero)
{
    bowie_dht_config_t c = zeroed();
    c.max_buckets = 16u;
    c.max_hashes = 64u;
    c.sec_level = BOWIE_DHT_SEC_BASIC;
    c.router_mode = 1;

    ck_assert_int_eq(bowie_dht_config_defaults(&c), BOWIE_OK);
    ck_assert_uint_eq(c.max_buckets, 16u);
    ck_assert_uint_eq(c.max_hashes, 64u);
    ck_assert_int_eq(c.sec_level, BOWIE_DHT_SEC_BASIC);
    ck_assert_int_eq(c.router_mode, 1);
}
END_TEST

START_TEST(test_defaults_bad_level_reset)
{
    bowie_dht_config_t c = zeroed();
    c.sec_level = (bowie_dht_sec_level_t)99;
    (void)bowie_dht_config_defaults(&c);
    ck_assert_int_eq(c.sec_level, BOWIE_DHT_SEC_NONE);
}
END_TEST

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

START_TEST(test_validate_null)
{
    ck_assert_int_eq(bowie_dht_config_validate(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_validate_default_is_valid)
{
    bowie_dht_config_t c = defaulted();
    /*
     * The default max_storage_peers is 4096, and the
     * default product is 256 * 16 = 4096. The defaults
     * function does not raise the storage because the
     * default already equals the need.
     */
    ck_assert_int_eq(bowie_dht_config_validate(&c), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_normalized_is_valid)
{
    bowie_dht_config_t c = zeroed();
    (void)bowie_dht_config_normalize(&c);
    ck_assert_int_eq(bowie_dht_config_validate(&c), BOWIE_OK);
}
END_TEST

START_TEST(test_validate_max_buckets_too_large)
{
    bowie_dht_config_t c = defaulted();
    c.max_buckets = 161u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_max_buckets_zero)
{
    bowie_dht_config_t c = defaulted();
    c.max_buckets = 0u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_max_nodes_per_bucket_too_large)
{
    bowie_dht_config_t c = defaulted();
    c.max_nodes_per_bucket = 65u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_storage_too_small)
{
    /*
     * The storage must hold max_hashes * max_peers_per_hash.
     * A smaller value is a range error.
     */
    bowie_dht_config_t c = defaulted();
    c.max_hashes = 256u;
    c.max_peers_per_hash = 16u;
    c.max_storage_peers = 256u * 16u - 1u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_strict_needs_rate_limit)
{
    bowie_dht_config_t c = defaulted();
    c.sec_level = BOWIE_DHT_SEC_STRICT;
    c.max_requests_per_window = 0u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_relay_and_metadata_conflict)
{
    bowie_dht_config_t c = defaulted();
    c.relay_only = 1;
    c.store_metadata = 1;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_bootstrap_count_too_large)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = BOWIE_DHT_BOOTSTRAP_MAX + 1u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_RANGE);
}
END_TEST

START_TEST(test_validate_bootstrap_empty_host)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = 1u;
    memset(c.bootstrap[0].host, 0, sizeof(c.bootstrap[0].host));
    c.bootstrap[0].port = 6881u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_validate_bootstrap_zero_port)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = 1u;
    memcpy(c.bootstrap[0].host, "router.example",
           strlen("router.example") + 1u);
    c.bootstrap[0].port = 0u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_validate_bootstrap_not_terminated)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = 1u;
    memset(c.bootstrap[0].host, 'x', sizeof(c.bootstrap[0].host));
    c.bootstrap[0].port = 6881u;
    ck_assert_int_eq(bowie_dht_config_validate(&c),
                     BOWIE_ERR_NOT_TERMINATED);
}
END_TEST

START_TEST(test_validate_bootstrap_ok)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = 1u;
    memcpy(c.bootstrap[0].host, "router.example",
           strlen("router.example") + 1u);
    c.bootstrap[0].port = 6881u;
    ck_assert_int_eq(bowie_dht_config_validate(&c), BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * NORMALIZE
 * ============================================================================
 */

START_TEST(test_normalize_null)
{
    ck_assert_int_eq(bowie_dht_config_normalize(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_normalize_zeroed)
{
    bowie_dht_config_t c = zeroed();
    ck_assert_int_eq(bowie_dht_config_normalize(&c), BOWIE_OK);
    ck_assert_int_eq(bowie_dht_config_validate(&c), BOWIE_OK);
}
END_TEST

START_TEST(test_normalize_clamps_max_buckets)
{
    bowie_dht_config_t c = defaulted();
    c.max_buckets = 999u;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_uint_eq(c.max_buckets, 160u);
}
END_TEST

START_TEST(test_normalize_raises_storage)
{
    bowie_dht_config_t c = defaulted();
    c.max_hashes = 100u;
    c.max_peers_per_hash = 32u;
    c.max_storage_peers = 1u;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_uint_eq(c.max_storage_peers, 100u * 32u);
}
END_TEST

START_TEST(test_normalize_bad_level_becomes_none)
{
    bowie_dht_config_t c = defaulted();
    c.sec_level = (bowie_dht_sec_level_t)99;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_int_eq(c.sec_level, BOWIE_DHT_SEC_NONE);
}
END_TEST

START_TEST(test_normalize_strict_fills_rate_limit)
{
    bowie_dht_config_t c = defaulted();
    c.sec_level = BOWIE_DHT_SEC_STRICT;
    c.max_requests_per_window = 0u;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_uint_gt(c.max_requests_per_window, 0u);
}
END_TEST

START_TEST(test_normalize_relay_wins_over_metadata)
{
    bowie_dht_config_t c = defaulted();
    c.relay_only = 1;
    c.store_metadata = 1;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_int_eq(c.store_metadata, 0);
    ck_assert_int_eq(c.relay_only, 1);
}
END_TEST

START_TEST(test_normalize_terminates_bootstrap_host)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = 1u;
    memset(c.bootstrap[0].host, 'x', sizeof(c.bootstrap[0].host));
    c.bootstrap[0].port = 6881u;

    (void)bowie_dht_config_normalize(&c);
    ck_assert_int_eq(
        c.bootstrap[0].host[BOWIE_DHT_BOOTSTRAP_LEN_MAX - 1u],
        '\0');
}
END_TEST

START_TEST(test_normalize_clamps_bootstrap_count)
{
    bowie_dht_config_t c = defaulted();
    c.bootstrap_count = BOWIE_DHT_BOOTSTRAP_MAX + 5u;
    (void)bowie_dht_config_normalize(&c);
    ck_assert_uint_eq(c.bootstrap_count, BOWIE_DHT_BOOTSTRAP_MAX);
}
END_TEST

START_TEST(test_normalize_idempotent)
{
    bowie_dht_config_t a = defaulted();
    a.router_mode = 1;
    a.max_buckets = 999u;

    (void)bowie_dht_config_normalize(&a);
    bowie_dht_config_t b = a;
    (void)bowie_dht_config_normalize(&b);

    ck_assert_uint_eq(a.max_buckets, b.max_buckets);
    ck_assert_uint_eq(a.max_storage_peers, b.max_storage_peers);
    ck_assert_int_eq(a.sec_level, b.sec_level);
    ck_assert_int_eq(a.relay_only, b.relay_only);
    ck_assert_int_eq(a.store_metadata, b.store_metadata);
    ck_assert_uint_eq(a.bootstrap_count, b.bootstrap_count);
}
END_TEST

START_TEST(test_normalize_then_validate_various)
{
    /*
     * A set of intentionally broken configs. After
     * normalize, each must validate.
     */
    bowie_dht_config_t cases[5];
    for (size_t i = 0u; i < 5u; i++) {
        cases[i] = zeroed();
    }

    /* Case 0: everything zero. */
    /* Case 1: max_buckets too high. */
    cases[1].max_buckets = 9999u;
    /* Case 2: storage too small. */
    cases[2].max_hashes = 100u;
    cases[2].max_peers_per_hash = 100u;
    cases[2].max_storage_peers = 1u;
    /* Case 3: bad level + strict rate limit. */
    cases[3].sec_level = BOWIE_DHT_SEC_STRICT;
    cases[3].max_requests_per_window = 0u;
    /* Case 4: relay + metadata. */
    cases[4].relay_only = 1;
    cases[4].store_metadata = 1;

    for (size_t i = 0u; i < 5u; i++) {
        ck_assert_int_eq(bowie_dht_config_normalize(&cases[i]),
                         BOWIE_OK);
        ck_assert_int_eq(bowie_dht_config_validate(&cases[i]),
                         BOWIE_OK);
    }
}
END_TEST

/*
 * ============================================================================
 * BOOTSTRAP HELPERS
 * ============================================================================
 */

START_TEST(test_add_bootstrap_null)
{
    bowie_dht_config_t c = defaulted();
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(NULL, "a", 1u),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, NULL, 1u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_add_bootstrap_zero_port)
{
    bowie_dht_config_t c = defaulted();
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, "a", 0u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_add_bootstrap_empty_host)
{
    bowie_dht_config_t c = defaulted();
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, "", 1u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_add_bootstrap_too_long)
{
    bowie_dht_config_t c = defaulted();
    char long_host[BOWIE_DHT_BOOTSTRAP_LEN_MAX + 10u];
    memset(long_host, 'x', sizeof(long_host) - 1u);
    long_host[sizeof(long_host) - 1u] = '\0';

    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, long_host, 1u),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_add_bootstrap_ok)
{
    bowie_dht_config_t c = defaulted();
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, "a.example", 6881u),
        BOWIE_OK);
    ck_assert_uint_eq(c.bootstrap_count, 1u);
    ck_assert_str_eq(c.bootstrap[0].host, "a.example");
    ck_assert_uint_eq(c.bootstrap[0].port, 6881u);
}
END_TEST

START_TEST(test_add_bootstrap_full)
{
    bowie_dht_config_t c = defaulted();
    for (size_t i = 0u; i < BOWIE_DHT_BOOTSTRAP_MAX; i++) {
        ck_assert_int_eq(
            bowie_dht_config_add_bootstrap(&c, "a", 1u),
            BOWIE_OK);
    }
    ck_assert_int_eq(
        bowie_dht_config_add_bootstrap(&c, "b", 1u),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_clear_bootstrap)
{
    bowie_dht_config_t c = defaulted();
    (void)bowie_dht_config_add_bootstrap(&c, "a", 1u);
    ck_assert_uint_eq(c.bootstrap_count, 1u);

    bowie_dht_config_clear_bootstrap(&c);
    ck_assert_uint_eq(c.bootstrap_count, 0u);
}
END_TEST

START_TEST(test_clear_bootstrap_null)
{
    bowie_dht_config_clear_bootstrap(NULL);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *config_suite(void)
{
    Suite *s = suite_create("DhtConfig");

    TCase *tc_def = tcase_create("Defaults");
    tcase_add_test(tc_def, test_defaults_null);
    tcase_add_test(tc_def, test_defaults_zeroed);
    tcase_add_test(tc_def, test_defaults_preserves_nonzero);
    tcase_add_test(tc_def, test_defaults_bad_level_reset);
    suite_add_tcase(s, tc_def);

    TCase *tc_val = tcase_create("Validate");
    tcase_add_test(tc_val, test_validate_null);
    tcase_add_test(tc_val, test_validate_default_is_valid);
    tcase_add_test(tc_val, test_validate_normalized_is_valid);
    tcase_add_test(tc_val, test_validate_max_buckets_too_large);
    tcase_add_test(tc_val, test_validate_max_buckets_zero);
    tcase_add_test(tc_val,
                   test_validate_max_nodes_per_bucket_too_large);
    tcase_add_test(tc_val, test_validate_storage_too_small);
    tcase_add_test(tc_val, test_validate_strict_needs_rate_limit);
    tcase_add_test(tc_val,
                   test_validate_relay_and_metadata_conflict);
    tcase_add_test(tc_val,
                   test_validate_bootstrap_count_too_large);
    tcase_add_test(tc_val, test_validate_bootstrap_empty_host);
    tcase_add_test(tc_val, test_validate_bootstrap_zero_port);
    tcase_add_test(tc_val, test_validate_bootstrap_not_terminated);
    tcase_add_test(tc_val, test_validate_bootstrap_ok);
    suite_add_tcase(s, tc_val);

    TCase *tc_norm = tcase_create("Normalize");
    tcase_add_test(tc_norm, test_normalize_null);
    tcase_add_test(tc_norm, test_normalize_zeroed);
    tcase_add_test(tc_norm, test_normalize_clamps_max_buckets);
    tcase_add_test(tc_norm, test_normalize_raises_storage);
    tcase_add_test(tc_norm, test_normalize_bad_level_becomes_none);
    tcase_add_test(tc_norm, test_normalize_strict_fills_rate_limit);
    tcase_add_test(tc_norm, test_normalize_relay_wins_over_metadata);
    tcase_add_test(tc_norm,
                   test_normalize_terminates_bootstrap_host);
    tcase_add_test(tc_norm, test_normalize_clamps_bootstrap_count);
    tcase_add_test(tc_norm, test_normalize_idempotent);
    tcase_add_test(tc_norm, test_normalize_then_validate_various);
    suite_add_tcase(s, tc_norm);

    TCase *tc_bs = tcase_create("Bootstrap");
    tcase_add_test(tc_bs, test_add_bootstrap_null);
    tcase_add_test(tc_bs, test_add_bootstrap_zero_port);
    tcase_add_test(tc_bs, test_add_bootstrap_empty_host);
    tcase_add_test(tc_bs, test_add_bootstrap_too_long);
    tcase_add_test(tc_bs, test_add_bootstrap_ok);
    tcase_add_test(tc_bs, test_add_bootstrap_full);
    tcase_add_test(tc_bs, test_clear_bootstrap);
    tcase_add_test(tc_bs, test_clear_bootstrap_null);
    suite_add_tcase(s, tc_bs);

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
