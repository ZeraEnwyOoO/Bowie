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
 * BOWIE — DHT TOKEN TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/token.c.
 *
 * The tests cover:
 *
 *   - State lifecycle: init, clear.
 *   - Rotation: rotate, should_rotate.
 *   - Generation: generate.
 *   - Validation: validate.
 *
 * The token generator reads from the platform entropy source.
 * The tests do not assume a particular value; they check the
 * contracts: a generated token is valid, a different address
 * produces a different token, a rotated secret invalidates the
 * older token after the second rotation.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/token.h"                the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/token.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

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

/*
 * ============================================================================
 * STATE LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null)
{
    ck_assert_int_eq(
        bowie_dht_token_state_init(NULL, 60000u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_ok)
{
    bowie_dht_token_state_t s;
    ck_assert_int_eq(
        bowie_dht_token_state_init(&s, 60000u, 1000u),
        BOWIE_OK);
    ck_assert_uint_eq(s.rotate_interval_ms, 60000u);
    ck_assert_uint_eq(s.last_rotate_ms, 1000u);

    /* The current and previous secrets must be non-zero. */
    int current_nonzero = 0;
    int previous_nonzero = 0;
    for (size_t i = 0u; i < BOWIE_DHT_TOKEN_SECRET_LEN; i++) {
        if (s.current.bytes[i] != 0u) {
            current_nonzero = 1;
        }
        if (s.previous.bytes[i] != 0u) {
            previous_nonzero = 1;
        }
    }
    ck_assert(current_nonzero);
    ck_assert(previous_nonzero);
}
END_TEST

START_TEST(test_init_zero_interval)
{
    bowie_dht_token_state_t s;
    ck_assert_int_eq(
        bowie_dht_token_state_init(&s, 0u, 0u),
        BOWIE_OK);
    ck_assert_uint_eq(s.rotate_interval_ms, 0u);
}
END_TEST

START_TEST(test_clear)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    bowie_dht_token_state_clear(&s);

    ck_assert_uint_eq(s.rotate_interval_ms, 0u);
    ck_assert_uint_eq(s.last_rotate_ms, 0u);

    int all_zero = 1;
    for (size_t i = 0u; i < BOWIE_DHT_TOKEN_SECRET_LEN; i++) {
        if (s.current.bytes[i] != 0u) {
            all_zero = 0;
        }
        if (s.previous.bytes[i] != 0u) {
            all_zero = 0;
        }
    }
    ck_assert(all_zero);
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_dht_token_state_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * ROTATE
 * ============================================================================
 */

START_TEST(test_rotate_null)
{
    ck_assert_int_eq(
        bowie_dht_token_rotate(NULL, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_rotate_moves_current_to_previous)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_dht_token_secret_t old_current = s.current;
    (void)bowie_dht_token_rotate(&s, 2000u);

    /* The old current is now the previous. */
    ck_assert_mem_eq(s.previous.bytes,
                     old_current.bytes,
                     BOWIE_DHT_TOKEN_SECRET_LEN);

    /* The new current differs from the old. */
    int same = (memcmp(s.current.bytes, old_current.bytes,
                       BOWIE_DHT_TOKEN_SECRET_LEN) == 0);
    ck_assert(!same);

    ck_assert_uint_eq(s.last_rotate_ms, 2000u);
}
END_TEST

START_TEST(test_should_rotate_null)
{
    ck_assert(!bowie_dht_token_should_rotate(NULL, 1000u));
}
END_TEST

START_TEST(test_should_rotate_zero_interval)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 0u, 1000u);
    ck_assert(!bowie_dht_token_should_rotate(&s, 100000u));
}
END_TEST

START_TEST(test_should_rotate_before_interval)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    ck_assert(!bowie_dht_token_should_rotate(&s, 50000u));
}
END_TEST

START_TEST(test_should_rotate_at_interval)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    ck_assert(bowie_dht_token_should_rotate(&s, 61000u));
}
END_TEST

START_TEST(test_should_rotate_after_interval)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    ck_assert(bowie_dht_token_should_rotate(&s, 100000u));
}
END_TEST

START_TEST(test_should_rotate_clock_backwards)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 100000u);
    ck_assert(!bowie_dht_token_should_rotate(&s, 50000u));
}
END_TEST

/*
 * ============================================================================
 * GENERATE
 * ============================================================================
 */

START_TEST(test_generate_null)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    bowie_dht_token_t t;

    ck_assert_int_eq(
        bowie_dht_token_generate(NULL, &a, &t),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_token_generate(&s, NULL, &t),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_token_generate(&s, &a, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_generate_unset_state)
{
    bowie_dht_token_state_t s;
    memset(&s, 0, sizeof(s));

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    bowie_dht_token_t t;

    ck_assert_int_eq(
        bowie_dht_token_generate(&s, &a, &t),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_generate_ipv6_rejected)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr6(&a);
    bowie_dht_token_t t;

    ck_assert_int_eq(
        bowie_dht_token_generate(&s, &a, &t),
        BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_generate_ok)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));

    ck_assert_int_eq(bowie_dht_token_generate(&s, &a, &t),
                     BOWIE_OK);
    ck_assert_uint_eq(t.len, 20u);

    int all_zero = 1;
    for (size_t i = 0u; i < t.len; i++) {
        if (t.bytes[i] != 0u) {
            all_zero = 0;
        }
    }
    ck_assert(!all_zero);
}
END_TEST

START_TEST(test_generate_different_addr_different_token)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a1;
    make_addr4(&a1, 1u, 6881u);
    bowie_addr_t a2;
    make_addr4(&a2, 2u, 6881u);

    bowie_dht_token_t t1;
    bowie_dht_token_t t2;
    (void)bowie_dht_token_generate(&s, &a1, &t1);
    (void)bowie_dht_token_generate(&s, &a2, &t2);

    ck_assert_int_ne(
        memcmp(t1.bytes, t2.bytes, t1.len), 0);
}
END_TEST

START_TEST(test_generate_different_port_different_token)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a1;
    make_addr4(&a1, 1u, 6881u);
    bowie_addr_t a2;
    make_addr4(&a2, 1u, 6882u);

    bowie_dht_token_t t1;
    bowie_dht_token_t t2;
    (void)bowie_dht_token_generate(&s, &a1, &t1);
    (void)bowie_dht_token_generate(&s, &a2, &t2);

    ck_assert_int_ne(
        memcmp(t1.bytes, t2.bytes, t1.len), 0);
}
END_TEST

START_TEST(test_generate_same_addr_same_token)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t1;
    bowie_dht_token_t t2;
    (void)bowie_dht_token_generate(&s, &a, &t1);
    (void)bowie_dht_token_generate(&s, &a, &t2);

    ck_assert_mem_eq(t1.bytes, t2.bytes, t1.len);
}
END_TEST

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

START_TEST(test_validate_null)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));

    ck_assert(!bowie_dht_token_validate(NULL, &a, &t));
    ck_assert(!bowie_dht_token_validate(&s, NULL, &t));
    ck_assert(!bowie_dht_token_validate(&s, &a, NULL));
}
END_TEST

START_TEST(test_validate_wrong_length)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);
    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.len = 10u;

    ck_assert(!bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_ipv6)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr6(&a);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.len = 20u;

    ck_assert(!bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_unset_state)
{
    bowie_dht_token_state_t s;
    memset(&s, 0, sizeof(s));

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    t.len = 20u;

    ck_assert(!bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_round_trip)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a, &t);

    ck_assert(bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_wrong_addr)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a1;
    make_addr4(&a1, 1u, 6881u);
    bowie_addr_t a2;
    make_addr4(&a2, 2u, 6881u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a1, &t);

    ck_assert(!bowie_dht_token_validate(&s, &a2, &t));
}
END_TEST

START_TEST(test_validate_wrong_port)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a1;
    make_addr4(&a1, 1u, 6881u);
    bowie_addr_t a2;
    make_addr4(&a2, 1u, 6882u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a1, &t);

    ck_assert(!bowie_dht_token_validate(&s, &a2, &t));
}
END_TEST

START_TEST(test_validate_corrupted_token)
{
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a, &t);

    /* Flip one bit. */
    t.bytes[0] ^= 0x01u;

    ck_assert(!bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_previous_secret)
{
    /*
     * Generate a token, then rotate once. The token was
     * generated with the old current secret, which is now
     * the previous secret. It must still validate.
     */
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a, &t);

    (void)bowie_dht_token_rotate(&s, 2000u);

    ck_assert(bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

START_TEST(test_validate_dropped_after_two_rotations)
{
    /*
     * Generate a token, then rotate twice. The original
     * secret is no longer current or previous. The token
     * must not validate.
     */
    bowie_dht_token_state_t s;
    (void)bowie_dht_token_state_init(&s, 60000u, 1000u);

    bowie_addr_t a;
    make_addr4(&a, 1u, 6881u);

    bowie_dht_token_t t;
    (void)bowie_dht_token_generate(&s, &a, &t);

    (void)bowie_dht_token_rotate(&s, 2000u);
    (void)bowie_dht_token_rotate(&s, 3000u);

    ck_assert(!bowie_dht_token_validate(&s, &a, &t));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *token_suite(void)
{
    Suite *s = suite_create("DhtToken");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null);
    tcase_add_test(tc_life, test_init_ok);
    tcase_add_test(tc_life, test_init_zero_interval);
    tcase_add_test(tc_life, test_clear);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_rot = tcase_create("Rotate");
    tcase_add_test(tc_rot, test_rotate_null);
    tcase_add_test(tc_rot, test_rotate_moves_current_to_previous);
    tcase_add_test(tc_rot, test_should_rotate_null);
    tcase_add_test(tc_rot, test_should_rotate_zero_interval);
    tcase_add_test(tc_rot, test_should_rotate_before_interval);
    tcase_add_test(tc_rot, test_should_rotate_at_interval);
    tcase_add_test(tc_rot, test_should_rotate_after_interval);
    tcase_add_test(tc_rot, test_should_rotate_clock_backwards);
    suite_add_tcase(s, tc_rot);

    TCase *tc_gen = tcase_create("Generate");
    tcase_add_test(tc_gen, test_generate_null);
    tcase_add_test(tc_gen, test_generate_unset_state);
    tcase_add_test(tc_gen, test_generate_ipv6_rejected);
    tcase_add_test(tc_gen, test_generate_ok);
    tcase_add_test(tc_gen, test_generate_different_addr_different_token);
    tcase_add_test(tc_gen, test_generate_different_port_different_token);
    tcase_add_test(tc_gen, test_generate_same_addr_same_token);
    suite_add_tcase(s, tc_gen);

    TCase *tc_val = tcase_create("Validate");
    tcase_add_test(tc_val, test_validate_null);
    tcase_add_test(tc_val, test_validate_wrong_length);
    tcase_add_test(tc_val, test_validate_ipv6);
    tcase_add_test(tc_val, test_validate_unset_state);
    tcase_add_test(tc_val, test_validate_round_trip);
    tcase_add_test(tc_val, test_validate_wrong_addr);
    tcase_add_test(tc_val, test_validate_wrong_port);
    tcase_add_test(tc_val, test_validate_corrupted_token);
    tcase_add_test(tc_val, test_validate_previous_secret);
    tcase_add_test(tc_val, test_validate_dropped_after_two_rotations);
    suite_add_tcase(s, tc_val);

    return s;
}

int main(void)
{
    Suite *s = token_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
