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
 * BOWIE — KEYPAIR TESTS
 * ============================================================================
 *
 * Unit tests for src/crypto/keypair.c.
 *
 * Every public function declared in crypto/keypair.h is
 * covered here.
 *
 * The tests use freshly generated keypairs. X25519 key
 * generation is not deterministic, so a test that compared
 * two keypairs would not test anything. The tests check the
 * properties of the operation:
 *
 *   - Generation produces non-zero keys.
 *   - Two generations produce different keys.
 *   - The public key derived from a private key matches the
 *     public key of the same keypair.
 *   - The shared secret is symmetric: Alice's secret with
 *     Bob's public equals Bob's secret with Alice's public.
 *   - The shared secret is not all zeros.
 *   - A different pair of keys produces a different secret.
 *
 * The tests also cover NULL handling for every required
 * pointer.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "crypto/keypair.h"              the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "crypto/keypair.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static int is_all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * ============================================================================
 * GENERATE — INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_generate_null_public)
{
    bowie_keypair_private_t priv;
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(NULL, &priv),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_generate_null_private)
{
    bowie_keypair_public_t pub;
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_generate_null_both)
{
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(NULL, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * GENERATE — BASIC
 * ============================================================================
 */

START_TEST(test_generate_succeeds)
{
    bowie_keypair_public_t pub;
    bowie_keypair_private_t priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub, &priv),
        BOWIE_OK);
}
END_TEST

START_TEST(test_generate_nonzero)
{
    bowie_keypair_public_t pub;
    bowie_keypair_private_t priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub, &priv),
        BOWIE_OK);

    ck_assert(!is_all_zero(pub.bytes, BOWIE_KEYPAIR_PUBLIC_LEN));
    ck_assert(!is_all_zero(priv.bytes, BOWIE_KEYPAIR_PRIVATE_LEN));
}
END_TEST

START_TEST(test_generate_two_differ)
{
    bowie_keypair_public_t pub1;
    bowie_keypair_private_t priv1;
    bowie_keypair_public_t pub2;
    bowie_keypair_private_t priv2;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub1, &priv1),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub2, &priv2),
        BOWIE_OK);

    ck_assert_int_ne(
        memcmp(pub1.bytes, pub2.bytes, BOWIE_KEYPAIR_PUBLIC_LEN),
        0);
    ck_assert_int_ne(
        memcmp(priv1.bytes, priv2.bytes, BOWIE_KEYPAIR_PRIVATE_LEN),
        0);
}
END_TEST

/*
 * ============================================================================
 * PUBLIC FROM PRIVATE — INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_pub_from_priv_null_private)
{
    bowie_keypair_public_t pub;
    ck_assert_int_eq(
        bowie_keypair_x25519_public_from_private(NULL, &pub),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_pub_from_priv_null_out)
{
    bowie_keypair_private_t priv;
    memset(&priv, 0, sizeof(priv));
    ck_assert_int_eq(
        bowie_keypair_x25519_public_from_private(&priv, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * PUBLIC FROM PRIVATE — BASIC
 * ============================================================================
 */

START_TEST(test_pub_from_priv_matches_generated)
{
    bowie_keypair_public_t pub;
    bowie_keypair_private_t priv;
    bowie_keypair_public_t derived;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub, &priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_public_from_private(&priv, &derived),
        BOWIE_OK);

    ck_assert_int_eq(
        memcmp(pub.bytes, derived.bytes, BOWIE_KEYPAIR_PUBLIC_LEN),
        0);
}
END_TEST

START_TEST(test_pub_from_priv_deterministic)
{
    bowie_keypair_public_t pub;
    bowie_keypair_private_t priv;
    bowie_keypair_public_t a;
    bowie_keypair_public_t b;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&pub, &priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_public_from_private(&priv, &a),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_public_from_private(&priv, &b),
        BOWIE_OK);

    ck_assert_int_eq(
        memcmp(a.bytes, b.bytes, BOWIE_KEYPAIR_PUBLIC_LEN),
        0);
}
END_TEST

/*
 * ============================================================================
 * SHARED — INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_shared_null_private)
{
    bowie_keypair_public_t pub;
    bowie_keypair_shared_t shared;
    memset(&pub, 0, sizeof(pub));
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(NULL, &pub, &shared),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_shared_null_public)
{
    bowie_keypair_private_t priv;
    bowie_keypair_shared_t shared;
    memset(&priv, 0, sizeof(priv));
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&priv, NULL, &shared),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_shared_null_out)
{
    bowie_keypair_private_t priv;
    bowie_keypair_public_t pub;
    memset(&priv, 0, sizeof(priv));
    memset(&pub, 0, sizeof(pub));
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&priv, &pub, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * SHARED — SYMMETRY
 * ============================================================================
 *
 * The defining property of Diffie-Hellman: the secret derived
 * from (Alice_private, Bob_public) equals the secret derived
 * from (Bob_private, Alice_public).
 */

START_TEST(test_shared_symmetric)
{
    bowie_keypair_public_t alice_pub;
    bowie_keypair_private_t alice_priv;
    bowie_keypair_public_t bob_pub;
    bowie_keypair_private_t bob_priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&alice_pub, &alice_priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&bob_pub, &bob_priv),
        BOWIE_OK);

    bowie_keypair_shared_t alice_shared;
    bowie_keypair_shared_t bob_shared;

    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &bob_pub,
                                     &alice_shared),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&bob_priv, &alice_pub,
                                     &bob_shared),
        BOWIE_OK);

    ck_assert_int_eq(
        memcmp(alice_shared.bytes, bob_shared.bytes,
               BOWIE_KEYPAIR_SHARED_LEN),
        0);
}
END_TEST

START_TEST(test_shared_not_zero)
{
    bowie_keypair_public_t alice_pub;
    bowie_keypair_private_t alice_priv;
    bowie_keypair_public_t bob_pub;
    bowie_keypair_private_t bob_priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&alice_pub, &alice_priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&bob_pub, &bob_priv),
        BOWIE_OK);

    bowie_keypair_shared_t shared;
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &bob_pub,
                                     &shared),
        BOWIE_OK);

    ck_assert(!is_all_zero(shared.bytes, BOWIE_KEYPAIR_SHARED_LEN));
}
END_TEST

START_TEST(test_shared_different_pairs_differ)
{
    bowie_keypair_public_t alice_pub;
    bowie_keypair_private_t alice_priv;
    bowie_keypair_public_t bob_pub;
    bowie_keypair_private_t bob_priv;
    bowie_keypair_public_t carol_pub;
    bowie_keypair_private_t carol_priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&alice_pub, &alice_priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&bob_pub, &bob_priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&carol_pub, &carol_priv),
        BOWIE_OK);

    bowie_keypair_shared_t alice_bob;
    bowie_keypair_shared_t alice_carol;

    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &bob_pub,
                                     &alice_bob),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &carol_pub,
                                     &alice_carol),
        BOWIE_OK);

    ck_assert_int_ne(
        memcmp(alice_bob.bytes, alice_carol.bytes,
               BOWIE_KEYPAIR_SHARED_LEN),
        0);
}
END_TEST

START_TEST(test_shared_deterministic)
{
    bowie_keypair_public_t alice_pub;
    bowie_keypair_private_t alice_priv;
    bowie_keypair_public_t bob_pub;
    bowie_keypair_private_t bob_priv;

    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&alice_pub, &alice_priv),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_generate(&bob_pub, &bob_priv),
        BOWIE_OK);

    bowie_keypair_shared_t a;
    bowie_keypair_shared_t b;

    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &bob_pub, &a),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_keypair_x25519_shared(&alice_priv, &bob_pub, &b),
        BOWIE_OK);

    ck_assert_int_eq(
        memcmp(a.bytes, b.bytes, BOWIE_KEYPAIR_SHARED_LEN),
        0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *keypair_suite(void)
{
    Suite *s = suite_create("Keypair");

    TCase *tc_gen_val = tcase_create("GenerateValidate");
    tcase_add_test(tc_gen_val, test_generate_null_public);
    tcase_add_test(tc_gen_val, test_generate_null_private);
    tcase_add_test(tc_gen_val, test_generate_null_both);
    suite_add_tcase(s, tc_gen_val);

    TCase *tc_gen = tcase_create("GenerateBasic");
    tcase_add_test(tc_gen, test_generate_succeeds);
    tcase_add_test(tc_gen, test_generate_nonzero);
    tcase_add_test(tc_gen, test_generate_two_differ);
    suite_add_tcase(s, tc_gen);

    TCase *tc_pub_val = tcase_create("PublicFromPrivateValidate");
    tcase_add_test(tc_pub_val, test_pub_from_priv_null_private);
    tcase_add_test(tc_pub_val, test_pub_from_priv_null_out);
    suite_add_tcase(s, tc_pub_val);

    TCase *tc_pub = tcase_create("PublicFromPrivateBasic");
    tcase_add_test(tc_pub, test_pub_from_priv_matches_generated);
    tcase_add_test(tc_pub, test_pub_from_priv_deterministic);
    suite_add_tcase(s, tc_pub);

    TCase *tc_sh_val = tcase_create("SharedValidate");
    tcase_add_test(tc_sh_val, test_shared_null_private);
    tcase_add_test(tc_sh_val, test_shared_null_public);
    tcase_add_test(tc_sh_val, test_shared_null_out);
    suite_add_tcase(s, tc_sh_val);

    TCase *tc_sh = tcase_create("SharedSymmetry");
    tcase_add_test(tc_sh, test_shared_symmetric);
    tcase_add_test(tc_sh, test_shared_not_zero);
    tcase_add_test(tc_sh, test_shared_different_pairs_differ);
    tcase_add_test(tc_sh, test_shared_deterministic);
    suite_add_tcase(s, tc_sh);

    return s;
}

int main(void)
{
    Suite *s = keypair_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
