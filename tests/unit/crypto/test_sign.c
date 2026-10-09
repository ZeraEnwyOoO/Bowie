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
 * BOWIE — SIGN TESTS
 * ============================================================================
 *
 * Unit tests for src/crypto/sign.c.
 *
 * Every public function declared in crypto/sign.h is covered
 * here.
 *
 * The tests use a fixed keypair. The private key is a
 * 64-byte buffer whose first 32 bytes are a fixed seed and
 * whose second 32 bytes are the corresponding public key. The
 * keypair is not a standard test vector, but it is a valid
 * Ed25519 keypair. The tests check the property, not the value.
 *
 * The tests cover:
 *
 *   - Round-trip: sign and verify return BOWIE_OK.
 *   - Determinism: two signatures of the same message are
 *     identical. Ed25519 is deterministic by design.
 *   - Rejection: a corrupted signature, a corrupted message,
 *     a wrong key, and a wrong signature length are all
 *     rejected with BOWIE_ERR_SIGN_INVALID.
 *   - Public-from-private: the derived public key equals the
 *     public key embedded in the private key.
 *   - NULL handling: every required pointer is tested.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "crypto/sign.h"                 the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "crypto/sign.h"

/*
 * ============================================================================
 * FIXED KEYPAIR
 * ============================================================================
 *
 * A valid Ed25519 keypair, given as a 64-byte private key in
 * the OpenSSL form (seed || public). The public key is the
 * second half of the private key.
 *
 * The seed is a fixed pattern; the public key is derived from
 * it. The pair is not a standard test vector, but it is a
 * valid pair. The tests do not check for a specific signature
 * value; they check the properties.
 *
 * The bytes below are a real Ed25519 keypair. The seed was
 * generated once and the public key was derived from it.
 */

static const uint8_t TEST_PRIVATE_BYTES[BOWIE_SIGN_PRIVATE_LEN] = {
    /* Seed (32 bytes) */
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    /* Public key (32 bytes) */
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

static void make_private(bowie_sign_private_t *priv)
{
    memcpy(priv->bytes, TEST_PRIVATE_BYTES, BOWIE_SIGN_PRIVATE_LEN);
}

static void make_public(bowie_sign_public_t *pub)
{
    memcpy(pub->bytes,
           TEST_PRIVATE_BYTES + BOWIE_SIGN_PUBLIC_LEN,
           BOWIE_SIGN_PUBLIC_LEN);
}

/*
 * ============================================================================
 * SIGN — INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_sign_null_private)
{
    bowie_sign_signature_t sig;
    ck_assert_int_eq(
        bowie_sign_ed25519(NULL, "hi", 2, &sig),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sign_null_out)
{
    bowie_sign_private_t priv;
    make_private(&priv);
    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hi", 2, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sign_null_msg_with_len)
{
    bowie_sign_private_t priv;
    bowie_sign_signature_t sig;
    make_private(&priv);
    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, NULL, 2, &sig),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sign_null_msg_zero_len)
{
    bowie_sign_private_t priv;
    bowie_sign_signature_t sig;
    make_private(&priv);
    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, NULL, 0, &sig),
        BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * SIGN — BASIC
 * ============================================================================
 */

START_TEST(test_sign_succeeds)
{
    bowie_sign_private_t priv;
    bowie_sign_signature_t sig;
    make_private(&priv);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig),
        BOWIE_OK);
}
END_TEST

START_TEST(test_sign_deterministic)
{
    bowie_sign_private_t priv;
    bowie_sign_signature_t a;
    bowie_sign_signature_t b;
    make_private(&priv);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &a), BOWIE_OK);
    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &b), BOWIE_OK);

    ck_assert_int_eq(
        memcmp(a.bytes, b.bytes, BOWIE_SIGN_SIGNATURE_LEN), 0);
}
END_TEST

START_TEST(test_sign_different_messages_differ)
{
    bowie_sign_private_t priv;
    bowie_sign_signature_t a;
    bowie_sign_signature_t b;
    make_private(&priv);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &a), BOWIE_OK);
    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "world", 5, &b), BOWIE_OK);

    ck_assert_int_ne(
        memcmp(a.bytes, b.bytes, BOWIE_SIGN_SIGNATURE_LEN), 0);
}
END_TEST

/*
 * ============================================================================
 * VERIFY — INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_verify_null_public)
{
    bowie_sign_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(NULL, "hi", 2, &sig),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_verify_null_signature)
{
    bowie_sign_public_t pub;
    make_public(&pub);
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hi", 2, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_verify_null_msg_with_len)
{
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;
    make_public(&pub);
    memset(&sig, 0, sizeof(sig));
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, NULL, 2, &sig),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * VERIFY — ROUND TRIP
 * ============================================================================
 */

START_TEST(test_verify_roundtrip)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig), BOWIE_OK);
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hello", 5, &sig),
        BOWIE_OK);
}
END_TEST

START_TEST(test_verify_roundtrip_empty_message)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, NULL, 0, &sig), BOWIE_OK);
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, NULL, 0, &sig),
        BOWIE_OK);
}
END_TEST

START_TEST(test_verify_roundtrip_larger_message)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    uint8_t msg[256];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i & 0xFFu);
    }

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, msg, sizeof(msg), &sig),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, msg, sizeof(msg), &sig),
        BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * VERIFY — REJECTION
 * ============================================================================
 */

START_TEST(test_verify_corrupt_signature)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig), BOWIE_OK);

    /* Corrupt the signature. */
    sig.bytes[0] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hello", 5, &sig),
        BOWIE_ERR_SIGN_INVALID);
}
END_TEST

START_TEST(test_verify_corrupt_message)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig), BOWIE_OK);

    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "HELLO", 5, &sig),
        BOWIE_ERR_SIGN_INVALID);
}
END_TEST

START_TEST(test_verify_wrong_message_length)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig), BOWIE_OK);

    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hell", 4, &sig),
        BOWIE_ERR_SIGN_INVALID);
}
END_TEST

START_TEST(test_verify_wrong_public_key)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519(&priv, "hello", 5, &sig), BOWIE_OK);

    /* Corrupt the public key. */
    pub.bytes[0] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hello", 5, &sig),
        BOWIE_ERR_SIGN_INVALID);
}
END_TEST

START_TEST(test_verify_zero_signature)
{
    bowie_sign_public_t pub;
    bowie_sign_signature_t sig;

    make_public(&pub);
    memset(&sig, 0, sizeof(sig));

    ck_assert_int_eq(
        bowie_sign_ed25519_verify(&pub, "hello", 5, &sig),
        BOWIE_ERR_SIGN_INVALID);
}
END_TEST

/*
 * ============================================================================
 * PUBLIC FROM PRIVATE
 * ============================================================================
 */

START_TEST(test_public_from_private_null_priv)
{
    bowie_sign_public_t pub;
    ck_assert_int_eq(
        bowie_sign_ed25519_public_from_private(NULL, &pub),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_public_from_private_null_out)
{
    bowie_sign_private_t priv;
    make_private(&priv);
    ck_assert_int_eq(
        bowie_sign_ed25519_public_from_private(&priv, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_public_from_private_matches)
{
    bowie_sign_private_t priv;
    bowie_sign_public_t pub;
    bowie_sign_public_t derived;

    make_private(&priv);
    make_public(&pub);

    ck_assert_int_eq(
        bowie_sign_ed25519_public_from_private(&priv, &derived),
        BOWIE_OK);
    ck_assert_int_eq(
        memcmp(pub.bytes, derived.bytes, BOWIE_SIGN_PUBLIC_LEN),
        0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *sign_suite(void)
{
    Suite *s = suite_create("Sign");

    TCase *tc_sign_val = tcase_create("SignValidate");
    tcase_add_test(tc_sign_val, test_sign_null_private);
    tcase_add_test(tc_sign_val, test_sign_null_out);
    tcase_add_test(tc_sign_val, test_sign_null_msg_with_len);
    tcase_add_test(tc_sign_val, test_sign_null_msg_zero_len);
    suite_add_tcase(s, tc_sign_val);

    TCase *tc_sign = tcase_create("SignBasic");
    tcase_add_test(tc_sign, test_sign_succeeds);
    tcase_add_test(tc_sign, test_sign_deterministic);
    tcase_add_test(tc_sign, test_sign_different_messages_differ);
    suite_add_tcase(s, tc_sign);

    TCase *tc_ver_val = tcase_create("VerifyValidate");
    tcase_add_test(tc_ver_val, test_verify_null_public);
    tcase_add_test(tc_ver_val, test_verify_null_signature);
    tcase_add_test(tc_ver_val, test_verify_null_msg_with_len);
    suite_add_tcase(s, tc_ver_val);

    TCase *tc_ver_rt = tcase_create("VerifyRoundTrip");
    tcase_add_test(tc_ver_rt, test_verify_roundtrip);
    tcase_add_test(tc_ver_rt, test_verify_roundtrip_empty_message);
    tcase_add_test(tc_ver_rt, test_verify_roundtrip_larger_message);
    suite_add_tcase(s, tc_ver_rt);

    TCase *tc_ver_rej = tcase_create("VerifyRejection");
    tcase_add_test(tc_ver_rej, test_verify_corrupt_signature);
    tcase_add_test(tc_ver_rej, test_verify_corrupt_message);
    tcase_add_test(tc_ver_rej, test_verify_wrong_message_length);
    tcase_add_test(tc_ver_rej, test_verify_wrong_public_key);
    tcase_add_test(tc_ver_rej, test_verify_zero_signature);
    suite_add_tcase(s, tc_ver_rej);

    TCase *tc_pub = tcase_create("PublicFromPrivate");
    tcase_add_test(tc_pub, test_public_from_private_null_priv);
    tcase_add_test(tc_pub, test_public_from_private_null_out);
    tcase_add_test(tc_pub, test_public_from_private_matches);
    suite_add_tcase(s, tc_pub);

    return s;
}

int main(void)
{
    Suite *s = sign_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
