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
 * BOWIE — SECURITY: OWNERSHIP UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the Proof of Ownership helpers declared in
 * security/ownership.h.
 *
 * These tests exercise the real logic: a signature over a
 * challenge, produced with a real Ed25519 key, must verify
 * against the matching public key. A signature over a
 * different challenge must not verify. A signature produced
 * with a different key must not verify.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No key storage.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The tests use OpenSSL directly to generate an Ed25519 keypair
 * and to sign a challenge. The signature is then passed to
 * bowie_ownership_verify() and the result is checked. This is
 * the strongest test short of a network test.
 *
 * The suite is split into three cases:
 *
 *   null        — NULL arguments
 *   valid       — a correct signature
 *   invalid     — wrong challenge, wrong key, wrong length
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset, memcpy
 *   <openssl/evp.h>         EVP_PKEY, EVP_MD_CTX, EVP_DigestSign
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "crypto/sign.h"         Ed25519 signing and verification
 *   "security/ownership.h"  declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>
#include <openssl/evp.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "crypto/sign.h"
#include "security/ownership.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Generate an Ed25519 keypair using OpenSSL directly.
 */
static int generate_ed25519_keypair(bowie_sign_public_t *pub,
                                     bowie_sign_private_t *priv)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *pkey;
    size_t        pub_len = BOWIE_SIGN_PUBLIC_LEN;
    size_t        priv_len = BOWIE_SIGN_PRIVATE_LEN;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);

    if (EVP_PKEY_get_raw_public_key(pkey, pub->bytes, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_PKEY_get_raw_private_key(pkey, priv->bytes, &priv_len) != 1) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);

    return (pub_len == BOWIE_SIGN_PUBLIC_LEN &&
            priv_len == BOWIE_SIGN_PRIVATE_LEN) ? 1 : 0;
}

/*
 * Build a bowie_public_id_t from a bowie_sign_public_t.
 */
static void public_id_from_sign(const bowie_sign_public_t *pub,
                                bowie_public_id_t *out)
{
    memcpy(out->bytes, pub->bytes, BOWIE_PUBLIC_ID_LEN);
}

/*
 * ============================================================================
 * NULL
 * ============================================================================
 */

START_TEST(test_ownership_verify_null_public)
{
    uint8_t       challenge[32] = {0};
    bowie_span_t  c;
    bowie_span_t  s;
    bowie_error_t rc;

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = NULL;
    s.len  = 0;

    rc = bowie_ownership_verify(NULL, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_ownership_verify_null_challenge)
{
    bowie_public_id_t id;
    bowie_span_t      c;
    bowie_span_t      s;
    bowie_error_t     rc;

    memset(&id, 0, sizeof(id));
    c.data = NULL;
    c.len  = 32;
    s.data = NULL;
    s.len  = 0;

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_ownership_verify_zero_challenge)
{
    bowie_public_id_t id;
    bowie_span_t      c;
    bowie_span_t      s;
    bowie_error_t     rc;

    memset(&id, 0, sizeof(id));
    c.data = NULL;
    c.len  = 0;
    s.data = NULL;
    s.len  = 0;

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_ownership_verify_wrong_sig_len)
{
    bowie_public_id_t id;
    uint8_t           challenge[32] = {0};
    uint8_t           signature[10] = {0};
    bowie_span_t      c;
    bowie_span_t      s;
    bowie_error_t     rc;

    memset(&id, 0, sizeof(id));
    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = signature;
    s.len  = sizeof(signature);

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_SIGN_INVALID);
}
END_TEST

/*
 * ============================================================================
 * VALID
 * ============================================================================
 */

START_TEST(test_ownership_verify_valid)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      id;
    uint8_t                challenge[32];
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);
    public_id_from_sign(&pub, &id);

    rc = bowie_sign_ed25519(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * INVALID
 * ============================================================================
 */

START_TEST(test_ownership_verify_wrong_challenge)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      id;
    uint8_t                challenge[32];
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);
    public_id_from_sign(&pub, &id);

    rc = bowie_sign_ed25519(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    challenge[0] ^= 0x01;

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_SIGN_INVALID);
}
END_TEST

START_TEST(test_ownership_verify_wrong_key)
{
    bowie_sign_public_t    pub1, pub2;
    bowie_sign_private_t   priv1, priv2;
    bowie_sign_signature_t sig;
    bowie_public_id_t      id;
    uint8_t                challenge[32];
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub1, &priv1), 1);
    ck_assert_int_eq(generate_ed25519_keypair(&pub2, &priv2), 1);

    public_id_from_sign(&pub1, &id);

    rc = bowie_sign_ed25519(&priv2, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_ownership_verify(&id, c, s);

    ck_assert_int_eq(rc, BOWIE_ERR_SIGN_INVALID);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *ownership_suite(void)
{
    Suite *s;
    TCase *tc_null;
    TCase *tc_valid;
    TCase *tc_invalid;

    s = suite_create("SecurityOwnership");

    tc_null = tcase_create("Null");
    tcase_add_test(tc_null, test_ownership_verify_null_public);
    tcase_add_test(tc_null, test_ownership_verify_null_challenge);
    tcase_add_test(tc_null, test_ownership_verify_zero_challenge);
    tcase_add_test(tc_null, test_ownership_verify_wrong_sig_len);
    suite_add_tcase(s, tc_null);

    tc_valid = tcase_create("Valid");
    tcase_add_test(tc_valid, test_ownership_verify_valid);
    suite_add_tcase(s, tc_valid);

    tc_invalid = tcase_create("Invalid");
    tcase_add_test(tc_invalid, test_ownership_verify_wrong_challenge);
    tcase_add_test(tc_invalid, test_ownership_verify_wrong_key);
    suite_add_tcase(s, tc_invalid);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = ownership_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
