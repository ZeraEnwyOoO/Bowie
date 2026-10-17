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
 * BOWIE — SECURITY: PERMISSION UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the permission check declared in
 * security/permission.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The tests use OpenSSL directly to generate an Ed25519 keypair
 * and to sign a challenge. The signature is then passed to the
 * permission check.
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
 *   "security/sign.h"       bowie_security_sign
 *   "security/grant.h"      grant helpers
 *   "security/ownership.h"  proof of ownership
 *   "security/revoke.h"     revocation list
 *   "security/permission.h" declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>
#include <openssl/evp.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/sign.h"
#include "security/grant.h"
#include "security/ownership.h"
#include "security/revoke.h"
#include "security/permission.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static int generate_ed25519_keypair(bowie_sign_public_t *pub,
                                     bowie_sign_private_t *priv)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *pkey;
    size_t        pub_len = BOWIE_SIGN_PUBLIC_LEN;
    size_t        priv_len = BOWIE_SIGN_PRIVATE_LEN;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) return 0;

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

static void public_id_from_sign(const bowie_sign_public_t *pub,
                                bowie_public_id_t *out)
{
    memcpy(out->bytes, pub->bytes, BOWIE_PUBLIC_ID_LEN);
}

static void peer_id_from_public(const bowie_public_id_t *pub,
                                bowie_peer_id_t *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->bytes, pub->bytes, BOWIE_PEER_ID_LEN);
    if (bowie_peer_id_is_zero(out)) {
        out->bytes[0] = 1;
    }
}

static void make_grant(bowie_grant_t *g,
                       const bowie_public_id_t *issuer,
                       const bowie_peer_id_t *subject,
                       uint32_t capability)
{
    bowie_grant_clear(g);

    memcpy(&g->issuer, issuer, sizeof(*issuer));
    memcpy(&g->subject, subject, sizeof(*subject));

    memset(g->grant_id.bytes, 0x42, sizeof(g->grant_id.bytes));
    if (bowie_grant_id_is_zero(&g->grant_id)) {
        g->grant_id.bytes[0] = 1;
    }

    g->permissions = capability;
    g->issued_at   = 1000;
    g->expires_at  = 2000;
}

/*
 * ============================================================================
 * NULL
 * ============================================================================
 */

START_TEST(test_permission_null_grant)
{
    bowie_public_id_t   owner;
    bowie_peer_id_t     subject;
    bowie_revoke_list_t revoke;
    uint8_t             challenge[32] = {0};
    uint8_t             signature[64] = {0};
    bowie_span_t        c;
    bowie_span_t        s;
    bowie_error_t       rc;

    memset(&owner, 0xAA, sizeof(owner));
    memset(&subject, 0xBB, sizeof(subject));
    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = signature;
    s.len  = sizeof(signature);

    rc = bowie_permission_check_list(NULL, &owner, &revoke,
                                      0x01, &subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * OWNER
 * ============================================================================
 */

START_TEST(test_permission_owner_mismatch)
{
    bowie_sign_public_t pub1, pub2;
    bowie_sign_private_t priv1, priv2;
    bowie_public_id_t   owner;
    bowie_public_id_t   other;
    bowie_peer_id_t     subject;
    bowie_grant_t       grant;
    bowie_revoke_list_t revoke;
    uint8_t             challenge[32] = {0};
    uint8_t             signature[64] = {0};
    bowie_span_t        c;
    bowie_span_t        s;
    bowie_error_t       rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub1, &priv1), 1);
    ck_assert_int_eq(generate_ed25519_keypair(&pub2, &priv2), 1);

    public_id_from_sign(&pub1, &owner);
    public_id_from_sign(&pub2, &other);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);
    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = signature;
    s.len  = sizeof(signature);

    rc = bowie_permission_check_list(&grant, &other, &revoke,
                                      0x01, &subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_ERR_OWNER_MISMATCH);
}
END_TEST

/*
 * ============================================================================
 * EXPIRED
 * ============================================================================
 */

START_TEST(test_permission_expired)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_peer_id_t        subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);

    public_id_from_sign(&pub, &owner);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_list(&grant, &owner, &revoke,
                                      0x01, &subject, c, s, 3000);

    ck_assert_int_eq(rc, BOWIE_ERR_GRANT_EXPIRED);
}
END_TEST

/*
 * ============================================================================
 * REVOKED
 * ============================================================================
 */

START_TEST(test_permission_revoked)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_peer_id_t        subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);

    public_id_from_sign(&pub, &owner);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);
    bowie_revoke_list_add(&revoke, &grant.grant_id);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_list(&grant, &owner, &revoke,
                                      0x01, &subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_ERR_GRANT_REVOKED);
}
END_TEST

/*
 * ============================================================================
 * CAPABILITY
 * ============================================================================
 */

START_TEST(test_permission_capability)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_peer_id_t        subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);

    public_id_from_sign(&pub, &owner);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_list(&grant, &owner, &revoke,
                                      0x02, &subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_ERR_PERMISSION);
}
END_TEST

/*
 * ============================================================================
 * SUBJECT
 * ============================================================================
 */

START_TEST(test_permission_subject_mismatch)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_public_t    pub_other;
    bowie_sign_private_t   priv_other;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_public_id_t      other_public;
    bowie_peer_id_t        subject;
    bowie_peer_id_t        wrong_subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);
    ck_assert_int_eq(generate_ed25519_keypair(&pub_other, &priv_other), 1);

    public_id_from_sign(&pub, &owner);
    public_id_from_sign(&pub_other, &other_public);
    peer_id_from_public(&owner, &subject);
    peer_id_from_public(&other_public, &wrong_subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_list(&grant, &owner, &revoke,
                                      0x01, &wrong_subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_ERR_SUBJECT_MISMATCH);
}
END_TEST

START_TEST(test_permission_valid)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_peer_id_t        subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);

    public_id_from_sign(&pub, &owner);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_list(&grant, &owner, &revoke,
                                      0x01, &subject, c, s, 1500);

    ck_assert_int_eq(rc, BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

START_TEST(test_permission_check_and_bind_null_session)
{
    bowie_sign_public_t    pub;
    bowie_sign_private_t   priv;
    bowie_sign_signature_t sig;
    bowie_public_id_t      owner;
    bowie_peer_id_t        subject;
    bowie_grant_t          grant;
    bowie_revoke_list_t    revoke;
    uint8_t                challenge[32] = {0};
    bowie_span_t           c;
    bowie_span_t           s;
    bowie_error_t          rc;

    memset(challenge, 0xAA, sizeof(challenge));

    ck_assert_int_eq(generate_ed25519_keypair(&pub, &priv), 1);

    public_id_from_sign(&pub, &owner);
    peer_id_from_public(&owner, &subject);

    make_grant(&grant, &owner, &subject, 0x01);

    rc = bowie_security_sign(&priv, challenge, sizeof(challenge), &sig);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_revoke_list_clear(&revoke);

    c.data = challenge;
    c.len  = sizeof(challenge);
    s.data = sig.bytes;
    s.len  = sizeof(sig.bytes);

    rc = bowie_permission_check_and_bind(&grant, &owner, &revoke,
                                          0x01, &subject, c, s, 1500,
                                          NULL);

    ck_assert_int_eq(rc, BOWIE_OK);
}
END_TEST

START_TEST(test_permission_error_string_ok)
{
    const char *s = bowie_permission_error_string(BOWIE_OK);

    ck_assert_ptr_nonnull(s);
    ck_assert_str_eq(s, "ok");
}
END_TEST

START_TEST(test_permission_error_string_unknown)
{
    const char *s = bowie_permission_error_string((bowie_error_t)-9999);

    ck_assert_ptr_nonnull(s);
    ck_assert_str_eq(s, "unknown permission error");
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *permission_suite(void)
{
    Suite *s;
    TCase *tc_null;
    TCase *tc_owner;
    TCase *tc_expired;
    TCase *tc_revoked;
    TCase *tc_capability;
    TCase *tc_subject;
    TCase *tc_helpers;

    s = suite_create("SecurityPermission");

    tc_null = tcase_create("Null");
    tcase_add_test(tc_null, test_permission_null_grant);
    suite_add_tcase(s, tc_null);

    tc_owner = tcase_create("Owner");
    tcase_add_test(tc_owner, test_permission_owner_mismatch);
    suite_add_tcase(s, tc_owner);

    tc_expired = tcase_create("Expired");
    tcase_add_test(tc_expired, test_permission_expired);
    suite_add_tcase(s, tc_expired);

    tc_revoked = tcase_create("Revoked");
    tcase_add_test(tc_revoked, test_permission_revoked);
    suite_add_tcase(s, tc_revoked);

    tc_capability = tcase_create("Capability");
    tcase_add_test(tc_capability, test_permission_capability);
    suite_add_tcase(s, tc_capability);

    tc_subject = tcase_create("Subject");
    tcase_add_test(tc_subject, test_permission_subject_mismatch);
    tcase_add_test(tc_subject, test_permission_valid);
    suite_add_tcase(s, tc_subject);

    tc_helpers = tcase_create("Helpers");
    tcase_add_test(tc_helpers, test_permission_check_and_bind_null_session);
    tcase_add_test(tc_helpers, test_permission_error_string_ok);
    tcase_add_test(tc_helpers, test_permission_error_string_unknown);
    suite_add_tcase(s, tc_helpers);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = permission_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
