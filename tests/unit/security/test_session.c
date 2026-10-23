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
 * BOWIE — SECURITY: SESSION UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the session helpers declared in
 * security/session.h.
 *
 * These tests exercise the real logic: encrypt a plaintext,
 * decrypt the result, and check that the plaintext matches.
 * A tampered ciphertext must fail to decrypt. A ciphertext
 * decrypted with a different session key must fail. The
 * nonce counter must advance on every call, so a repeated
 * plaintext produces a different ciphertext.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No key exchange. The shared secret is supplied as a
 *     fixed byte string.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The tests use a fixed shared secret, not a real X25519
 * exchange. The session layer does not care where the secret
 * came from; it only runs HKDF on it. A fixed secret makes
 * the test deterministic and keeps it out of the crypto/
 * layer.
 *
 * The plaintext is a small byte array with a distinctive
 * pattern so that a truncation or a swap of bytes is visible
 * in the comparison.
 *
 * The suite is split into five cases:
 *
 *   null        — NULL arguments
 *   roundtrip   — encrypt then decrypt
 *   tamper      — modified ciphertext
 *   wrong_key   — a different shared secret
 *   unique      — the same plaintext produces different
 *                 ciphertext
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "security/session.h"    declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/session.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_secret(uint8_t *secret, size_t len, uint8_t seed)
{
    size_t i;

    for (i = 0; i < len; i++) {
        secret[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void make_plaintext(uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA0 + (uint8_t)i);
    }
}

/*
 * ============================================================================
 * NULL
 * ============================================================================
 */

START_TEST(test_session_new_null_out)
{
    uint8_t            secret[32];
    bowie_session_id_t id;
    bowie_error_t      rc;

    make_secret(secret, sizeof(secret), 0x01);
    memset(&id, 0x11, sizeof(id));

    rc = bowie_session_new(secret, sizeof(secret), &id, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_session_new_null_secret)
{
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;

    memset(&id, 0x11, sizeof(id));

    rc = bowie_session_new(NULL, 32, &id, &s);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
    ck_assert_ptr_null(s);
}
END_TEST

START_TEST(test_session_new_zero_secret_len)
{
    uint8_t            secret[32];
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;

    make_secret(secret, sizeof(secret), 0x01);
    memset(&id, 0x11, sizeof(id));

    rc = bowie_session_new(secret, 0, &id, &s);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(s);
}
END_TEST

START_TEST(test_session_new_zero_id)
{
    uint8_t            secret[32];
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;

    make_secret(secret, sizeof(secret), 0x01);
    memset(&id, 0, sizeof(id));

    rc = bowie_session_new(secret, sizeof(secret), &id, &s);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(s);
}
END_TEST

/*
 * ============================================================================
 * ROUNDTRIP
 * ============================================================================
 */

START_TEST(test_session_roundtrip)
{
    uint8_t            secret[32];
    uint8_t            plain[37];
    uint8_t            cipher[128];
    uint8_t            out[128];
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;
    size_t             cipher_len = 0;
    size_t             out_len = 0;

    make_secret(secret, sizeof(secret), 0x01);
    make_plaintext(plain, sizeof(plain));
    memset(&id, 0x22, sizeof(id));

    rc = bowie_session_new(secret, sizeof(secret), &id, &s);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(s);

    rc = bowie_session_encrypt(s, plain, sizeof(plain),
                                cipher, sizeof(cipher), &cipher_len);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(cipher_len, sizeof(plain) + BOWIE_SESSION_OVERHEAD_LEN);

    rc = bowie_session_decrypt(s, cipher, cipher_len,
                                out, sizeof(out), &out_len);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(out_len, sizeof(plain));
    ck_assert_mem_eq(out, plain, sizeof(plain));

    bowie_session_free(s);
}
END_TEST

/*
 * ============================================================================
 * TAMPER
 * ============================================================================
 */

START_TEST(test_session_tamper)
{
    uint8_t            secret[32];
    uint8_t            plain[32];
    uint8_t            cipher[128];
    uint8_t            out[128];
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;
    size_t             cipher_len = 0;
    size_t             out_len = 0;

    make_secret(secret, sizeof(secret), 0x01);
    make_plaintext(plain, sizeof(plain));
    memset(&id, 0x22, sizeof(id));

    rc = bowie_session_new(secret, sizeof(secret), &id, &s);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_session_encrypt(s, plain, sizeof(plain),
                                cipher, sizeof(cipher), &cipher_len);
    ck_assert_int_eq(rc, BOWIE_OK);

    /* Flip a bit in the ciphertext. The tag must fail. */
    cipher[BOWIE_SESSION_COUNTER_LEN] ^= 0x01;

    rc = bowie_session_decrypt(s, cipher, cipher_len,
                                out, sizeof(out), &out_len);
    ck_assert_int_eq(rc, BOWIE_ERR_CRYPTO);

    bowie_session_free(s);
}
END_TEST

START_TEST(test_session_reordering_and_replay)
{
    uint8_t secret[32], plain1[12], plain2[12];
    uint8_t cipher1[64], cipher2[64], out[64];
    bowie_session_id_t id;
    bowie_session_t *sender = NULL, *receiver = NULL;
    size_t c1_len = 0u, c2_len = 0u, out_len = 0u;

    make_secret(secret, sizeof(secret), 0x31);
    make_plaintext(plain1, sizeof(plain1));
    make_plaintext(plain2, sizeof(plain2));
    plain2[0] ^= 0x7fu;
    memset(&id, 0x52, sizeof(id));
    ck_assert_int_eq(bowie_session_new(secret, sizeof(secret), &id, &sender), BOWIE_OK);
    ck_assert_int_eq(bowie_session_new(secret, sizeof(secret), &id, &receiver), BOWIE_OK);
    ck_assert_int_eq(bowie_session_encrypt(sender, plain1, sizeof(plain1), cipher1, sizeof(cipher1), &c1_len), BOWIE_OK);
    ck_assert_int_eq(bowie_session_encrypt(sender, plain2, sizeof(plain2), cipher2, sizeof(cipher2), &c2_len), BOWIE_OK);

    ck_assert_int_eq(bowie_session_decrypt(receiver, cipher2, c2_len, out, sizeof(out), &out_len), BOWIE_OK);
    ck_assert_mem_eq(out, plain2, sizeof(plain2));
    ck_assert_int_eq(bowie_session_decrypt(receiver, cipher1, c1_len, out, sizeof(out), &out_len), BOWIE_OK);
    ck_assert_mem_eq(out, plain1, sizeof(plain1));
    ck_assert_int_eq(bowie_session_decrypt(receiver, cipher1, c1_len, out, sizeof(out), &out_len), BOWIE_ERR_PERMISSION);

    bowie_session_free(sender);
    bowie_session_free(receiver);
}
END_TEST

/*
 * ============================================================================
 * WRONG KEY
 * ============================================================================
 */

START_TEST(test_session_wrong_key)
{
    uint8_t            secret1[32];
    uint8_t            secret2[32];
    uint8_t            plain[32];
    uint8_t            cipher[128];
    uint8_t            out[128];
    bowie_session_id_t id;
    bowie_session_t   *s1 = NULL;
    bowie_session_t   *s2 = NULL;
    bowie_error_t      rc;
    size_t             cipher_len = 0;
    size_t             out_len = 0;

    make_secret(secret1, sizeof(secret1), 0x01);
    make_secret(secret2, sizeof(secret2), 0x99);
    make_plaintext(plain, sizeof(plain));
    memset(&id, 0x22, sizeof(id));

    rc = bowie_session_new(secret1, sizeof(secret1), &id, &s1);
    ck_assert_int_eq(rc, BOWIE_OK);
    rc = bowie_session_new(secret2, sizeof(secret2), &id, &s2);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_session_encrypt(s1, plain, sizeof(plain),
                                cipher, sizeof(cipher), &cipher_len);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_session_decrypt(s2, cipher, cipher_len,
                                out, sizeof(out), &out_len);
    ck_assert_int_eq(rc, BOWIE_ERR_CRYPTO);

    bowie_session_free(s1);
    bowie_session_free(s2);
}
END_TEST

/*
 * ============================================================================
 * UNIQUE
 * ============================================================================
 */

START_TEST(test_session_unique)
{
    uint8_t            secret[32];
    uint8_t            plain[32];
    uint8_t            cipher1[128];
    uint8_t            cipher2[128];
    bowie_session_id_t id;
    bowie_session_t   *s = NULL;
    bowie_error_t      rc;
    size_t             cipher1_len = 0;
    size_t             cipher2_len = 0;

    make_secret(secret, sizeof(secret), 0x01);
    make_plaintext(plain, sizeof(plain));
    memset(&id, 0x22, sizeof(id));

    rc = bowie_session_new(secret, sizeof(secret), &id, &s);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_session_encrypt(s, plain, sizeof(plain),
                                cipher1, sizeof(cipher1), &cipher1_len);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_session_encrypt(s, plain, sizeof(plain),
                                cipher2, sizeof(cipher2), &cipher2_len);
    ck_assert_int_eq(rc, BOWIE_OK);

    /*
     * The nonce counter advances, so the two ciphertexts must
     * differ even though the plaintext is the same.
     */
    ck_assert_uint_eq(cipher1_len, cipher2_len);
    ck_assert_int_ne(memcmp(cipher1, cipher2, cipher1_len), 0);

    bowie_session_free(s);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *session_suite(void)
{
    Suite *s;
    TCase *tc_null;
    TCase *tc_roundtrip;
    TCase *tc_tamper;
    TCase *tc_wrong_key;
    TCase *tc_unique;
    TCase *tc_replay;

    s = suite_create("SecuritySession");

    tc_null = tcase_create("Null");
    tcase_add_test(tc_null, test_session_new_null_out);
    tcase_add_test(tc_null, test_session_new_null_secret);
    tcase_add_test(tc_null, test_session_new_zero_secret_len);
    tcase_add_test(tc_null, test_session_new_zero_id);
    suite_add_tcase(s, tc_null);

    tc_roundtrip = tcase_create("Roundtrip");
    tcase_add_test(tc_roundtrip, test_session_roundtrip);
    suite_add_tcase(s, tc_roundtrip);

    tc_tamper = tcase_create("Tamper");
    tcase_add_test(tc_tamper, test_session_tamper);
    suite_add_tcase(s, tc_tamper);

    tc_wrong_key = tcase_create("WrongKey");
    tcase_add_test(tc_wrong_key, test_session_wrong_key);
    suite_add_tcase(s, tc_wrong_key);

    tc_unique = tcase_create("Unique");
    tcase_add_test(tc_unique, test_session_unique);
    suite_add_tcase(s, tc_unique);

    tc_replay = tcase_create("ReplayWindow");
    tcase_add_test(tc_replay, test_session_reordering_and_replay);
    suite_add_tcase(s, tc_replay);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = session_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
