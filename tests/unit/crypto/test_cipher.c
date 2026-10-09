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
 * BOWIE — CIPHER TESTS
 * ============================================================================
 *
 * Unit tests for src/crypto/cipher.c.
 *
 * Every public function declared in crypto/cipher.h is covered
 * here.
 *
 * The cipher functions are deterministic for a fixed key and
 * nonce. A test that encrypts and decrypts a known plaintext
 * and checks that the result matches the plaintext is a real
 * test of the round-trip property. A test that encrypts a
 * random plaintext and compares it to itself would not test
 * anything.
 *
 * GCM is authenticated, so the tests also cover tag
 * verification: a corrupted tag must be rejected, and a
 * corrupted ciphertext must be rejected. The tag tests are the
 * most important part of the GCM suite; a GCM implementation
 * that does not reject a bad tag is not a GCM implementation.
 *
 * CTR is a stream cipher, so the round-trip property is the
 * only thing to test. There is no tag.
 *
 * The tests do not use a fixed key or nonce from a standard.
 * The values are chosen to be obvious in a debugger: a key of
 * 0x00..0x1F, a nonce of 0x00..0x0B (GCM) or 0x00..0x0F
 * (CTR). The choice is arbitrary; the property under test does
 * not depend on the values.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "crypto/cipher.h"               the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "crypto/cipher.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_key(uint8_t key[BOWIE_CIPHER_KEY_LEN])
{
    for (size_t i = 0; i < BOWIE_CIPHER_KEY_LEN; i++) {
        key[i] = (uint8_t)i;
    }
}

static void make_gcm_nonce(uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN])
{
    for (size_t i = 0; i < BOWIE_CIPHER_GCM_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)i;
    }
}

static void make_ctr_nonce(uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN])
{
    for (size_t i = 0; i < BOWIE_CIPHER_CTR_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)i;
    }
}

/*
 * ============================================================================
 * GCM — ENCRYPT INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_gcm_encrypt_null_key)
{
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t out[64];
    size_t out_len = 0;

    make_gcm_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(NULL, nonce,
                                         NULL, 0,
                                         "hi", 2,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_gcm_encrypt_null_nonce)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t out[64];
    size_t out_len = 0;

    make_key(key);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, NULL,
                                         NULL, 0,
                                         "hi", 2,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_gcm_encrypt_null_out)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    size_t out_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         "hi", 2,
                                         NULL, 64, &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_gcm_encrypt_null_out_len)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t out[64];

    make_key(key);
    make_gcm_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         "hi", 2,
                                         out, sizeof(out), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_gcm_encrypt_output_too_small)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t out[8];
    size_t out_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    /*
     * The output for "hi" needs 2 + 16 = 18 bytes; only 8
     * are available.
     */
    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         "hi", 2,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

/*
 * ============================================================================
 * GCM — ROUND TRIP
 * ============================================================================
 */

START_TEST(test_gcm_roundtrip_small)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *msg = "hello";
    size_t msg_len = 5;

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         msg, msg_len,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, msg_len + BOWIE_CIPHER_TAG_LEN);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_uint_eq(pt_len, msg_len);
    ck_assert_int_eq(memcmp(pt, msg, msg_len), 0);
}
END_TEST

START_TEST(test_gcm_roundtrip_empty)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         NULL, 0,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, BOWIE_CIPHER_TAG_LEN);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_uint_eq(pt_len, 0u);
}
END_TEST

START_TEST(test_gcm_roundtrip_with_aad)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *aad = "header";
    const char *msg = "payload";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         aad, 6,
                                         msg, 7,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         aad, 6,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_int_eq(memcmp(pt, msg, 7), 0);
}
END_TEST

/*
 * ============================================================================
 * GCM — TAG VERIFICATION
 * ============================================================================
 */

START_TEST(test_gcm_decrypt_corrupt_tag)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *msg = "hello";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         msg, 5,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    /* Corrupt the last byte of the tag. */
    ct[ct_len - 1] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

START_TEST(test_gcm_decrypt_corrupt_ciphertext)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *msg = "hello";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         msg, 5,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    /* Corrupt the first byte of the ciphertext. */
    ct[0] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

START_TEST(test_gcm_decrypt_wrong_key)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *msg = "hello";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         msg, 5,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    /* Change the key. */
    key[0] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

START_TEST(test_gcm_decrypt_wrong_nonce)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *msg = "hello";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         NULL, 0,
                                         msg, 5,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    /* Change the nonce. */
    nonce[0] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

START_TEST(test_gcm_decrypt_wrong_aad)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    const char *aad = "header";
    const char *msg = "payload";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_encrypt(key, nonce,
                                         aad, 6,
                                         msg, 7,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);

    /* Use a different AAD on decrypt. */
    const char *wrong_aad = "HEADER";

    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         wrong_aad, 6,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

START_TEST(test_gcm_decrypt_short_input)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN];
    uint8_t ct[8] = { 0 };
    uint8_t pt[64];
    size_t pt_len = 0;

    make_key(key);
    make_gcm_nonce(nonce);

    /* Fewer than 16 bytes: no room for a tag. */
    ck_assert_int_eq(
        bowie_cipher_aes256_gcm_decrypt(key, nonce,
                                         NULL, 0,
                                         ct, 8,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_ERR_CRYPTO);
}
END_TEST

/*
 * ============================================================================
 * CTR — ENCRYPT INPUT VALIDATION
 * ============================================================================
 */

START_TEST(test_ctr_encrypt_null_key)
{
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t out[64];
    size_t out_len = 0;

    make_ctr_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(NULL, nonce,
                                         "hi", 2,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_ctr_encrypt_null_nonce)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t out[64];
    size_t out_len = 0;

    make_key(key);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, NULL,
                                         "hi", 2,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_ctr_encrypt_null_out)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    size_t out_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         "hi", 2,
                                         NULL, 64, &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_ctr_encrypt_output_too_small)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t out[4];
    size_t out_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         "hello", 5,
                                         out, sizeof(out), &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

/*
 * ============================================================================
 * CTR — ROUND TRIP
 * ============================================================================
 */

START_TEST(test_ctr_roundtrip_small)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    const char *msg = "hello";
    size_t msg_len = 5;

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         msg, msg_len,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, msg_len);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_decrypt(key, nonce,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_uint_eq(pt_len, msg_len);
    ck_assert_int_eq(memcmp(pt, msg, msg_len), 0);
}
END_TEST

START_TEST(test_ctr_roundtrip_empty)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t ct[16];
    uint8_t pt[16];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         NULL, 0,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, 0u);

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_decrypt(key, nonce,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_uint_eq(pt_len, 0u);
}
END_TEST

START_TEST(test_ctr_roundtrip_longer)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t ct[256];
    uint8_t pt[256];
    size_t ct_len = 0;
    size_t pt_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    /* 200 bytes of a pattern. */
    uint8_t msg[200];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i & 0xFFu);
    }

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         msg, sizeof(msg),
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, sizeof(msg));

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_decrypt(key, nonce,
                                         ct, ct_len,
                                         pt, sizeof(pt), &pt_len),
        BOWIE_OK);
    ck_assert_uint_eq(pt_len, sizeof(msg));
    ck_assert_int_eq(memcmp(pt, msg, sizeof(msg)), 0);
}
END_TEST

START_TEST(test_ctr_encrypt_differs_from_plaintext)
{
    uint8_t key[BOWIE_CIPHER_KEY_LEN];
    uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN];
    uint8_t ct[64];
    size_t ct_len = 0;

    make_key(key);
    make_ctr_nonce(nonce);

    const char *msg = "hello world!";
    size_t msg_len = 12;

    ck_assert_int_eq(
        bowie_cipher_aes256_ctr_encrypt(key, nonce,
                                         msg, msg_len,
                                         ct, sizeof(ct), &ct_len),
        BOWIE_OK);
    ck_assert_uint_eq(ct_len, msg_len);

    /* The ciphertext must differ from the plaintext. */
    ck_assert_int_ne(memcmp(ct, msg, msg_len), 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *cipher_suite(void)
{
    Suite *s = suite_create("Cipher");

    TCase *tc_gcm_enc = tcase_create("GCMEncryptValidate");
    tcase_add_test(tc_gcm_enc, test_gcm_encrypt_null_key);
    tcase_add_test(tc_gcm_enc, test_gcm_encrypt_null_nonce);
    tcase_add_test(tc_gcm_enc, test_gcm_encrypt_null_out);
    tcase_add_test(tc_gcm_enc, test_gcm_encrypt_null_out_len);
    tcase_add_test(tc_gcm_enc, test_gcm_encrypt_output_too_small);
    suite_add_tcase(s, tc_gcm_enc);

    TCase *tc_gcm_rt = tcase_create("GCMRoundTrip");
    tcase_add_test(tc_gcm_rt, test_gcm_roundtrip_small);
    tcase_add_test(tc_gcm_rt, test_gcm_roundtrip_empty);
    tcase_add_test(tc_gcm_rt, test_gcm_roundtrip_with_aad);
    suite_add_tcase(s, tc_gcm_rt);

    TCase *tc_gcm_tag = tcase_create("GCMTagVerification");
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_corrupt_tag);
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_corrupt_ciphertext);
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_wrong_key);
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_wrong_nonce);
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_wrong_aad);
    tcase_add_test(tc_gcm_tag, test_gcm_decrypt_short_input);
    suite_add_tcase(s, tc_gcm_tag);

    TCase *tc_ctr_enc = tcase_create("CTREncryptValidate");
    tcase_add_test(tc_ctr_enc, test_ctr_encrypt_null_key);
    tcase_add_test(tc_ctr_enc, test_ctr_encrypt_null_nonce);
    tcase_add_test(tc_ctr_enc, test_ctr_encrypt_null_out);
    tcase_add_test(tc_ctr_enc, test_ctr_encrypt_output_too_small);
    suite_add_tcase(s, tc_ctr_enc);

    TCase *tc_ctr_rt = tcase_create("CTRRoundTrip");
    tcase_add_test(tc_ctr_rt, test_ctr_roundtrip_small);
    tcase_add_test(tc_ctr_rt, test_ctr_roundtrip_empty);
    tcase_add_test(tc_ctr_rt, test_ctr_roundtrip_longer);
    tcase_add_test(tc_ctr_rt, test_ctr_encrypt_differs_from_plaintext);
    suite_add_tcase(s, tc_ctr_rt);

    return s;
}

int main(void)
{
    Suite *s = cipher_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
