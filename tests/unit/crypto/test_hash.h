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
 * BOWIE — HASH TESTS
 * ============================================================================
 *
 * Unit tests for src/crypto/hash.c.
 *
 * Every public function declared in bowie/crypto/hash.h is
 * covered here.
 *
 * The hash functions are deterministic. A test that hashes a
 * known input and compares the result to a known digest is a
 * real test of the implementation. The known digests are the
 * standard test vectors for each algorithm. A test that
 * hashed a random input and compared to itself would not test
 * anything.
 *
 * The test vectors:
 *
 *   SHA-256 of "" is
 *     e3b0c44298fc1c149afbf4c8996fb924
 *     27ae41e4649b934ca495991b7852b855
 *
 *   SHA-256 of "abc" is
 *     ba7816bf8f01cfea414140de5dae2223
 *     b00361a396177a9cb410ff61f20015ad
 *
 *   SHA-1 of "abc" is
 *     a9993e364706816aba3e25717850c26c9cd0d89d
 *
 *   MD5 of "abc" is
 *     900150983cd24fb0d6963f7d28e17f72
 *
 *   HMAC-SHA256 of "The quick brown fox jumps over the lazy dog"
 *   with key "key" is
 *     f7bc83f430538424b13298e6aa6fb143
 *     ef4d59a14946175997479dbc2d1a3cd8
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "bowie/crypto/hash.h"           the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "bowie/crypto/hash.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Compare a hash to a known digest given as a byte array. The
 * caller supplies the expected bytes.
 */
static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

/*
 * Known SHA-256 digest of the empty string.
 */
static const uint8_t SHA256_EMPTY[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/*
 * Known SHA-256 digest of "abc".
 */
static const uint8_t SHA256_ABC[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

/*
 * Known SHA-1 digest of "abc".
 */
static const uint8_t SHA1_ABC[20] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d,
};

/*
 * Known SHA-1 digest of the empty string.
 */
static const uint8_t SHA1_EMPTY[20] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
    0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
};

/*
 * Known MD5 digest of "abc".
 */
static const uint8_t MD5_ABC[16] = {
    0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
    0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
};

/*
 * Known MD5 digest of the empty string.
 */
static const uint8_t MD5_EMPTY[16] = {
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
};

/*
 * Known HMAC-SHA256 of "The quick brown fox jumps over the
 * lazy dog" with key "key".
 */
static const uint8_t HMAC_KEY_FOX[32] = {
    0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
    0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
    0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
    0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
};

/*
 * ============================================================================
 * SHA-256
 * ============================================================================
 */

START_TEST(test_sha256_null_out)
{
    const char *data = "abc";
    ck_assert_int_eq(
        bowie_hash_sha256(data, 3u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sha256_null_data_with_len)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_sha256(NULL, 3u, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sha256_null_data_zero_len)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_sha256(NULL, 0u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, SHA256_EMPTY, 32),
        1);
}
END_TEST

START_TEST(test_sha256_empty)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_sha256("", 0u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, SHA256_EMPTY, 32),
        1);
}
END_TEST

START_TEST(test_sha256_abc)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_sha256("abc", 3u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, SHA256_ABC, 32),
        1);
}
END_TEST

START_TEST(test_sha256_deterministic)
{
    bowie_hash_sha256_t a;
    bowie_hash_sha256_t b;
    (void)bowie_hash_sha256("hello", 5u, &a);
    (void)bowie_hash_sha256("hello", 5u, &b);
    ck_assert_int_eq(
        bytes_equal(a.bytes, b.bytes, 32),
        1);
}
END_TEST

START_TEST(test_sha256_different_inputs_differ)
{
    bowie_hash_sha256_t a;
    bowie_hash_sha256_t b;
    (void)bowie_hash_sha256("hello", 5u, &a);
    (void)bowie_hash_sha256("world", 5u, &b);
    ck_assert_int_ne(
        bytes_equal(a.bytes, b.bytes, 32),
        1);
}
END_TEST

/*
 * ============================================================================
 * SHA-1
 * ============================================================================
 */

START_TEST(test_sha1_null_out)
{
    ck_assert_int_eq(
        bowie_hash_sha1("abc", 3u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sha1_null_data_with_len)
{
    bowie_hash_sha1_t out;
    ck_assert_int_eq(
        bowie_hash_sha1(NULL, 3u, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_sha1_empty)
{
    bowie_hash_sha1_t out;
    ck_assert_int_eq(
        bowie_hash_sha1("", 0u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, SHA1_EMPTY, 20),
        1);
}
END_TEST

START_TEST(test_sha1_abc)
{
    bowie_hash_sha1_t out;
    ck_assert_int_eq(
        bowie_hash_sha1("abc", 3u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, SHA1_ABC, 20),
        1);
}
END_TEST

START_TEST(test_sha1_deterministic)
{
    bowie_hash_sha1_t a;
    bowie_hash_sha1_t b;
    (void)bowie_hash_sha1("hello", 5u, &a);
    (void)bowie_hash_sha1("hello", 5u, &b);
    ck_assert_int_eq(
        bytes_equal(a.bytes, b.bytes, 20),
        1);
}
END_TEST

/*
 * ============================================================================
 * MD5
 * ============================================================================
 */

START_TEST(test_md5_null_out)
{
    ck_assert_int_eq(
        bowie_hash_md5("abc", 3u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_md5_null_data_with_len)
{
    bowie_hash_md5_t out;
    ck_assert_int_eq(
        bowie_hash_md5(NULL, 3u, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_md5_empty)
{
    bowie_hash_md5_t out;
    ck_assert_int_eq(
        bowie_hash_md5("", 0u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, MD5_EMPTY, 16),
        1);
}
END_TEST

START_TEST(test_md5_abc)
{
    bowie_hash_md5_t out;
    ck_assert_int_eq(
        bowie_hash_md5("abc", 3u, &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, MD5_ABC, 16),
        1);
}
END_TEST

START_TEST(test_md5_deterministic)
{
    bowie_hash_md5_t a;
    bowie_hash_md5_t b;
    (void)bowie_hash_md5("hello", 5u, &a);
    (void)bowie_hash_md5("hello", 5u, &b);
    ck_assert_int_eq(
        bytes_equal(a.bytes, b.bytes, 16),
        1);
}
END_TEST

/*
 * ============================================================================
 * HMAC-SHA256
 * ============================================================================
 */

START_TEST(test_hmac_null_out)
{
    ck_assert_int_eq(
        bowie_hash_hmac_sha256("k", 1u, "d", 1u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hmac_null_key_with_len)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_hmac_sha256(NULL, 3u, "d", 1u, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hmac_null_data_with_len)
{
    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_hmac_sha256("k", 1u, NULL, 3u, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hmac_rfc_vector)
{
    /*
     * The test vector from RFC 4231, case 1, adapted to the
     * key "key" and the fox sentence.
     *
     * key     = "key"
     * data    = "The quick brown fox jumps over the lazy dog"
     * HMAC    = f7bc83f430538424b13298e6aa6fb143
     *           ef4d59a14946175997479dbc2d1a3cd8
     */
    const char *key  = "key";
    const char *data = "The quick brown fox jumps over the lazy dog";

    bowie_hash_sha256_t out;
    ck_assert_int_eq(
        bowie_hash_hmac_sha256(key, strlen(key),
                               data, strlen(data),
                               &out),
        BOWIE_OK);
    ck_assert_int_eq(
        bytes_equal(out.bytes, HMAC_KEY_FOX, 32),
        1);
}
END_TEST

START_TEST(test_hmac_deterministic)
{
    bowie_hash_sha256_t a;
    bowie_hash_sha256_t b;
    (void)bowie_hash_hmac_sha256("key", 3u, "data", 4u, &a);
    (void)bowie_hash_hmac_sha256("key", 3u, "data", 4u, &b);
    ck_assert_int_eq(
        bytes_equal(a.bytes, b.bytes, 32),
        1);
}
END_TEST

START_TEST(test_hmac_different_keys_differ)
{
    bowie_hash_sha256_t a;
    bowie_hash_sha256_t b;
    (void)bowie_hash_hmac_sha256("key1", 4u, "data", 4u, &a);
    (void)bowie_hash_hmac_sha256("key2", 4u, "data", 4u, &b);
    ck_assert_int_ne(
        bytes_equal(a.bytes, b.bytes, 32),
        1);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *hash_suite(void)
{
    Suite *s = suite_create("Hash");

    TCase *tc_sha256 = tcase_create("SHA256");
    tcase_add_test(tc_sha256, test_sha256_null_out);
    tcase_add_test(tc_sha256, test_sha256_null_data_with_len);
    tcase_add_test(tc_sha256, test_sha256_null_data_zero_len);
    tcase_add_test(tc_sha256, test_sha256_empty);
    tcase_add_test(tc_sha256, test_sha256_abc);
    tcase_add_test(tc_sha256, test_sha256_deterministic);
    tcase_add_test(tc_sha256, test_sha256_different_inputs_differ);
    suite_add_tcase(s, tc_sha256);

    TCase *tc_sha1 = tcase_create("SHA1");
    tcase_add_test(tc_sha1, test_sha1_null_out);
    tcase_add_test(tc_sha1, test_sha1_null_data_with_len);
    tcase_add_test(tc_sha1, test_sha1_empty);
    tcase_add_test(tc_sha1, test_sha1_abc);
    tcase_add_test(tc_sha1, test_sha1_deterministic);
    suite_add_tcase(s, tc_sha1);

    TCase *tc_md5 = tcase_create("MD5");
    tcase_add_test(tc_md5, test_md5_null_out);
    tcase_add_test(tc_md5, test_md5_null_data_with_len);
    tcase_add_test(tc_md5, test_md5_empty);
    tcase_add_test(tc_md5, test_md5_abc);
    tcase_add_test(tc_md5, test_md5_deterministic);
    suite_add_tcase(s, tc_md5);

    TCase *tc_hmac = tcase_create("HMACSHA256");
    tcase_add_test(tc_hmac, test_hmac_null_out);
    tcase_add_test(tc_hmac, test_hmac_null_key_with_len);
    tcase_add_test(tc_hmac, test_hmac_null_data_with_len);
    tcase_add_test(tc_hmac, test_hmac_rfc_vector);
    tcase_add_test(tc_hmac, test_hmac_deterministic);
    tcase_add_test(tc_hmac, test_hmac_different_keys_differ);
    suite_add_tcase(s, tc_hmac);

    return s;
}

int main(void)
{
    Suite *s = hash_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
