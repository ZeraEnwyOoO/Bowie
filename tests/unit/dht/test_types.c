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
 * BOWIE — DHT TYPES TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/types.c.
 *
 * Every public function declared in dht/types.h is covered
 * here. The NULL contract of each pointer-taking function is
 * tested, because it is part of the declared contract and not
 * an accident of the implementation.
 *
 * The token is the only variable-length type. Its tests cover
 * the length check, the byte comparison over the declared
 * length, and the trailing-bytes-ignored rule.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "dht/types.h"                the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "dht/types.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void fill_node_id(bowie_dht_node_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_NODE_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void fill_info_hash(bowie_dht_info_hash_t *h, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_INFO_HASH_LEN; i++) {
        h->bytes[i] = (uint8_t)(seed + i);
    }
}

static void fill_token(bowie_dht_token_t *t, uint8_t seed, size_t len)
{
    memset(t, 0, sizeof(*t));
    for (size_t i = 0u; i < len && i < BOWIE_DHT_TOKEN_MAX; i++) {
        t->bytes[i] = (uint8_t)(seed + i);
    }
    t->len = len;
}

static void fill_distance(bowie_dht_distance_t *d, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_DISTANCE_LEN; i++) {
        d->bytes[i] = (uint8_t)(seed + i);
    }
}

/*
 * ============================================================================
 * NODE ID
 * ============================================================================
 */

START_TEST(test_node_id_clear_zeroes)
{
    bowie_dht_node_id_t id;
    fill_node_id(&id, 1u);
    bowie_dht_node_id_clear(&id);
    ck_assert(bowie_dht_node_id_is_zero(&id));
}
END_TEST

START_TEST(test_node_id_clear_null_is_noop)
{
    bowie_dht_node_id_clear(NULL);
}
END_TEST

START_TEST(test_node_id_is_zero_null)
{
    ck_assert(bowie_dht_node_id_is_zero(NULL));
}
END_TEST

START_TEST(test_node_id_is_zero_true)
{
    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_dht_node_id_is_zero(&id));
}
END_TEST

START_TEST(test_node_id_is_zero_false)
{
    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    id.bytes[10] = 1u;
    ck_assert(!bowie_dht_node_id_is_zero(&id));
}
END_TEST

START_TEST(test_node_id_equal_null_null)
{
    ck_assert(bowie_dht_node_id_equal(NULL, NULL));
}
END_TEST

START_TEST(test_node_id_equal_null_zero)
{
    bowie_dht_node_id_t id;
    memset(&id, 0, sizeof(id));
    ck_assert(bowie_dht_node_id_equal(NULL, &id));
    ck_assert(bowie_dht_node_id_equal(&id, NULL));
}
END_TEST

START_TEST(test_node_id_equal_same)
{
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    fill_node_id(&a, 5u);
    fill_node_id(&b, 5u);
    ck_assert(bowie_dht_node_id_equal(&a, &b));
}
END_TEST

START_TEST(test_node_id_equal_different)
{
    bowie_dht_node_id_t a;
    bowie_dht_node_id_t b;
    fill_node_id(&a, 5u);
    fill_node_id(&b, 6u);
    ck_assert(!bowie_dht_node_id_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * INFO HASH
 * ============================================================================
 */

START_TEST(test_info_hash_clear_zeroes)
{
    bowie_dht_info_hash_t h;
    fill_info_hash(&h, 1u);
    bowie_dht_info_hash_clear(&h);
    ck_assert(bowie_dht_info_hash_is_zero(&h));
}
END_TEST

START_TEST(test_info_hash_clear_null_is_noop)
{
    bowie_dht_info_hash_clear(NULL);
}
END_TEST

START_TEST(test_info_hash_is_zero_null)
{
    ck_assert(bowie_dht_info_hash_is_zero(NULL));
}
END_TEST

START_TEST(test_info_hash_is_zero_true)
{
    bowie_dht_info_hash_t h;
    memset(&h, 0, sizeof(h));
    ck_assert(bowie_dht_info_hash_is_zero(&h));
}
END_TEST

START_TEST(test_info_hash_is_zero_false)
{
    bowie_dht_info_hash_t h;
    memset(&h, 0, sizeof(h));
    h.bytes[19] = 0xFFu;
    ck_assert(!bowie_dht_info_hash_is_zero(&h));
}
END_TEST

START_TEST(test_info_hash_equal_null_null)
{
    ck_assert(bowie_dht_info_hash_equal(NULL, NULL));
}
END_TEST

START_TEST(test_info_hash_equal_null_zero)
{
    bowie_dht_info_hash_t h;
    memset(&h, 0, sizeof(h));
    ck_assert(bowie_dht_info_hash_equal(NULL, &h));
    ck_assert(bowie_dht_info_hash_equal(&h, NULL));
}
END_TEST

START_TEST(test_info_hash_equal_same)
{
    bowie_dht_info_hash_t a;
    bowie_dht_info_hash_t b;
    fill_info_hash(&a, 3u);
    fill_info_hash(&b, 3u);
    ck_assert(bowie_dht_info_hash_equal(&a, &b));
}
END_TEST

START_TEST(test_info_hash_equal_different)
{
    bowie_dht_info_hash_t a;
    bowie_dht_info_hash_t b;
    fill_info_hash(&a, 3u);
    fill_info_hash(&b, 4u);
    ck_assert(!bowie_dht_info_hash_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * TOKEN
 * ============================================================================
 */

START_TEST(test_token_clear_zeroes)
{
    bowie_dht_token_t t;
    fill_token(&t, 1u, 8u);
    bowie_dht_token_clear(&t);
    ck_assert(bowie_dht_token_is_zero(&t));
    ck_assert_uint_eq(t.len, 0u);
}
END_TEST

START_TEST(test_token_clear_null_is_noop)
{
    bowie_dht_token_clear(NULL);
}
END_TEST

START_TEST(test_token_is_zero_null)
{
    ck_assert(bowie_dht_token_is_zero(NULL));
}
END_TEST

START_TEST(test_token_is_zero_true)
{
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    ck_assert(bowie_dht_token_is_zero(&t));
}
END_TEST

START_TEST(test_token_is_zero_false)
{
    bowie_dht_token_t t;
    fill_token(&t, 1u, 4u);
    ck_assert(!bowie_dht_token_is_zero(&t));
}
END_TEST

START_TEST(test_token_is_zero_length_zero_bytes)
{
    bowie_dht_token_t t;
    memset(&t, 0xFF, sizeof(t));
    t.len = 0u;
    ck_assert(bowie_dht_token_is_zero(&t));
}
END_TEST

START_TEST(test_token_equal_null_null)
{
    ck_assert(bowie_dht_token_equal(NULL, NULL));
}
END_TEST

START_TEST(test_token_equal_null_unset)
{
    bowie_dht_token_t t;
    memset(&t, 0, sizeof(t));
    ck_assert(bowie_dht_token_equal(NULL, &t));
    ck_assert(bowie_dht_token_equal(&t, NULL));
}
END_TEST

START_TEST(test_token_equal_same)
{
    bowie_dht_token_t a;
    bowie_dht_token_t b;
    fill_token(&a, 7u, 8u);
    fill_token(&b, 7u, 8u);
    ck_assert(bowie_dht_token_equal(&a, &b));
}
END_TEST

START_TEST(test_token_equal_different_length)
{
    bowie_dht_token_t a;
    bowie_dht_token_t b;
    fill_token(&a, 7u, 8u);
    fill_token(&b, 7u, 4u);
    ck_assert(!bowie_dht_token_equal(&a, &b));
}
END_TEST

START_TEST(test_token_equal_different_bytes)
{
    bowie_dht_token_t a;
    bowie_dht_token_t b;
    fill_token(&a, 7u, 8u);
    fill_token(&b, 8u, 8u);
    ck_assert(!bowie_dht_token_equal(&a, &b));
}
END_TEST

START_TEST(test_token_equal_trailing_bytes_ignored)
{
    bowie_dht_token_t a;
    bowie_dht_token_t b;
    fill_token(&a, 7u, 4u);
    fill_token(&b, 7u, 4u);

    a.bytes[10] = 0xFFu;
    b.bytes[10] = 0x00u;

    ck_assert(bowie_dht_token_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * DISTANCE
 * ============================================================================
 */

START_TEST(test_distance_clear_zeroes)
{
    bowie_dht_distance_t d;
    fill_distance(&d, 1u);
    bowie_dht_distance_clear(&d);

    bowie_dht_distance_t zero;
    memset(&zero, 0, sizeof(zero));
    ck_assert(bowie_dht_distance_equal(&d, &zero));
}
END_TEST

START_TEST(test_distance_clear_null_is_noop)
{
    bowie_dht_distance_clear(NULL);
}
END_TEST

START_TEST(test_distance_equal_null_null)
{
    ck_assert(bowie_dht_distance_equal(NULL, NULL));
}
END_TEST

START_TEST(test_distance_equal_null_zero)
{
    bowie_dht_distance_t d;
    memset(&d, 0, sizeof(d));
    ck_assert(bowie_dht_distance_equal(NULL, &d));
    ck_assert(bowie_dht_distance_equal(&d, NULL));
}
END_TEST

START_TEST(test_distance_equal_same)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    fill_distance(&a, 2u);
    fill_distance(&b, 2u);
    ck_assert(bowie_dht_distance_equal(&a, &b));
}
END_TEST

START_TEST(test_distance_equal_different)
{
    bowie_dht_distance_t a;
    bowie_dht_distance_t b;
    fill_distance(&a, 2u);
    fill_distance(&b, 3u);
    ck_assert(!bowie_dht_distance_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *dht_types_suite(void)
{
    Suite *s = suite_create("DhtTypes");

    TCase *tc_nid = tcase_create("NodeId");
    tcase_add_test(tc_nid, test_node_id_clear_zeroes);
    tcase_add_test(tc_nid, test_node_id_clear_null_is_noop);
    tcase_add_test(tc_nid, test_node_id_is_zero_null);
    tcase_add_test(tc_nid, test_node_id_is_zero_true);
    tcase_add_test(tc_nid, test_node_id_is_zero_false);
    tcase_add_test(tc_nid, test_node_id_equal_null_null);
    tcase_add_test(tc_nid, test_node_id_equal_null_zero);
    tcase_add_test(tc_nid, test_node_id_equal_same);
    tcase_add_test(tc_nid, test_node_id_equal_different);
    suite_add_tcase(s, tc_nid);

    TCase *tc_ih = tcase_create("InfoHash");
    tcase_add_test(tc_ih, test_info_hash_clear_zeroes);
    tcase_add_test(tc_ih, test_info_hash_clear_null_is_noop);
    tcase_add_test(tc_ih, test_info_hash_is_zero_null);
    tcase_add_test(tc_ih, test_info_hash_is_zero_true);
    tcase_add_test(tc_ih, test_info_hash_is_zero_false);
    tcase_add_test(tc_ih, test_info_hash_equal_null_null);
    tcase_add_test(tc_ih, test_info_hash_equal_null_zero);
    tcase_add_test(tc_ih, test_info_hash_equal_same);
    tcase_add_test(tc_ih, test_info_hash_equal_different);
    suite_add_tcase(s, tc_ih);

    TCase *tc_tok = tcase_create("Token");
    tcase_add_test(tc_tok, test_token_clear_zeroes);
    tcase_add_test(tc_tok, test_token_clear_null_is_noop);
    tcase_add_test(tc_tok, test_token_is_zero_null);
    tcase_add_test(tc_tok, test_token_is_zero_true);
    tcase_add_test(tc_tok, test_token_is_zero_false);
    tcase_add_test(tc_tok, test_token_is_zero_length_zero_bytes);
    tcase_add_test(tc_tok, test_token_equal_null_null);
    tcase_add_test(tc_tok, test_token_equal_null_unset);
    tcase_add_test(tc_tok, test_token_equal_same);
    tcase_add_test(tc_tok, test_token_equal_different_length);
    tcase_add_test(tc_tok, test_token_equal_different_bytes);
    tcase_add_test(tc_tok, test_token_equal_trailing_bytes_ignored);
    suite_add_tcase(s, tc_tok);

    TCase *tc_dist = tcase_create("Distance");
    tcase_add_test(tc_dist, test_distance_clear_zeroes);
    tcase_add_test(tc_dist, test_distance_clear_null_is_noop);
    tcase_add_test(tc_dist, test_distance_equal_null_null);
    tcase_add_test(tc_dist, test_distance_equal_null_zero);
    tcase_add_test(tc_dist, test_distance_equal_same);
    tcase_add_test(tc_dist, test_distance_equal_different);
    suite_add_tcase(s, tc_dist);

    return s;
}

int main(void)
{
    Suite *s = dht_types_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
