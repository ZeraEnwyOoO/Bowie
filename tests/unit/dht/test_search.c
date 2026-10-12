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
 * BOWIE — DHT SEARCH TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/search.c.
 *
 * The tests cover:
 *
 *   - Lifecycle: init, clear.
 *   - Seeding: seed, seed_routing.
 *   - Step: next_query, query_done.
 *   - Response: add_response, add_peers.
 *   - Status: is_done, finish, fail, timed_out, counters.
 *
 * The tests use deterministic node IDs so that the distance
 * order of the candidates is visible.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/search.h"               the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/search.h"

/*
 * ============================================================================
 * FIXTURE
 * ============================================================================
 */

#define TEST_CAND_CAP   8
#define TEST_PEER_CAP   8

static bowie_dht_node_t       g_candidates[TEST_CAND_CAP];
static bowie_dht_peer_entry_t g_peers[TEST_PEER_CAP];

static void make_target(bowie_dht_node_id_t *id)
{
    memset(id, 0, sizeof(*id));
}

static void make_node(bowie_dht_node_t *n, uint8_t seed)
{
    memset(n, 0, sizeof(*n));
    n->id.bytes[0] = seed;
    n->addr.family = BOWIE_AF_INET;
    n->addr.addr[0] = 10u;
    n->addr.addr[3] = seed;
    n->addr.port = (uint16_t)(6881u + seed);
}

static bowie_dht_search_t make_search(
    bowie_dht_search_type_t type,
    size_t alpha, size_t max_queries,
    bowie_mtime_t timeout_ms)
{
    bowie_dht_node_id_t target;
    make_target(&target);

    bowie_dht_info_hash_t hash;
    memset(&hash, 0, sizeof(hash));

    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_search_init(&s, type, &target, &hash,
                                g_candidates, TEST_CAND_CAP,
                                g_peers, TEST_PEER_CAP,
                                alpha, max_queries, timeout_ms,
                                1000u);
    return s;
}

static bowie_dht_search_t make_search_node_only(
    size_t alpha, size_t max_queries)
{
    bowie_dht_node_id_t target;
    make_target(&target);

    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));
    (void)bowie_dht_search_init(&s, BOWIE_DHT_SEARCH_FIND_NODE,
                                &target, NULL,
                                g_candidates, TEST_CAND_CAP,
                                NULL, 0u,
                                alpha, max_queries, 30000u,
                                1000u);
    return s;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null_search)
{
    bowie_dht_node_id_t target;
    make_target(&target);

    ck_assert_int_eq(
        bowie_dht_search_init(NULL, BOWIE_DHT_SEARCH_FIND_NODE,
                              &target, NULL,
                              g_candidates, TEST_CAND_CAP,
                              NULL, 0u, 3u, 20u, 30000u, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_target)
{
    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_search_init(&s, BOWIE_DHT_SEARCH_FIND_NODE,
                              NULL, NULL,
                              g_candidates, TEST_CAND_CAP,
                              NULL, 0u, 3u, 20u, 30000u, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_get_peers_requires_peer_array)
{
    bowie_dht_node_id_t target;
    bowie_dht_info_hash_t hash;
    make_target(&target);
    memset(&hash, 0, sizeof(hash));

    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));

    ck_assert_int_eq(
        bowie_dht_search_init(&s, BOWIE_DHT_SEARCH_GET_PEERS,
                              &target, &hash,
                              g_candidates, TEST_CAND_CAP,
                              NULL, 0u, 3u, 20u, 30000u, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_unknown_type)
{
    bowie_dht_node_id_t target;
    make_target(&target);

    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_search_init(&s, (bowie_dht_search_type_t)99,
                              &target, NULL,
                              g_candidates, TEST_CAND_CAP,
                              NULL, 0u, 3u, 20u, 30000u, 1000u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_init_defaults)
{
    bowie_dht_node_id_t target;
    make_target(&target);

    bowie_dht_search_t s;
    memset(&s, 0, sizeof(s));
    ck_assert_int_eq(
        bowie_dht_search_init(&s, BOWIE_DHT_SEARCH_FIND_NODE,
                              &target, NULL,
                              g_candidates, TEST_CAND_CAP,
                              NULL, 0u, 0u, 0u, 0u, 1000u),
        BOWIE_OK);
    ck_assert_uint_eq(s.max_in_flight,
                      BOWIE_DHT_SEARCH_DEFAULT_ALPHA);
    ck_assert_uint_eq(s.max_queries,
                      BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES);
    ck_assert_uint_eq(s.timeout_ms,
                      BOWIE_DHT_SEARCH_DEFAULT_TIMEOUT_MS);
}
END_TEST

START_TEST(test_clear_resets)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 1u);

    bowie_dht_search_clear(&s);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 0u);
    ck_assert_uint_eq(bowie_dht_search_query_count(&s), 0u);
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_dht_search_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * SEED
 * ============================================================================
 */

START_TEST(test_seed_null)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);

    ck_assert_int_eq(bowie_dht_search_seed(NULL, &n),
                     BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(bowie_dht_search_seed(&s, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_seed_invalid_node)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    memset(&n, 0, sizeof(n));

    ck_assert_int_eq(bowie_dht_search_seed(&s, &n),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_seed_ok)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);

    ck_assert_int_eq(bowie_dht_search_seed(&s, &n), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 1u);
}
END_TEST

START_TEST(test_seed_no_duplicates)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);

    (void)bowie_dht_search_seed(&s, &n);
    (void)bowie_dht_search_seed(&s, &n);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 1u);
}
END_TEST

START_TEST(test_seed_sorted_by_distance)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);

    bowie_dht_node_t n1;
    make_node(&n1, 0x10u);
    (void)bowie_dht_search_seed(&s, &n1);

    bowie_dht_node_t n2;
    make_node(&n2, 0x00u);
    (void)bowie_dht_search_seed(&s, &n2);

    bowie_dht_node_t n3;
    make_node(&n3, 0x20u);
    (void)bowie_dht_search_seed(&s, &n3);

    ck_assert_uint_eq(s.candidates[0].id.bytes[0], 0x00u);
    ck_assert_uint_eq(s.candidates[1].id.bytes[0], 0x10u);
    ck_assert_uint_eq(s.candidates[2].id.bytes[0], 0x20u);
}
END_TEST

START_TEST(test_seed_full)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);

    for (uint8_t i = 0u; i < TEST_CAND_CAP; i++) {
        bowie_dht_node_t n;
        make_node(&n, (uint8_t)(i + 1u));
        (void)bowie_dht_search_seed(&s, &n);
    }

    bowie_dht_node_t extra;
    make_node(&extra, 100u);
    ck_assert_int_eq(bowie_dht_search_seed(&s, &extra),
                     BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_seed_routing_null)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert_int_eq(
        bowie_dht_search_seed_routing(&s, NULL, 1000u),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_search_seed_routing(NULL, NULL, 1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_seed_routing_empty)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_routing_t r;
    bowie_dht_node_id_t local;
    make_target(&local);
    bowie_dht_routing_init(&r, &local);

    ck_assert_int_eq(
        bowie_dht_search_seed_routing(&s, &r, 1000u), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 0u);
}
END_TEST

/*
 * ============================================================================
 * NEXT QUERY
 * ============================================================================
 */

START_TEST(test_next_query_null)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t out;

    ck_assert_int_eq(bowie_dht_search_next_query(NULL, &out),
                     BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(bowie_dht_search_next_query(&s, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_next_query_no_candidates)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t out;

    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_next_query_ok)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    bowie_dht_node_t out;
    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_OK);
    ck_assert_uint_eq(out.id.bytes[0], 1u);
    ck_assert_uint_eq(bowie_dht_search_query_count(&s), 1u);
}
END_TEST

START_TEST(test_next_query_closest_first)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);

    bowie_dht_node_t n1;
    make_node(&n1, 0x20u);
    (void)bowie_dht_search_seed(&s, &n1);

    bowie_dht_node_t n2;
    make_node(&n2, 0x00u);
    (void)bowie_dht_search_seed(&s, &n2);

    bowie_dht_node_t out;

    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_OK);
    ck_assert_uint_eq(out.id.bytes[0], 0x00u);

    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_OK);
    ck_assert_uint_eq(out.id.bytes[0], 0x20u);
}
END_TEST

START_TEST(test_next_query_in_flight_limit)
{
    bowie_dht_search_t s = make_search_node_only(1u, 20u);

    bowie_dht_node_t n1;
    make_node(&n1, 1u);
    (void)bowie_dht_search_seed(&s, &n1);
    bowie_dht_node_t n2;
    make_node(&n2, 2u);
    (void)bowie_dht_search_seed(&s, &n2);

    bowie_dht_node_t out;

    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_ERR_BUSY);
}
END_TEST

START_TEST(test_next_query_max_queries)
{
    bowie_dht_search_t s = make_search_node_only(3u, 1u);
    bowie_dht_node_t n1;
    make_node(&n1, 1u);
    (void)bowie_dht_search_seed(&s, &n1);
    bowie_dht_node_t n2;
    make_node(&n2, 2u);
    (void)bowie_dht_search_seed(&s, &n2);

    bowie_dht_node_t out;
    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_OK);
    ck_assert_int_eq(bowie_dht_search_next_query(&s, &out),
                     BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_query_done_null)
{
    ck_assert_int_eq(bowie_dht_search_query_done(NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_query_done_no_in_flight)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert_int_eq(bowie_dht_search_query_done(&s),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_query_done_decrements)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    bowie_dht_node_t out;
    (void)bowie_dht_search_next_query(&s, &out);
    ck_assert_uint_eq(s.in_flight, 1u);

    ck_assert_int_eq(bowie_dht_search_query_done(&s), BOWIE_OK);
    ck_assert_uint_eq(s.in_flight, 0u);
}
END_TEST

/*
 * ============================================================================
 * ADD RESPONSE
 * ============================================================================
 */

START_TEST(test_add_response_null)
{
    ck_assert_int_eq(bowie_dht_search_add_response(NULL, NULL, 0u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_add_response_empty)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    bowie_dht_node_t out;
    (void)bowie_dht_search_next_query(&s, &out);

    ck_assert_int_eq(
        bowie_dht_search_add_response(&s, NULL, 0u), BOWIE_OK);
    ck_assert_uint_eq(s.in_flight, 0u);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 1u);
}
END_TEST

START_TEST(test_add_response_adds_candidates)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    bowie_dht_node_t out;
    (void)bowie_dht_search_next_query(&s, &out);

    bowie_dht_compact_node_t cn;
    memset(&cn, 0, sizeof(cn));
    cn.id.bytes[0] = 0x42u;
    cn.addr.family = BOWIE_AF_INET;
    cn.addr.addr[0] = 10u;
    cn.addr.addr[3] = 0x42u;
    cn.addr.port = 6881u;

    ck_assert_int_eq(
        bowie_dht_search_add_response(&s, &cn, 1u), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_search_candidate_count(&s), 2u);
}
END_TEST

/*
 * ============================================================================
 * ADD PEERS
 * ============================================================================
 */

START_TEST(test_add_peers_null)
{
    ck_assert_int_eq(bowie_dht_search_add_peers(NULL, NULL, 0u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_add_peers_ok)
{
    bowie_dht_search_t s = make_search(BOWIE_DHT_SEARCH_GET_PEERS,
                                        3u, 20u, 30000u);
    bowie_dht_peer_entry_t p;
    memset(&p, 0, sizeof(p));
    p.addr.family = BOWIE_AF_INET;
    p.addr.addr[3] = 1u;
    p.addr.port = 6881u;

    ck_assert_int_eq(
        bowie_dht_search_add_peers(&s, &p, 1u), BOWIE_OK);
    ck_assert_uint_eq(bowie_dht_search_peer_count(&s), 1u);
}
END_TEST

START_TEST(test_add_peers_dedup)
{
    bowie_dht_search_t s = make_search(BOWIE_DHT_SEARCH_GET_PEERS,
                                        3u, 20u, 30000u);
    bowie_dht_peer_entry_t p;
    memset(&p, 0, sizeof(p));
    p.addr.family = BOWIE_AF_INET;
    p.addr.addr[3] = 1u;
    p.addr.port = 6881u;

    (void)bowie_dht_search_add_peers(&s, &p, 1u);
    (void)bowie_dht_search_add_peers(&s, &p, 1u);
    ck_assert_uint_eq(bowie_dht_search_peer_count(&s), 1u);
}
END_TEST

START_TEST(test_add_peers_capacity)
{
    bowie_dht_search_t s = make_search(BOWIE_DHT_SEARCH_GET_PEERS,
                                        3u, 20u, 30000u);

    bowie_dht_peer_entry_t p;
    for (uint8_t i = 1u; i <= TEST_PEER_CAP + 1u; i++) {
        memset(&p, 0, sizeof(p));
        p.addr.family = BOWIE_AF_INET;
        p.addr.addr[3] = i;
        p.addr.port = 6881u;
        (void)bowie_dht_search_add_peers(&s, &p, 1u);
    }

    ck_assert_uint_eq(bowie_dht_search_peer_count(&s),
                      TEST_PEER_CAP);
}
END_TEST

/*
 * ============================================================================
 * STATUS
 * ============================================================================
 */

START_TEST(test_is_done_null)
{
    ck_assert(!bowie_dht_search_is_done(NULL));
}
END_TEST

START_TEST(test_is_done_fresh_search)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert(bowie_dht_search_is_done(&s));
}
END_TEST

START_TEST(test_is_done_pending_candidate)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    ck_assert(!bowie_dht_search_is_done(&s));
}
END_TEST

START_TEST(test_is_done_after_all_queried)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_node_t n;
    make_node(&n, 1u);
    (void)bowie_dht_search_seed(&s, &n);

    bowie_dht_node_t out;
    (void)bowie_dht_search_next_query(&s, &out);

    ck_assert(!bowie_dht_search_is_done(&s));

    (void)bowie_dht_search_query_done(&s);

    ck_assert(bowie_dht_search_is_done(&s));
}
END_TEST

START_TEST(test_finish)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_search_finish(&s);
    ck_assert(bowie_dht_search_is_done(&s));
    ck_assert_int_eq(s.state, BOWIE_DHT_SEARCH_DONE);
}
END_TEST

START_TEST(test_finish_null)
{
    bowie_dht_search_finish(NULL);
}
END_TEST

START_TEST(test_fail)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    bowie_dht_search_fail(&s);
    ck_assert(bowie_dht_search_is_done(&s));
    ck_assert_int_eq(s.state, BOWIE_DHT_SEARCH_FAILED);
}
END_TEST

START_TEST(test_fail_null)
{
    bowie_dht_search_fail(NULL);
}
END_TEST

START_TEST(test_timed_out_null)
{
    ck_assert(!bowie_dht_search_timed_out(NULL, 1000u));
}
END_TEST

START_TEST(test_timed_out_no_timeout)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    s.timeout_ms = 0u;
    ck_assert(!bowie_dht_search_timed_out(&s, 999999u));
}
END_TEST

START_TEST(test_timed_out_not_yet)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert(!bowie_dht_search_timed_out(&s, 1000u + 5000u));
}
END_TEST

START_TEST(test_timed_out_yes)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert(bowie_dht_search_timed_out(&s, 1000u + 30001u));
}
END_TEST

START_TEST(test_timed_out_backward_clock)
{
    bowie_dht_search_t s = make_search_node_only(3u, 20u);
    ck_assert(!bowie_dht_search_timed_out(&s, 500u));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *search_suite(void)
{
    Suite *s = suite_create("DhtSearch");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null_search);
    tcase_add_test(tc_life, test_init_null_target);
    tcase_add_test(tc_life, test_init_get_peers_requires_peer_array);
    tcase_add_test(tc_life, test_init_unknown_type);
    tcase_add_test(tc_life, test_init_defaults);
    tcase_add_test(tc_life, test_clear_resets);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_seed = tcase_create("Seed");
    tcase_add_test(tc_seed, test_seed_null);
    tcase_add_test(tc_seed, test_seed_invalid_node);
    tcase_add_test(tc_seed, test_seed_ok);
    tcase_add_test(tc_seed, test_seed_no_duplicates);
    tcase_add_test(tc_seed, test_seed_sorted_by_distance);
    tcase_add_test(tc_seed, test_seed_full);
    tcase_add_test(tc_seed, test_seed_routing_null);
    tcase_add_test(tc_seed, test_seed_routing_empty);
    suite_add_tcase(s, tc_seed);

    TCase *tc_step = tcase_create("NextQuery");
    tcase_add_test(tc_step, test_next_query_null);
    tcase_add_test(tc_step, test_next_query_no_candidates);
    tcase_add_test(tc_step, test_next_query_ok);
    tcase_add_test(tc_step, test_next_query_closest_first);
    tcase_add_test(tc_step, test_next_query_in_flight_limit);
    tcase_add_test(tc_step, test_next_query_max_queries);
    tcase_add_test(tc_step, test_query_done_null);
    tcase_add_test(tc_step, test_query_done_no_in_flight);
    tcase_add_test(tc_step, test_query_done_decrements);
    suite_add_tcase(s, tc_step);

    TCase *tc_resp = tcase_create("Response");
    tcase_add_test(tc_resp, test_add_response_null);
    tcase_add_test(tc_resp, test_add_response_empty);
    tcase_add_test(tc_resp, test_add_response_adds_candidates);
    suite_add_tcase(s, tc_resp);

    TCase *tc_peer = tcase_create("AddPeers");
    tcase_add_test(tc_peer, test_add_peers_null);
    tcase_add_test(tc_peer, test_add_peers_ok);
    tcase_add_test(tc_peer, test_add_peers_dedup);
    tcase_add_test(tc_peer, test_add_peers_capacity);
    suite_add_tcase(s, tc_peer);

    TCase *tc_done = tcase_create("Done");
    tcase_add_test(tc_done, test_is_done_null);
    tcase_add_test(tc_done, test_is_done_fresh_search);
    tcase_add_test(tc_done, test_is_done_pending_candidate);
    tcase_add_test(tc_done, test_is_done_after_all_queried);
    tcase_add_test(tc_done, test_finish);
    tcase_add_test(tc_done, test_finish_null);
    tcase_add_test(tc_done, test_fail);
    tcase_add_test(tc_done, test_fail_null);
    suite_add_tcase(s, tc_done);

    TCase *tc_to = tcase_create("Timeout");
    tcase_add_test(tc_to, test_timed_out_null);
    tcase_add_test(tc_to, test_timed_out_no_timeout);
    tcase_add_test(tc_to, test_timed_out_not_yet);
    tcase_add_test(tc_to, test_timed_out_yes);
    tcase_add_test(tc_to, test_timed_out_backward_clock);
    suite_add_tcase(s, tc_to);

    return s;
}

int main(void)
{
    Suite *s = search_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
