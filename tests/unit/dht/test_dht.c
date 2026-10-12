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
 * BOWIE — DHT ENGINE TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/dht.c.
 *
 * The tests cover:
 *
 *   - Lifecycle: init, shutdown, clear.
 *   - Query helpers: local_id, node_count, hash_count,
 *     peer_count.
 *   - Query builder: ping, find_node, get_peers,
 *     announce_peer.
 *   - Message handling: ping, find_node, get_peers,
 *     announce_peer, response, error.
 *   - Maintenance: tick.
 *
 * The tests use a small DHT engine with small arrays.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "dht/dht.h"                  the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/dht.h"

/*
 * ============================================================================
 * FIXTURE
 * ============================================================================
 */

#define TEST_HASHES_CAP       4
#define TEST_PEERS_CAP       16
#define TEST_RATE_LIMITS_CAP  4
#define TEST_ARENA_NODES_CAP 16
#define TEST_ARENA_PEERS_CAP 16

static bowie_dht_hash_entry_t      g_hashes[TEST_HASHES_CAP];
static bowie_dht_peer_entry_t      g_peers[TEST_PEERS_CAP];
static bowie_dht_peer_metadata_t   g_metadata[TEST_PEERS_CAP];
static bowie_dht_rate_limit_t      g_rate_limits[TEST_RATE_LIMITS_CAP];
static bowie_dht_compact_node_t    g_arena_nodes[TEST_ARENA_NODES_CAP];
static bowie_dht_compact_peer_t    g_arena_peers[TEST_ARENA_PEERS_CAP];

static bowie_dht_config_t make_config(void)
{
    bowie_dht_config_t c;
    memset(&c, 0, sizeof(c));
    c.max_hashes         = TEST_HASHES_CAP;
    c.max_peers_per_hash = 4u;
    c.max_storage_peers  = TEST_PEERS_CAP;
    c.max_buckets        = 16u;
    c.max_nodes_per_bucket = 4u;
    c.refresh_interval_s = 300u;
    c.peer_lifetime_s    = 60u;
    c.token_rotate_s     = 600u;
    c.search_timeout_ms  = 30000u;
    c.sec_level          = BOWIE_DHT_SEC_NONE;
    c.store_metadata     = 1;
    return c;
}

static void make_local_id(bowie_dht_node_id_t *id)
{
    memset(id, 0, sizeof(*id));
    id->bytes[0] = 0x10u;
}

static bowie_dht_message_arena_t make_arena(void)
{
    bowie_dht_message_arena_t a;
    a.nodes      = g_arena_nodes;
    a.nodes_cap  = TEST_ARENA_NODES_CAP;
    a.nodes_used = 0u;
    a.peers      = g_arena_peers;
    a.peers_cap  = TEST_ARENA_PEERS_CAP;
    a.peers_used = 0u;
    return a;
}

static bowie_dht_t make_dht(bowie_mtime_t now_ms)
{
    bowie_dht_config_t c = make_config();
    bowie_dht_node_id_t local;
    make_local_id(&local);

    bowie_dht_t d;
    memset(&d, 0, sizeof(d));
    (void)bowie_dht_init(&d, &c, &local,
                         g_hashes, TEST_HASHES_CAP,
                         g_peers, TEST_PEERS_CAP,
                         g_metadata,
                         g_rate_limits, TEST_RATE_LIMITS_CAP,
                         now_ms);
    return d;
}

static void make_addr(bowie_addr_t *a, uint8_t last_octet,
                      uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->family = BOWIE_AF_INET;
    a->addr[0] = 10u;
    a->addr[3] = last_octet;
    a->port = port;
}

static void make_info_hash(bowie_dht_info_hash_t *h, uint8_t seed)
{
    memset(h, 0, sizeof(*h));
    h->bytes[0] = seed;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null_dht)
{
    bowie_dht_config_t c = make_config();
    bowie_dht_node_id_t local;
    make_local_id(&local);

    ck_assert_int_eq(
        bowie_dht_init(NULL, &c, &local,
                       g_hashes, TEST_HASHES_CAP,
                       g_peers, TEST_PEERS_CAP,
                       g_metadata,
                       g_rate_limits, TEST_RATE_LIMITS_CAP,
                       1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_config)
{
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_t d;
    memset(&d, 0, sizeof(d));

    ck_assert_int_eq(
        bowie_dht_init(&d, NULL, &local,
                       g_hashes, TEST_HASHES_CAP,
                       g_peers, TEST_PEERS_CAP,
                       g_metadata,
                       g_rate_limits, TEST_RATE_LIMITS_CAP,
                       1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_local)
{
    bowie_dht_config_t c = make_config();
    bowie_dht_t d;
    memset(&d, 0, sizeof(d));

    ck_assert_int_eq(
        bowie_dht_init(&d, &c, NULL,
                       g_hashes, TEST_HASHES_CAP,
                       g_peers, TEST_PEERS_CAP,
                       g_metadata,
                       g_rate_limits, TEST_RATE_LIMITS_CAP,
                       1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_hashes)
{
    bowie_dht_config_t c = make_config();
    bowie_dht_node_id_t local;
    make_local_id(&local);
    bowie_dht_t d;
    memset(&d, 0, sizeof(d));

    ck_assert_int_eq(
        bowie_dht_init(&d, &c, &local,
                       NULL, 0u,
                       g_peers, TEST_PEERS_CAP,
                       g_metadata,
                       g_rate_limits, TEST_RATE_LIMITS_CAP,
                       1000u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_ok)
{
    bowie_dht_t d = make_dht(1000u);
    ck_assert_int_eq(d.initialized, 1);
    ck_assert_uint_eq(bowie_dht_node_count(&d), 0u);
    ck_assert_uint_eq(bowie_dht_hash_count(&d), 0u);
    ck_assert_uint_eq(bowie_dht_peer_count(&d), 0u);
}
END_TEST

START_TEST(test_shutdown)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_shutdown(&d);
    ck_assert_int_eq(d.initialized, 0);
}
END_TEST

START_TEST(test_shutdown_null)
{
    bowie_dht_shutdown(NULL);
}
END_TEST

START_TEST(test_clear_keeps_config)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_mtime_t saved = d.last_refresh_ms;
    (void)saved;
    uint32_t saved_refresh = d.config.refresh_interval_s;

    bowie_dht_clear(&d);
    ck_assert_uint_eq(d.config.refresh_interval_s,
                      saved_refresh);
    ck_assert_uint_eq(d.last_refresh_ms, 0u);
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_dht_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * QUERY HELPERS
 * ============================================================================
 */

START_TEST(test_local_id_null)
{
    ck_assert_ptr_null(bowie_dht_local_id(NULL));
}
END_TEST

START_TEST(test_local_id_ok)
{
    bowie_dht_t d = make_dht(1000u);
    const bowie_dht_node_id_t *id = bowie_dht_local_id(&d);
    ck_assert_ptr_nonnull(id);
    ck_assert_uint_eq(id->bytes[0], 0x10u);
}
END_TEST

START_TEST(test_node_count_null)
{
    ck_assert_uint_eq(bowie_dht_node_count(NULL), 0u);
}
END_TEST

START_TEST(test_hash_count_null)
{
    ck_assert_uint_eq(bowie_dht_hash_count(NULL), 0u);
}
END_TEST

START_TEST(test_peer_count_null)
{
    ck_assert_uint_eq(bowie_dht_peer_count(NULL), 0u);
}
END_TEST

/*
 * ============================================================================
 * QUERY BUILDER
 * ============================================================================
 */

START_TEST(test_make_query_null)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(NULL, BOWIE_DHT_QUERY_PING,
                             NULL, NULL, NULL, 0u, &m),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_PING,
                             NULL, NULL, NULL, 0u, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_make_query_ping)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_PING,
                             NULL, NULL, NULL, 0u, &m),
        BOWIE_OK);
    ck_assert_int_eq(m.type, BOWIE_DHT_MSG_QUERY);
    ck_assert_int_eq(m.query_type, BOWIE_DHT_QUERY_PING);
    ck_assert_uint_eq(m.tid_len, 2u);
    ck_assert(bowie_dht_node_id_equal(&m.sender_id,
                                      &d.local_id));
}
END_TEST

START_TEST(test_make_query_find_node_requires_target)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_FIND_NODE,
                             NULL, NULL, NULL, 0u, &m),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_make_query_find_node_ok)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_node_id_t target;
    memset(&target, 0xAA, sizeof(target));
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_FIND_NODE,
                             &target, NULL, NULL, 0u, &m),
        BOWIE_OK);
    ck_assert_int_eq(m.query_type, BOWIE_DHT_QUERY_FIND_NODE);
    ck_assert(bowie_dht_node_id_equal(&m.target, &target));
}
END_TEST

START_TEST(test_make_query_get_peers_requires_hash)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_GET_PEERS,
                             NULL, NULL, NULL, 0u, &m),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_make_query_get_peers_ok)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_info_hash_t h;
    make_info_hash(&h, 0x42u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_GET_PEERS,
                             NULL, &h, NULL, 0u, &m),
        BOWIE_OK);
    ck_assert_int_eq(m.query_type, BOWIE_DHT_QUERY_GET_PEERS);
    ck_assert(bowie_dht_info_hash_equal(&m.info_hash, &h));
}
END_TEST

START_TEST(test_make_query_announce_peer_ok)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_info_hash_t h;
    make_info_hash(&h, 0x42u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_ANNOUNCE_PEER,
                             NULL, &h, NULL, 0u, &m),
        BOWIE_OK);
    ck_assert_int_eq(m.query_type,
                     BOWIE_DHT_QUERY_ANNOUNCE_PEER);
}
END_TEST

START_TEST(test_make_query_custom_tid)
{
    bowie_dht_t d = make_dht(1000u);
    uint8_t tid[2] = { 0xAB, 0xCD };
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_PING,
                             NULL, NULL, tid, 2u, &m),
        BOWIE_OK);
    ck_assert_uint_eq(m.tid_len, 2u);
    ck_assert_mem_eq(m.tid, tid, 2u);
}
END_TEST

START_TEST(test_make_query_tid_too_long)
{
    bowie_dht_t d = make_dht(1000u);
    uint8_t tid[3] = { 0x01, 0x02, 0x03 };
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d, BOWIE_DHT_QUERY_PING,
                             NULL, NULL, tid, 3u, &m),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_make_query_unknown_type)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t m;

    ck_assert_int_eq(
        bowie_dht_make_query(&d,
                             (bowie_dht_query_type_t)99,
                             NULL, NULL, NULL, 0u, &m),
        BOWIE_ERR_INVAL);
}
END_TEST

/*
 * ============================================================================
 * MESSAGE HANDLING — PING
 * ============================================================================
 */

START_TEST(test_handle_ping)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_arena_t a = make_arena();

    bowie_dht_message_t q;
    memset(&q, 0, sizeof(q));
    q.type = BOWIE_DHT_MSG_QUERY;
    q.query_type = BOWIE_DHT_QUERY_PING;
    q.tid[0] = 0x11;
    q.tid_len = 1u;
    /* Sender id matches the address low bits. */
    memset(&q.sender_id, 0, sizeof(q.sender_id));
    q.sender_id.bytes[0] = 0x02u;

    bowie_addr_t from;
    make_addr(&from, 0x0Au, 6881u);

    bowie_dht_message_t resp;
    int has = 0;
    ck_assert_int_eq(
        bowie_dht_handle_message(&d, &q, &from, 1000u,
                                 &a, &resp, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(resp.type, BOWIE_DHT_MSG_RESPONSE);
    ck_assert_uint_eq(resp.tid_len, 1u);
    ck_assert_uint_eq(resp.tid[0], 0x11u);
}
END_TEST

START_TEST(test_handle_message_null)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_arena_t a = make_arena();
    bowie_dht_message_t m;
    memset(&m, 0, sizeof(m));
    bowie_addr_t from;
    make_addr(&from, 0x0Au, 6881u);
    bowie_dht_message_t resp;
    int has = 0;

    ck_assert_int_eq(
        bowie_dht_handle_message(NULL, &m, &from, 1000u,
                                 &a, &resp, &has),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_handle_message(&d, NULL, &from, 1000u,
                                 &a, &resp, &has),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_handle_message(&d, &m, NULL, 1000u,
                                 &a, &resp, &has),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_handle_message(&d, &m, &from, 1000u,
                                 &a, NULL, &has),
        BOWIE_ERR_NULL_ARG);
    ck_assert_int_eq(
        bowie_dht_handle_message(&d, &m, &from, 1000u,
                                 &a, &resp, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * MAINTENANCE — TICK
 * ============================================================================
 */

START_TEST(test_tick_null)
{
    ck_assert_int_eq(bowie_dht_tick(NULL, 1000u, NULL, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_tick_uninit)
{
    bowie_dht_t d;
    memset(&d, 0, sizeof(d));
    ck_assert_int_eq(bowie_dht_tick(&d, 1000u, NULL, NULL),
                     BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_tick_no_refresh_yet)
{
    bowie_dht_t d = make_dht(1000u);
    bowie_dht_message_t r;
    int has = 0;

    ck_assert_int_eq(bowie_dht_tick(&d, 1000u, &r, &has),
                     BOWIE_OK);
    ck_assert_int_eq(has, 0);
}
END_TEST

START_TEST(test_tick_no_out_no_crash)
{
    bowie_dht_t d = make_dht(1000u);
    ck_assert_int_eq(bowie_dht_tick(&d, 1000u, NULL, NULL),
                     BOWIE_OK);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *dht_suite(void)
{
    Suite *s = suite_create("DhtEngine");

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null_dht);
    tcase_add_test(tc_life, test_init_null_config);
    tcase_add_test(tc_life, test_init_null_local);
    tcase_add_test(tc_life, test_init_null_hashes);
    tcase_add_test(tc_life, test_init_ok);
    tcase_add_test(tc_life, test_shutdown);
    tcase_add_test(tc_life, test_shutdown_null);
    tcase_add_test(tc_life, test_clear_keeps_config);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_q = tcase_create("QueryHelpers");
    tcase_add_test(tc_q, test_local_id_null);
    tcase_add_test(tc_q, test_local_id_ok);
    tcase_add_test(tc_q, test_node_count_null);
    tcase_add_test(tc_q, test_hash_count_null);
    tcase_add_test(tc_q, test_peer_count_null);
    suite_add_tcase(s, tc_q);

    TCase *tc_mq = tcase_create("MakeQuery");
    tcase_add_test(tc_mq, test_make_query_null);
    tcase_add_test(tc_mq, test_make_query_ping);
    tcase_add_test(tc_mq, test_make_query_find_node_requires_target);
    tcase_add_test(tc_mq, test_make_query_find_node_ok);
    tcase_add_test(tc_mq, test_make_query_get_peers_requires_hash);
    tcase_add_test(tc_mq, test_make_query_get_peers_ok);
    tcase_add_test(tc_mq, test_make_query_announce_peer_ok);
    tcase_add_test(tc_mq, test_make_query_custom_tid);
    tcase_add_test(tc_mq, test_make_query_tid_too_long);
    tcase_add_test(tc_mq, test_make_query_unknown_type);
    suite_add_tcase(s, tc_mq);

    TCase *tc_hm = tcase_create("HandleMessage");
    tcase_add_test(tc_hm, test_handle_ping);
    tcase_add_test(tc_hm, test_handle_message_null);
    suite_add_tcase(s, tc_hm);

    TCase *tc_tick = tcase_create("Tick");
    tcase_add_test(tc_tick, test_tick_null);
    tcase_add_test(tc_tick, test_tick_uninit);
    tcase_add_test(tc_tick, test_tick_no_refresh_yet);
    tcase_add_test(tc_tick, test_tick_no_out_no_crash);
    suite_add_tcase(s, tc_tick);

    return s;
}

int main(void)
{
    Suite *s = dht_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
