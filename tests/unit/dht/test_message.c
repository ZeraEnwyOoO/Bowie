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
 * BOWIE — DHT MESSAGE TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/message.c.
 *
 * The tests cover:
 *
 *   - Name helpers: type names, query name parsing.
 *   - Compact format: node and peer decode and encode.
 *   - Parse: query, response, error.
 *   - Serialize: query, response, error.
 *   - Round trip: serialize then parse, check the fields.
 *
 * The test vectors are the Mainline messages in the BitTorrent
 * DHT specification, adapted for Bowie's node id and info hash
 * sizes.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memcmp, memcpy
 *   "bowie/err.h"                error codes
 *   "dht/message.h"              the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/message.h"

/*
 * ============================================================================
 * TEST ARENAS
 * ============================================================================
 */

#define TEST_VALUE_CAP   64
#define TEST_ENTRY_CAP   32
#define TEST_NODES_CAP   16
#define TEST_PEERS_CAP   16

static bowie_bencode_value_t      g_values[TEST_VALUE_CAP];
static bowie_bencode_dict_entry_t g_entries[TEST_ENTRY_CAP];
static bowie_dht_compact_node_t   g_nodes[TEST_NODES_CAP];
static bowie_dht_compact_peer_t   g_peers[TEST_PEERS_CAP];

static bowie_bencode_arena_t make_benc_arena(void)
{
    bowie_bencode_arena_t a;
    a.values       = g_values;
    a.values_cap   = TEST_VALUE_CAP;
    a.values_used  = 0u;
    a.entries      = g_entries;
    a.entries_cap  = TEST_ENTRY_CAP;
    a.entries_used = 0u;
    a.lenient_used = 0;
    return a;
}

static bowie_dht_message_arena_t make_msg_arena(void)
{
    bowie_dht_message_arena_t a;
    a.nodes      = g_nodes;
    a.nodes_cap  = TEST_NODES_CAP;
    a.nodes_used = 0u;
    a.peers      = g_peers;
    a.peers_cap  = TEST_PEERS_CAP;
    a.peers_used = 0u;
    return a;
}

static bowie_span_t span_of(const char *s)
{
    bowie_span_t sp;
    sp.data = (const uint8_t *)s;
    sp.len  = strlen(s);
    return sp;
}

static void make_node_id(bowie_dht_node_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_NODE_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_info_hash(bowie_dht_info_hash_t *h, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_DHT_INFO_HASH_LEN; i++) {
        h->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_token(bowie_dht_token_t *t, uint8_t seed, size_t len)
{
    memset(t, 0, sizeof(*t));
    for (size_t i = 0u; i < len && i < BOWIE_DHT_TOKEN_MAX; i++) {
        t->bytes[i] = (uint8_t)(seed + i);
    }
    t->len = len;
}

/*
 * ============================================================================
 * NAME HELPERS
 * ============================================================================
 */

START_TEST(test_msg_type_name_query)
{
    ck_assert_str_eq(bowie_dht_msg_type_name(BOWIE_DHT_MSG_QUERY),
                     "query");
}
END_TEST

START_TEST(test_msg_type_name_response)
{
    ck_assert_str_eq(bowie_dht_msg_type_name(BOWIE_DHT_MSG_RESPONSE),
                     "response");
}
END_TEST

START_TEST(test_msg_type_name_error)
{
    ck_assert_str_eq(bowie_dht_msg_type_name(BOWIE_DHT_MSG_ERROR),
                     "error");
}
END_TEST

START_TEST(test_msg_type_name_unknown)
{
    ck_assert_str_eq(bowie_dht_msg_type_name(BOWIE_DHT_MSG_UNKNOWN),
                     "unknown");
}
END_TEST

START_TEST(test_query_type_name_ping)
{
    ck_assert_str_eq(bowie_dht_query_type_name(BOWIE_DHT_QUERY_PING),
                     "ping");
}
END_TEST

START_TEST(test_query_type_name_find_node)
{
    ck_assert_str_eq(
        bowie_dht_query_type_name(BOWIE_DHT_QUERY_FIND_NODE),
        "find_node");
}
END_TEST

START_TEST(test_query_type_name_get_peers)
{
    ck_assert_str_eq(
        bowie_dht_query_type_name(BOWIE_DHT_QUERY_GET_PEERS),
        "get_peers");
}
END_TEST

START_TEST(test_query_type_name_announce_peer)
{
    ck_assert_str_eq(
        bowie_dht_query_type_name(BOWIE_DHT_QUERY_ANNOUNCE_PEER),
        "announce_peer");
}
END_TEST

START_TEST(test_query_type_from_name_ping)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("ping")),
        BOWIE_DHT_QUERY_PING);
}
END_TEST

START_TEST(test_query_type_from_name_find_node)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("find_node")),
        BOWIE_DHT_QUERY_FIND_NODE);
}
END_TEST

START_TEST(test_query_type_from_name_get_peers)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("get_peers")),
        BOWIE_DHT_QUERY_GET_PEERS);
}
END_TEST

START_TEST(test_query_type_from_name_announce_peer)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("announce_peer")),
        BOWIE_DHT_QUERY_ANNOUNCE_PEER);
}
END_TEST

START_TEST(test_query_type_from_name_unknown)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("bogus")),
        BOWIE_DHT_QUERY_UNKNOWN);
}
END_TEST

START_TEST(test_query_type_from_name_empty)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("")),
        BOWIE_DHT_QUERY_UNKNOWN);
}
END_TEST

START_TEST(test_query_type_from_name_case_sensitive)
{
    ck_assert_int_eq(
        bowie_dht_query_type_from_name(span_of("PING")),
        BOWIE_DHT_QUERY_UNKNOWN);
}
END_TEST

/*
 * ============================================================================
 * COMPACT NODES
 * ============================================================================
 */

START_TEST(test_compact_nodes_empty)
{
    bowie_dht_message_arena_t a = make_msg_arena();
    bowie_span_t in = { NULL, 0u };
    bowie_dht_compact_node_t *nodes = NULL;
    size_t count = 99u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_decode(in, &a, &nodes, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 0u);
}
END_TEST

START_TEST(test_compact_nodes_bad_length)
{
    bowie_dht_message_arena_t a = make_msg_arena();
    uint8_t buf[27] = { 0 };
    bowie_span_t in = { buf, 27u };
    bowie_dht_compact_node_t *nodes = NULL;
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_decode(in, &a, &nodes, &count),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_compact_nodes_round_trip)
{
    bowie_dht_compact_node_t in_nodes[2];
    memset(in_nodes, 0, sizeof(in_nodes));

    make_node_id(&in_nodes[0].id, 1u);
    in_nodes[0].addr.family = BOWIE_AF_INET;
    in_nodes[0].addr.addr[0] = 10;
    in_nodes[0].addr.addr[1] = 0;
    in_nodes[0].addr.addr[2] = 0;
    in_nodes[0].addr.addr[3] = 1;
    in_nodes[0].addr.port = 6881;

    make_node_id(&in_nodes[1].id, 50u);
    in_nodes[1].addr.family = BOWIE_AF_INET;
    in_nodes[1].addr.addr[0] = 192;
    in_nodes[1].addr.addr[1] = 168;
    in_nodes[1].addr.addr[2] = 1;
    in_nodes[1].addr.addr[3] = 2;
    in_nodes[1].addr.port = 51413;

    uint8_t buf[2 * BOWIE_DHT_COMPACT_NODE_LEN];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_encode(in_nodes, 2u,
                                       buf, sizeof(buf), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 2u * BOWIE_DHT_COMPACT_NODE_LEN);

    bowie_dht_message_arena_t a = make_msg_arena();
    bowie_span_t encoded = { buf, out_len };
    bowie_dht_compact_node_t *out_nodes = NULL;
    size_t out_count = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_decode(encoded, &a,
                                       &out_nodes, &out_count),
        BOWIE_OK);
    ck_assert_uint_eq(out_count, 2u);

    ck_assert(bowie_dht_node_id_equal(&in_nodes[0].id,
                                      &out_nodes[0].id));
    ck_assert_uint_eq(out_nodes[0].addr.addr[0], 10u);
    ck_assert_uint_eq(out_nodes[0].addr.port, 6881u);

    ck_assert(bowie_dht_node_id_equal(&in_nodes[1].id,
                                      &out_nodes[1].id));
    ck_assert_uint_eq(out_nodes[1].addr.addr[0], 192u);
    ck_assert_uint_eq(out_nodes[1].addr.port, 51413u);
}
END_TEST

START_TEST(test_compact_nodes_encode_non_ipv4)
{
    bowie_dht_compact_node_t n;
    memset(&n, 0, sizeof(n));
    make_node_id(&n.id, 1u);
    n.addr.family = BOWIE_AF_INET6;

    uint8_t buf[BOWIE_DHT_COMPACT_NODE_LEN];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_encode(&n, 1u,
                                       buf, sizeof(buf), &out_len),
        BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_compact_nodes_encode_too_small)
{
    bowie_dht_compact_node_t n;
    memset(&n, 0, sizeof(n));
    make_node_id(&n.id, 1u);
    n.addr.family = BOWIE_AF_INET;

    uint8_t buf[BOWIE_DHT_COMPACT_NODE_LEN - 1u];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_nodes_encode(&n, 1u,
                                       buf, sizeof(buf), &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

/*
 * ============================================================================
 * COMPACT PEERS
 * ============================================================================
 */

START_TEST(test_compact_peers_empty)
{
    bowie_dht_message_arena_t a = make_msg_arena();
    bowie_span_t in = { NULL, 0u };
    bowie_dht_compact_peer_t *peers = NULL;
    size_t count = 99u;

    ck_assert_int_eq(
        bowie_dht_compact_peers_decode(in, &a, &peers, &count),
        BOWIE_OK);
    ck_assert_uint_eq(count, 0u);
}
END_TEST

START_TEST(test_compact_peers_bad_length)
{
    bowie_dht_message_arena_t a = make_msg_arena();
    uint8_t buf[5] = { 0 };
    bowie_span_t in = { buf, 5u };
    bowie_dht_compact_peer_t *peers = NULL;
    size_t count = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_peers_decode(in, &a, &peers, &count),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_compact_peers_round_trip)
{
    bowie_dht_compact_peer_t in_peers[2];
    memset(in_peers, 0, sizeof(in_peers));

    in_peers[0].addr.family = BOWIE_AF_INET;
    in_peers[0].addr.addr[0] = 1;
    in_peers[0].addr.addr[1] = 2;
    in_peers[0].addr.addr[2] = 3;
    in_peers[0].addr.addr[3] = 4;
    in_peers[0].addr.port = 80;

    in_peers[1].addr.family = BOWIE_AF_INET;
    in_peers[1].addr.addr[0] = 5;
    in_peers[1].addr.addr[1] = 6;
    in_peers[1].addr.addr[2] = 7;
    in_peers[1].addr.addr[3] = 8;
    in_peers[1].addr.port = 443;

    uint8_t buf[2 * BOWIE_DHT_COMPACT_PEER_LEN];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_peers_encode(in_peers, 2u,
                                       buf, sizeof(buf), &out_len),
        BOWIE_OK);

    bowie_dht_message_arena_t a = make_msg_arena();
    bowie_span_t encoded = { buf, out_len };
    bowie_dht_compact_peer_t *out_peers = NULL;
    size_t out_count = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_peers_decode(encoded, &a,
                                       &out_peers, &out_count),
        BOWIE_OK);
    ck_assert_uint_eq(out_count, 2u);
    ck_assert_uint_eq(out_peers[0].addr.port, 80u);
    ck_assert_uint_eq(out_peers[1].addr.port, 443u);
}
END_TEST

START_TEST(test_compact_peers_encode_non_ipv4)
{
    bowie_dht_compact_peer_t p;
    memset(&p, 0, sizeof(p));
    p.addr.family = BOWIE_AF_INET6;

    uint8_t buf[BOWIE_DHT_COMPACT_PEER_LEN];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_dht_compact_peers_encode(&p, 1u,
                                       buf, sizeof(buf), &out_len),
        BOWIE_ERR_TYPE);
}
END_TEST

/*
 * ============================================================================
 * PARSE — PING QUERY
 * ============================================================================
 */

START_TEST(test_parse_ping_query)
{
    /*
     * A minimal ping query:
     * d1:t2:aa1:y1:q1:q4:ping1:ad2:id20:...ee
     */
    const char *wire =
        "d1:t2:aa"
        "1:y1:q"
        "1:q4:ping"
        "1:ad2:id20:";
    uint8_t id_bytes[20];
    for (size_t i = 0u; i < 20u; i++) {
        id_bytes[i] = (uint8_t)(1u + i);
    }

    uint8_t buf[128];
    size_t  pos = 0u;
    memcpy(buf, wire, strlen(wire));
    pos = strlen(wire);
    memcpy(buf + pos, id_bytes, 20);
    pos += 20;
    buf[pos++] = 'e';
    buf[pos++] = 'e';

    bowie_span_t in = { buf, pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_OK);
    ck_assert_int_eq(msg.type, BOWIE_DHT_MSG_QUERY);
    ck_assert_int_eq(msg.query_type, BOWIE_DHT_QUERY_PING);
    ck_assert_uint_eq(msg.tid_len, 2u);
    ck_assert_mem_eq(msg.tid, "aa", 2u);
    ck_assert_uint_eq(msg.sender_id.bytes[0], 1u);
}
END_TEST

/*
 * ============================================================================
 * PARSE — FIND_NODE QUERY
 * ============================================================================
 */

START_TEST(test_parse_find_node_query)
{
    const char *wire =
        "d1:t2:bb"
        "1:y1:q"
        "1:q9:find_node"
        "1:ad2:id20:";
    uint8_t id_bytes[20];
    for (size_t i = 0u; i < 20u; i++) {
        id_bytes[i] = (uint8_t)(10u + i);
    }
    uint8_t target_bytes[20];
    for (size_t i = 0u; i < 20u; i++) {
        target_bytes[i] = (uint8_t)(100u + i);
    }

    uint8_t buf[256];
    size_t pos = 0u;
    memcpy(buf, wire, strlen(wire));
    pos = strlen(wire);
    memcpy(buf + pos, id_bytes, 20);
    pos += 20;
    const char *mid = "6:target20:";
    memcpy(buf + pos, mid, strlen(mid));
    pos += strlen(mid);
    memcpy(buf + pos, target_bytes, 20);
    pos += 20;
    buf[pos++] = 'e';
    buf[pos++] = 'e';

    bowie_span_t in = { buf, pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_OK);
    ck_assert_int_eq(msg.query_type, BOWIE_DHT_QUERY_FIND_NODE);
    ck_assert_uint_eq(msg.sender_id.bytes[0], 10u);
    ck_assert_uint_eq(msg.target.bytes[0], 100u);
}
END_TEST

/*
 * ============================================================================
 * PARSE — GET_PEERS QUERY
 * ============================================================================
 */

START_TEST(test_parse_get_peers_query)
{
    const char *wire =
        "d1:t2:cc"
        "1:y1:q"
        "1:q9:get_peers"
        "1:ad2:id20:";
    uint8_t id_bytes[20] = { 0 };
    uint8_t ih_bytes[20] = { 0 };
    ih_bytes[0] = 0xAB;
    ih_bytes[19] = 0xCD;

    uint8_t buf[256];
    size_t pos = 0u;
    memcpy(buf, wire, strlen(wire));
    pos = strlen(wire);
    memcpy(buf + pos, id_bytes, 20);
    pos += 20;
    const char *mid = "9:info_hash20:";
    memcpy(buf + pos, mid, strlen(mid));
    pos += strlen(mid);
    memcpy(buf + pos, ih_bytes, 20);
    pos += 20;
    buf[pos++] = 'e';
    buf[pos++] = 'e';

    bowie_span_t in = { buf, pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_OK);
    ck_assert_int_eq(msg.query_type, BOWIE_DHT_QUERY_GET_PEERS);
    ck_assert_uint_eq(msg.info_hash.bytes[0], 0xABu);
    ck_assert_uint_eq(msg.info_hash.bytes[19], 0xCDu);
}
END_TEST

/*
 * ============================================================================
 * PARSE — ANNOUNCE_PEER QUERY
 * ============================================================================
 */

START_TEST(test_parse_announce_peer_query)
{
    const char *wire =
        "d1:t2:dd"
        "1:y1:q"
        "1:q13:announce_peer"
        "1:ad2:id20:";
    uint8_t id_bytes[20] = { 0 };
    uint8_t ih_bytes[20] = { 0 };
    ih_bytes[5] = 0x42;

    uint8_t buf[512];
    size_t pos = 0u;
    memcpy(buf, wire, strlen(wire));
    pos = strlen(wire);
    memcpy(buf + pos, id_bytes, 20);
    pos += 20;

    const char *mid = "9:info_hash20:";
    memcpy(buf + pos, mid, strlen(mid));
    pos += strlen(mid);
    memcpy(buf + pos, ih_bytes, 20);
    pos += 20;

    const char *port = "4:porti6881e";
    memcpy(buf + pos, port, strlen(port));
    pos += strlen(port);

    const char *tok = "5:token4:abcd";
    memcpy(buf + pos, tok, strlen(tok));
    pos += strlen(tok);

    const char *ip = "12:implied_porti1e";
    memcpy(buf + pos, ip, strlen(ip));
    pos += strlen(ip);

    buf[pos++] = 'e';
    buf[pos++] = 'e';

    bowie_span_t in = { buf, pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_OK);
    ck_assert_int_eq(msg.query_type,
                     BOWIE_DHT_QUERY_ANNOUNCE_PEER);
    ck_assert_uint_eq(msg.port, 6881u);
    ck_assert_uint_eq(msg.token.len, 4u);
    ck_assert_mem_eq(msg.token.bytes, "abcd", 4u);
    ck_assert_int_eq(msg.implied_port, 1);
}
END_TEST

/*
 * ============================================================================
 * PARSE — ERROR
 * ============================================================================
 */

START_TEST(test_parse_error)
{
    const char *wire = "d1:t2:ee1:y1:e1:eli201e4:oops ee";
    /*
     * The exact bytes:
     *   d
     *   1:t 2:ee
     *   1:y 1:e
     *   1:e l i201e 4:oops e
     *   e
     */
    const char *wire2 =
        "d1:t2:ee1:y1:e1:eli201e4:oopsee";

    bowie_span_t in = span_of(wire2);
    (void)wire;

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_OK);
    ck_assert_int_eq(msg.type, BOWIE_DHT_MSG_ERROR);
    ck_assert_int_eq(msg.error_code, 201);
    ck_assert_uint_eq(msg.error_message.len, 4u);
    ck_assert_mem_eq(msg.error_message.data, "oops", 4u);
}
END_TEST

/*
 * ============================================================================
 * PARSE — ERRORS
 * ============================================================================
 */

START_TEST(test_parse_null_benc_arena)
{
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("de");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, NULL, &ma, &msg),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_null_msg_arena)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("de");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, NULL, &msg),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_null_out)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_span_t in = span_of("de");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_not_a_dict)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_parse_missing_t)
{
    /* d1:y1:qe — has y but no t. */
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("d1:y1:qe");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_missing_y)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("d1:t2:aae");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_bad_y)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    bowie_span_t in = span_of("d1:t2:aa1:y1:xe");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_tid_too_long)
{
    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg;
    /* tid "abc" is 3 bytes, more than the limit. */
    bowie_span_t in =
        span_of("d1:t3:abc1:y1:qe");

    ck_assert_int_eq(
        bowie_dht_message_parse(in, &ba, &ma, &msg),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP — QUERY
 * ============================================================================
 */

START_TEST(test_round_trip_ping_query)
{
    bowie_dht_message_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = BOWIE_DHT_MSG_QUERY;
    msg_out.query_type = BOWIE_DHT_QUERY_PING;
    msg_out.tid[0] = 'x';
    msg_out.tid[1] = 'y';
    msg_out.tid_len = 2u;
    make_node_id(&msg_out.sender_id, 1u);

    uint8_t buf[256];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_dht_message_serialize(&msg_out, &w),
        BOWIE_OK);

    bowie_span_t encoded = { buf, w.pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg_in;

    ck_assert_int_eq(
        bowie_dht_message_parse(encoded, &ba, &ma, &msg_in),
        BOWIE_OK);
    ck_assert_int_eq(msg_in.type, BOWIE_DHT_MSG_QUERY);
    ck_assert_int_eq(msg_in.query_type, BOWIE_DHT_QUERY_PING);
    ck_assert_uint_eq(msg_in.tid_len, 2u);
    ck_assert_mem_eq(msg_in.tid, "xy", 2u);
    ck_assert(bowie_dht_node_id_equal(&msg_in.sender_id,
                                      &msg_out.sender_id));
}
END_TEST

START_TEST(test_round_trip_announce_peer_query)
{
    bowie_dht_message_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = BOWIE_DHT_MSG_QUERY;
    msg_out.query_type = BOWIE_DHT_QUERY_ANNOUNCE_PEER;
    msg_out.tid[0] = 'q';
    msg_out.tid[1] = '1';
    msg_out.tid_len = 2u;
    make_node_id(&msg_out.sender_id, 5u);
    make_info_hash(&msg_out.info_hash, 50u);
    msg_out.port = 6881u;
    make_token(&msg_out.token, 100u, 8u);
    msg_out.implied_port = 1;

    uint8_t buf[512];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_dht_message_serialize(&msg_out, &w),
        BOWIE_OK);

    bowie_span_t encoded = { buf, w.pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg_in;

    ck_assert_int_eq(
        bowie_dht_message_parse(encoded, &ba, &ma, &msg_in),
        BOWIE_OK);
    ck_assert_int_eq(msg_in.query_type,
                     BOWIE_DHT_QUERY_ANNOUNCE_PEER);
    ck_assert_uint_eq(msg_in.port, 6881u);
    ck_assert_uint_eq(msg_in.token.len, 8u);
    ck_assert_int_eq(msg_in.implied_port, 1);
    ck_assert(bowie_dht_info_hash_equal(&msg_in.info_hash,
                                        &msg_out.info_hash));
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP — RESPONSE WITH PEERS
 * ============================================================================
 */

START_TEST(test_round_trip_response_with_peers)
{
    bowie_dht_compact_peer_t peers[2];
    memset(peers, 0, sizeof(peers));

    peers[0].addr.family = BOWIE_AF_INET;
    peers[0].addr.addr[0] = 1;
    peers[0].addr.addr[1] = 2;
    peers[0].addr.addr[2] = 3;
    peers[0].addr.addr[3] = 4;
    peers[0].addr.port = 1111;

    peers[1].addr.family = BOWIE_AF_INET;
    peers[1].addr.addr[0] = 5;
    peers[1].addr.addr[1] = 6;
    peers[1].addr.addr[2] = 7;
    peers[1].addr.addr[3] = 8;
    peers[1].addr.port = 2222;

    bowie_dht_message_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = BOWIE_DHT_MSG_RESPONSE;
    msg_out.tid[0] = 'r';
    msg_out.tid_len = 1u;
    make_node_id(&msg_out.sender_id, 1u);
    msg_out.peers = peers;
    msg_out.peers_count = 2u;
    make_token(&msg_out.token, 200u, 4u);

    uint8_t buf[512];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_dht_message_serialize(&msg_out, &w),
        BOWIE_OK);

    bowie_span_t encoded = { buf, w.pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg_in;

    ck_assert_int_eq(
        bowie_dht_message_parse(encoded, &ba, &ma, &msg_in),
        BOWIE_OK);
    ck_assert_int_eq(msg_in.type, BOWIE_DHT_MSG_RESPONSE);
    ck_assert_uint_eq(msg_in.peers_count, 2u);
    ck_assert_uint_eq(msg_in.peers[0].addr.port, 1111u);
    ck_assert_uint_eq(msg_in.peers[1].addr.port, 2222u);
    ck_assert_uint_eq(msg_in.token.len, 4u);
}
END_TEST

START_TEST(test_round_trip_response_with_nodes)
{
    bowie_dht_compact_node_t nodes[1];
    memset(nodes, 0, sizeof(nodes));
    make_node_id(&nodes[0].id, 1u);
    nodes[0].addr.family = BOWIE_AF_INET;
    nodes[0].addr.addr[0] = 10;
    nodes[0].addr.addr[1] = 0;
    nodes[0].addr.addr[2] = 0;
    nodes[0].addr.addr[3] = 1;
    nodes[0].addr.port = 6881;

    bowie_dht_message_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = BOWIE_DHT_MSG_RESPONSE;
    msg_out.tid[0] = 'n';
    msg_out.tid_len = 1u;
    make_node_id(&msg_out.sender_id, 2u);
    msg_out.nodes = nodes;
    msg_out.nodes_count = 1u;

    uint8_t buf[512];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_dht_message_serialize(&msg_out, &w),
        BOWIE_OK);

    bowie_span_t encoded = { buf, w.pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg_in;

    ck_assert_int_eq(
        bowie_dht_message_parse(encoded, &ba, &ma, &msg_in),
        BOWIE_OK);
    ck_assert_int_eq(msg_in.type, BOWIE_DHT_MSG_RESPONSE);
    ck_assert_uint_eq(msg_in.nodes_count, 1u);
    ck_assert_uint_eq(msg_in.nodes[0].addr.port, 6881u);
    ck_assert(bowie_dht_node_id_equal(&msg_in.nodes[0].id,
                                      &nodes[0].id));
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP — ERROR
 * ============================================================================
 */

START_TEST(test_round_trip_error)
{
    bowie_dht_message_t msg_out;
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = BOWIE_DHT_MSG_ERROR;
    msg_out.tid[0] = 'e';
    msg_out.tid_len = 1u;
    msg_out.error_code = 201;
    const char *emsg = "generic error";
    msg_out.error_message.data = (const uint8_t *)emsg;
    msg_out.error_message.len  = strlen(emsg);

    uint8_t buf[256];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_dht_message_serialize(&msg_out, &w),
        BOWIE_OK);

    bowie_span_t encoded = { buf, w.pos };

    bowie_bencode_arena_t ba = make_benc_arena();
    bowie_dht_message_arena_t ma = make_msg_arena();
    bowie_dht_message_t msg_in;

    ck_assert_int_eq(
        bowie_dht_message_parse(encoded, &ba, &ma, &msg_in),
        BOWIE_OK);
    ck_assert_int_eq(msg_in.type, BOWIE_DHT_MSG_ERROR);
    ck_assert_int_eq(msg_in.error_code, 201);
    ck_assert_uint_eq(msg_in.error_message.len, strlen(emsg));
    ck_assert_mem_eq(msg_in.error_message.data, emsg,
                     strlen(emsg));
}
END_TEST

/*
 * ============================================================================
 * SERIALIZE — ERRORS
 * ============================================================================
 */

START_TEST(test_serialize_null_msg)
{
    uint8_t buf[64];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_dht_message_serialize(NULL, &w),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_serialize_null_writer)
{
    bowie_dht_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = BOWIE_DHT_MSG_QUERY;
    msg.query_type = BOWIE_DHT_QUERY_PING;

    ck_assert_int_eq(bowie_dht_message_serialize(&msg, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_serialize_unknown_type)
{
    bowie_dht_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = BOWIE_DHT_MSG_UNKNOWN;

    uint8_t buf[64];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_dht_message_serialize(&msg, &w),
                     BOWIE_ERR_INVAL);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *message_suite(void)
{
    Suite *s = suite_create("DhtMessage");

    TCase *tc_names = tcase_create("Names");
    tcase_add_test(tc_names, test_msg_type_name_query);
    tcase_add_test(tc_names, test_msg_type_name_response);
    tcase_add_test(tc_names, test_msg_type_name_error);
    tcase_add_test(tc_names, test_msg_type_name_unknown);
    tcase_add_test(tc_names, test_query_type_name_ping);
    tcase_add_test(tc_names, test_query_type_name_find_node);
    tcase_add_test(tc_names, test_query_type_name_get_peers);
    tcase_add_test(tc_names, test_query_type_name_announce_peer);
    tcase_add_test(tc_names, test_query_type_from_name_ping);
    tcase_add_test(tc_names, test_query_type_from_name_find_node);
    tcase_add_test(tc_names, test_query_type_from_name_get_peers);
    tcase_add_test(tc_names, test_query_type_from_name_announce_peer);
    tcase_add_test(tc_names, test_query_type_from_name_unknown);
    tcase_add_test(tc_names, test_query_type_from_name_empty);
    tcase_add_test(tc_names, test_query_type_from_name_case_sensitive);
    suite_add_tcase(s, tc_names);

    TCase *tc_cn = tcase_create("CompactNodes");
    tcase_add_test(tc_cn, test_compact_nodes_empty);
    tcase_add_test(tc_cn, test_compact_nodes_bad_length);
    tcase_add_test(tc_cn, test_compact_nodes_round_trip);
    tcase_add_test(tc_cn, test_compact_nodes_encode_non_ipv4);
    tcase_add_test(tc_cn, test_compact_nodes_encode_too_small);
    suite_add_tcase(s, tc_cn);

    TCase *tc_cp = tcase_create("CompactPeers");
    tcase_add_test(tc_cp, test_compact_peers_empty);
    tcase_add_test(tc_cp, test_compact_peers_bad_length);
    tcase_add_test(tc_cp, test_compact_peers_round_trip);
    tcase_add_test(tc_cp, test_compact_peers_encode_non_ipv4);
    suite_add_tcase(s, tc_cp);

    TCase *tc_pq = tcase_create("ParseQuery");
    tcase_add_test(tc_pq, test_parse_ping_query);
    tcase_add_test(tc_pq, test_parse_find_node_query);
    tcase_add_test(tc_pq, test_parse_get_peers_query);
    tcase_add_test(tc_pq, test_parse_announce_peer_query);
    suite_add_tcase(s, tc_pq);

    TCase *tc_pe = tcase_create("ParseError");
    tcase_add_test(tc_pe, test_parse_error);
    suite_add_tcase(s, tc_pe);

    TCase *tc_perr = tcase_create("ParseErrors");
    tcase_add_test(tc_perr, test_parse_null_benc_arena);
    tcase_add_test(tc_perr, test_parse_null_msg_arena);
    tcase_add_test(tc_perr, test_parse_null_out);
    tcase_add_test(tc_perr, test_parse_not_a_dict);
    tcase_add_test(tc_perr, test_parse_missing_t);
    tcase_add_test(tc_perr, test_parse_missing_y);
    tcase_add_test(tc_perr, test_parse_bad_y);
    tcase_add_test(tc_perr, test_parse_tid_too_long);
    suite_add_tcase(s, tc_perr);

    TCase *tc_rt = tcase_create("RoundTrip");
    tcase_add_test(tc_rt, test_round_trip_ping_query);
    tcase_add_test(tc_rt, test_round_trip_announce_peer_query);
    tcase_add_test(tc_rt, test_round_trip_response_with_peers);
    tcase_add_test(tc_rt, test_round_trip_response_with_nodes);
    tcase_add_test(tc_rt, test_round_trip_error);
    suite_add_tcase(s, tc_rt);

    TCase *tc_ser = tcase_create("SerializeErrors");
    tcase_add_test(tc_ser, test_serialize_null_msg);
    tcase_add_test(tc_ser, test_serialize_null_writer);
    tcase_add_test(tc_ser, test_serialize_unknown_type);
    suite_add_tcase(s, tc_ser);

    return s;
}

int main(void)
{
    Suite *s = message_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
