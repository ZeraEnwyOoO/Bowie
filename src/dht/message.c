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
 * BOWIE — DHT MESSAGE IMPLEMENTATION
 * ============================================================================
 *
 * Mainline DHT message parsing and serialization.
 *
 * The file is organized in three parts:
 *
 *   1. Name helpers: type names and query name parsing.
 *   2. Compact format: node and peer list decode and encode.
 *   3. Message parse and serialize.
 *
 * The three parts share the message struct and the arena.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O.
 *   - No policy.
 *   - No IPv6. The compact formats are the IPv4 ones.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The compact node and peer lists are byte strings. Each node
 * entry is 26 bytes, each peer entry is 6 bytes. The IP is in
 * network byte order on the wire; the parser converts it to
 * the host byte order used by bowie_addr_t.
 *
 * The parse function reads the bencode tree with the accessors
 * from the bencode module. It does not walk the tree by hand.
 *
 * The serialize function writes the bencode tree with the
 * writer functions from the bencode module. It does not build
 * the tree in memory first.
 *
 * A missing required field is reported as BOWIE_ERR_FORMAT. A
 * field with the wrong type is reported as BOWIE_ERR_TYPE. A
 * field that exceeds a limit is reported as BOWIE_ERR_TOO_LARGE.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   int64_t, uint8_t, uint16_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memcmp, memcpy
 *   "bowie/types.h"              bowie_span_t, bowie_addr_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, info hash, token
 *   "dht/bencode.h"              arena, value, writer
 *   "dht/message.h"              the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/bencode.h"
#include "dht/message.h"

/*
 * ============================================================================
 * PART 1 — NAME HELPERS
 * ============================================================================
 */

const char *bowie_dht_msg_type_name(bowie_dht_msg_type_t t)
{
    switch (t) {
    case BOWIE_DHT_MSG_QUERY:    return "query";
    case BOWIE_DHT_MSG_RESPONSE: return "response";
    case BOWIE_DHT_MSG_ERROR:    return "error";
    case BOWIE_DHT_MSG_UNKNOWN:
    default:                     return "unknown";
    }
}

const char *bowie_dht_query_type_name(bowie_dht_query_type_t q)
{
    switch (q) {
    case BOWIE_DHT_QUERY_PING:          return "ping";
    case BOWIE_DHT_QUERY_FIND_NODE:     return "find_node";
    case BOWIE_DHT_QUERY_GET_PEERS:     return "get_peers";
    case BOWIE_DHT_QUERY_ANNOUNCE_PEER: return "announce_peer";
    case BOWIE_DHT_QUERY_UNKNOWN:
    default:                            return "unknown";
    }
}

/*
 * ============================================================================
 * INTERNAL — SPAN COMPARISON
 * ============================================================================
 */

static int span_equal_cstr(bowie_span_t s, const char *cstr)
{
    size_t len = strlen(cstr);
    if (s.len != len) {
        return 0;
    }
    if (len == 0u) {
        return 1;
    }
    if (s.data == NULL) {
        return 0;
    }
    return (memcmp(s.data, cstr, len) == 0) ? 1 : 0;
}

bowie_dht_query_type_t bowie_dht_query_type_from_name(
    bowie_span_t name)
{
    if (span_equal_cstr(name, "ping")) {
        return BOWIE_DHT_QUERY_PING;
    }
    if (span_equal_cstr(name, "find_node")) {
        return BOWIE_DHT_QUERY_FIND_NODE;
    }
    if (span_equal_cstr(name, "get_peers")) {
        return BOWIE_DHT_QUERY_GET_PEERS;
    }
    if (span_equal_cstr(name, "announce_peer")) {
        return BOWIE_DHT_QUERY_ANNOUNCE_PEER;
    }
    return BOWIE_DHT_QUERY_UNKNOWN;
}

/*
 * ============================================================================
 * PART 2 — COMPACT NODE FORMAT
 * ============================================================================
 *
 * A compact node entry is 26 bytes:
 *
 *   20 bytes   node id
 *    4 bytes   IPv4 address, network byte order
 *    2 bytes   port, big-endian
 */

bowie_error_t bowie_dht_compact_nodes_decode(
    bowie_span_t                encoded,
    bowie_dht_message_arena_t  *arena,
    bowie_dht_compact_node_t  **out_nodes,
    size_t                     *out_count)
{
    if (arena == NULL || out_nodes == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (encoded.len > 0u && encoded.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (encoded.len % BOWIE_DHT_COMPACT_NODE_LEN != 0u) {
        return BOWIE_ERR_FORMAT;
    }

    size_t count = encoded.len / BOWIE_DHT_COMPACT_NODE_LEN;

    if (count > arena->nodes_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    for (size_t i = 0u; i < count; i++) {
        const uint8_t *p = encoded.data + i * BOWIE_DHT_COMPACT_NODE_LEN;

        bowie_dht_compact_node_t *n = &arena->nodes[i];

        memcpy(n->id.bytes, p, BOWIE_DHT_NODE_ID_LEN);

        memset(&n->addr, 0, sizeof(n->addr));
        n->addr.family = BOWIE_AF_INET;
        n->addr.addr[0] = p[20];
        n->addr.addr[1] = p[21];
        n->addr.addr[2] = p[22];
        n->addr.addr[3] = p[23];

        uint16_t port_be = (uint16_t)((uint16_t)p[24] << 8)
                         | (uint16_t)p[25];
        n->addr.port = port_be;
    }

    arena->nodes_used = count;
    *out_nodes = arena->nodes;
    *out_count = count;
    return BOWIE_OK;
}

bowie_error_t bowie_dht_compact_nodes_encode(
    const bowie_dht_compact_node_t *nodes,
    size_t                          count,
    uint8_t                        *out,
    size_t                          out_cap,
    size_t                         *out_len)
{
    if (out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (count > 0u && (nodes == NULL || out == NULL)) {
        return BOWIE_ERR_NULL_ARG;
    }

    size_t required = count * BOWIE_DHT_COMPACT_NODE_LEN;
    if (required > out_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    for (size_t i = 0u; i < count; i++) {
        const bowie_dht_compact_node_t *n = &nodes[i];

        if (n->addr.family != BOWIE_AF_INET) {
            return BOWIE_ERR_TYPE;
        }

        uint8_t *p = out + i * BOWIE_DHT_COMPACT_NODE_LEN;

        memcpy(p, n->id.bytes, BOWIE_DHT_NODE_ID_LEN);
        p[20] = n->addr.addr[0];
        p[21] = n->addr.addr[1];
        p[22] = n->addr.addr[2];
        p[23] = n->addr.addr[3];
        p[24] = (uint8_t)((n->addr.port >> 8) & 0xFFu);
        p[25] = (uint8_t)(n->addr.port & 0xFFu);
    }

    *out_len = required;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * PART 2 — COMPACT PEER FORMAT
 * ============================================================================
 *
 * A compact peer entry is 6 bytes:
 *
 *    4 bytes   IPv4 address, network byte order
 *    2 bytes   port, big-endian
 */

bowie_error_t bowie_dht_compact_peers_decode(
    bowie_span_t                encoded,
    bowie_dht_message_arena_t  *arena,
    bowie_dht_compact_peer_t  **out_peers,
    size_t                     *out_count)
{
    if (arena == NULL || out_peers == NULL || out_count == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (encoded.len > 0u && encoded.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (encoded.len % BOWIE_DHT_COMPACT_PEER_LEN != 0u) {
        return BOWIE_ERR_FORMAT;
    }

    size_t count = encoded.len / BOWIE_DHT_COMPACT_PEER_LEN;

    if (count > arena->peers_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    for (size_t i = 0u; i < count; i++) {
        const uint8_t *p = encoded.data + i * BOWIE_DHT_COMPACT_PEER_LEN;

        bowie_dht_compact_peer_t *peer = &arena->peers[i];

        memset(&peer->addr, 0, sizeof(peer->addr));
        peer->addr.family = BOWIE_AF_INET;
        peer->addr.addr[0] = p[0];
        peer->addr.addr[1] = p[1];
        peer->addr.addr[2] = p[2];
        peer->addr.addr[3] = p[3];

        uint16_t port_be = (uint16_t)((uint16_t)p[4] << 8)
                         | (uint16_t)p[5];
        peer->addr.port = port_be;
    }

    arena->peers_used = count;
    *out_peers = arena->peers;
    *out_count = count;
    return BOWIE_OK;
}

bowie_error_t bowie_dht_compact_peers_encode(
    const bowie_dht_compact_peer_t *peers,
    size_t                          count,
    uint8_t                        *out,
    size_t                          out_cap,
    size_t                         *out_len)
{
    if (out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (count > 0u && (peers == NULL || out == NULL)) {
        return BOWIE_ERR_NULL_ARG;
    }

    size_t required = count * BOWIE_DHT_COMPACT_PEER_LEN;
    if (required > out_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    for (size_t i = 0u; i < count; i++) {
        const bowie_dht_compact_peer_t *peer = &peers[i];

        if (peer->addr.family != BOWIE_AF_INET) {
            return BOWIE_ERR_TYPE;
        }

        uint8_t *p = out + i * BOWIE_DHT_COMPACT_PEER_LEN;

        p[0] = peer->addr.addr[0];
        p[1] = peer->addr.addr[1];
        p[2] = peer->addr.addr[2];
        p[3] = peer->addr.addr[3];
        p[4] = (uint8_t)((peer->addr.port >> 8) & 0xFFu);
        p[5] = (uint8_t)(peer->addr.port & 0xFFu);
    }

    *out_len = required;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * PART 3 — MESSAGE PARSE
 * ============================================================================
 */

static bowie_error_t get_dict_field(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    const bowie_bencode_value_t **out)
{
    bowie_span_t k;
    k.data = (const uint8_t *)key;
    k.len  = strlen(key);

    *out = bowie_bencode_dict_get(arena, dict, k);
    return BOWIE_OK;
}

static bowie_error_t read_node_id(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    bowie_dht_node_id_t         *out)
{
    const bowie_bencode_value_t *v = NULL;
    (void)get_dict_field(arena, dict, key, &v);
    if (v == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    bowie_span_t s;
    bowie_error_t rc = bowie_bencode_get_str(v, &s);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (s.len != BOWIE_DHT_NODE_ID_LEN) {
        return BOWIE_ERR_FORMAT;
    }

    memcpy(out->bytes, s.data, BOWIE_DHT_NODE_ID_LEN);
    return BOWIE_OK;
}

static bowie_error_t read_info_hash(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    bowie_dht_info_hash_t       *out)
{
    const bowie_bencode_value_t *v = NULL;
    (void)get_dict_field(arena, dict, key, &v);
    if (v == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    bowie_span_t s;
    bowie_error_t rc = bowie_bencode_get_str(v, &s);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (s.len != BOWIE_DHT_INFO_HASH_LEN) {
        return BOWIE_ERR_FORMAT;
    }

    memcpy(out->bytes, s.data, BOWIE_DHT_INFO_HASH_LEN);
    return BOWIE_OK;
}

static bowie_error_t read_token(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    bowie_dht_token_t           *out)
{
    const bowie_bencode_value_t *v = NULL;
    (void)get_dict_field(arena, dict, key, &v);
    if (v == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    bowie_span_t s;
    bowie_error_t rc = bowie_bencode_get_str(v, &s);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (s.len > BOWIE_DHT_TOKEN_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    bowie_dht_token_clear(out);
    if (s.len > 0u) {
        memcpy(out->bytes, s.data, s.len);
    }
    out->len = s.len;
    return BOWIE_OK;
}

static bowie_error_t read_uint16(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    uint16_t                    *out)
{
    const bowie_bencode_value_t *v = NULL;
    (void)get_dict_field(arena, dict, key, &v);
    if (v == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    int64_t i = 0;
    bowie_error_t rc = bowie_bencode_get_int(v, &i);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (i < 0 || i > 65535) {
        return BOWIE_ERR_RANGE;
    }
    *out = (uint16_t)i;
    return BOWIE_OK;
}

static bowie_error_t read_int_opt(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    const char                  *key,
    int64_t                     *out)
{
    const bowie_bencode_value_t *v = NULL;
    (void)get_dict_field(arena, dict, key, &v);
    if (v == NULL) {
        return BOWIE_OK;
    }
    return bowie_bencode_get_int(v, out);
}

static bowie_error_t parse_query(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *root,
    bowie_dht_message_t         *out)
{
    const bowie_bencode_value_t *q = NULL;
    (void)get_dict_field(arena, root, "q", &q);
    if (q == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    bowie_span_t qname;
    bowie_error_t rc = bowie_bencode_get_str(q, &qname);
    if (rc != BOWIE_OK) {
        return rc;
    }

    out->query_type = bowie_dht_query_type_from_name(qname);
    if (out->query_type == BOWIE_DHT_QUERY_UNKNOWN) {
        return BOWIE_ERR_FORMAT;
    }

    const bowie_bencode_value_t *a = NULL;
    (void)get_dict_field(arena, root, "a", &a);
    if (a == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    if (a->kind != BOWIE_BENCODE_DICT) {
        return BOWIE_ERR_TYPE;
    }

    rc = read_node_id(arena, a, "id", &out->sender_id);
    if (rc != BOWIE_OK) {
        return rc;
    }

    switch (out->query_type) {
    case BOWIE_DHT_QUERY_PING:
        break;

    case BOWIE_DHT_QUERY_FIND_NODE:
        rc = read_node_id(arena, a, "target", &out->target);
        if (rc != BOWIE_OK) {
            return rc;
        }
        break;

    case BOWIE_DHT_QUERY_GET_PEERS:
        rc = read_info_hash(arena, a, "info_hash",
                            &out->info_hash);
        if (rc != BOWIE_OK) {
            return rc;
        }
        break;

    case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
        rc = read_info_hash(arena, a, "info_hash",
                            &out->info_hash);
        if (rc != BOWIE_OK) {
            return rc;
        }
        rc = read_token(arena, a, "token", &out->token);
        if (rc != BOWIE_OK) {
            return rc;
        }
        rc = read_uint16(arena, a, "port", &out->port);
        if (rc != BOWIE_OK) {
            return rc;
        }
        int64_t implied = 0;
        (void)read_int_opt(arena, a, "implied_port", &implied);
        out->implied_port = (implied != 0) ? 1 : 0;
        break;

    default:
        return BOWIE_ERR_FORMAT;
    }

    return BOWIE_OK;
}

static bowie_error_t parse_response(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *root,
    bowie_dht_message_arena_t   *msg_arena,
    bowie_dht_message_t         *out)
{
    const bowie_bencode_value_t *r = NULL;
    (void)get_dict_field(arena, root, "r", &r);
    if (r == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    if (r->kind != BOWIE_BENCODE_DICT) {
        return BOWIE_ERR_TYPE;
    }

    bowie_error_t rc = read_node_id(arena, r, "id",
                                    &out->sender_id);
    if (rc != BOWIE_OK) {
        return rc;
    }

    const bowie_bencode_value_t *nodes_v = NULL;
    (void)get_dict_field(arena, r, "nodes", &nodes_v);
    if (nodes_v != NULL) {
        bowie_span_t s;
        rc = bowie_bencode_get_str(nodes_v, &s);
        if (rc != BOWIE_OK) {
            return rc;
        }

        rc = bowie_dht_compact_nodes_decode(s, msg_arena,
                                            &out->nodes,
                                            &out->nodes_count);
        if (rc != BOWIE_OK) {
            return rc;
        }
    }

    const bowie_bencode_value_t *values_v = NULL;
    (void)get_dict_field(arena, r, "values", &values_v);
    if (values_v != NULL) {
        bowie_bencode_list_t l;
        rc = bowie_bencode_get_list(values_v, &l);
        if (rc != BOWIE_OK) {
            return rc;
        }

        size_t total = 0u;
        for (size_t i = 0u; i < l.count; i++) {
            const bowie_bencode_value_t *v =
                bowie_bencode_list_at(arena, values_v, i);
            if (v == NULL) {
                return BOWIE_ERR_FORMAT;
            }

            bowie_span_t s;
            rc = bowie_bencode_get_str(v, &s);
            if (rc != BOWIE_OK) {
                return rc;
            }

            if (s.len != BOWIE_DHT_COMPACT_PEER_LEN) {
                return BOWIE_ERR_FORMAT;
            }
            total++;
        }

        if (total > msg_arena->peers_cap) {
            return BOWIE_ERR_TOO_SMALL;
        }

        size_t written = 0u;
        for (size_t i = 0u; i < l.count; i++) {
            const bowie_bencode_value_t *v =
                bowie_bencode_list_at(arena, values_v, i);
            bowie_span_t s;
            (void)bowie_bencode_get_str(v, &s);

            bowie_dht_compact_peer_t *peer =
                &msg_arena->peers[written];
            memset(&peer->addr, 0, sizeof(peer->addr));
            peer->addr.family = BOWIE_AF_INET;
            peer->addr.addr[0] = s.data[0];
            peer->addr.addr[1] = s.data[1];
            peer->addr.addr[2] = s.data[2];
            peer->addr.addr[3] = s.data[3];
            peer->addr.port = (uint16_t)((uint16_t)s.data[4] << 8)
                            | (uint16_t)s.data[5];
            written++;
        }

        msg_arena->peers_used = written;
        out->peers = msg_arena->peers;
        out->peers_count = written;
    }

    const bowie_bencode_value_t *token_v = NULL;
    (void)get_dict_field(arena, r, "token", &token_v);
    if (token_v != NULL) {
        rc = read_token(arena, r, "token", &out->token);
        if (rc != BOWIE_OK) {
            return rc;
        }
    }

    return BOWIE_OK;
}

static bowie_error_t parse_error(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *root,
    bowie_dht_message_t         *out)
{
    const bowie_bencode_value_t *e = NULL;
    (void)get_dict_field(arena, root, "e", &e);
    if (e == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    bowie_bencode_list_t l;
    bowie_error_t rc = bowie_bencode_get_list(e, &l);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (l.count != 2u) {
        return BOWIE_ERR_FORMAT;
    }

    const bowie_bencode_value_t *code_v =
        bowie_bencode_list_at(arena, e, 0u);
    if (code_v == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    int64_t code = 0;
    rc = bowie_bencode_get_int(code_v, &code);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (code < 0 || code > 1000000) {
        return BOWIE_ERR_RANGE;
    }
    out->error_code = (int)code;

    const bowie_bencode_value_t *msg_v =
        bowie_bencode_list_at(arena, e, 1u);
    if (msg_v == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    rc = bowie_bencode_get_str(msg_v, &out->error_message);
    if (rc != BOWIE_OK) {
        return rc;
    }

    return BOWIE_OK;
}

bowie_error_t bowie_dht_message_parse(
    bowie_span_t                    encoded,
    bowie_bencode_arena_t          *benc_arena,
    bowie_dht_message_arena_t      *msg_arena,
    bowie_dht_message_t            *out_msg)
{
    if (benc_arena == NULL || msg_arena == NULL ||
        out_msg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(out_msg, 0, sizeof(*out_msg));

    msg_arena->nodes_used = 0u;
    msg_arena->peers_used = 0u;

    const bowie_bencode_value_t *root = NULL;
    bowie_error_t rc = bowie_bencode_decode(encoded, benc_arena,
                                            &root, 0);
    if (rc != BOWIE_OK) {
        return rc;
    }

    if (root->kind != BOWIE_BENCODE_DICT) {
        return BOWIE_ERR_TYPE;
    }

    const bowie_bencode_value_t *t = NULL;
    (void)get_dict_field(benc_arena, root, "t", &t);
    if (t == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    bowie_span_t tid;
    rc = bowie_bencode_get_str(t, &tid);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (tid.len > BOWIE_DHT_MSG_TID_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }
    if (tid.len > 0u) {
        memcpy(out_msg->tid, tid.data, tid.len);
    }
    out_msg->tid_len = tid.len;

    const bowie_bencode_value_t *y = NULL;
    (void)get_dict_field(benc_arena, root, "y", &y);
    if (y == NULL) {
        return BOWIE_ERR_FORMAT;
    }
    bowie_span_t yname;
    rc = bowie_bencode_get_str(y, &yname);
    if (rc != BOWIE_OK) {
        return rc;
    }
    if (yname.len != 1u || yname.data == NULL) {
        return BOWIE_ERR_FORMAT;
    }

    switch (yname.data[0]) {
    case 'q':
        out_msg->type = BOWIE_DHT_MSG_QUERY;
        return parse_query(benc_arena, root, out_msg);

    case 'r':
        out_msg->type = BOWIE_DHT_MSG_RESPONSE;
        return parse_response(benc_arena, root, msg_arena,
                              out_msg);

    case 'e':
        out_msg->type = BOWIE_DHT_MSG_ERROR;
        return parse_error(benc_arena, root, out_msg);

    default:
        return BOWIE_ERR_FORMAT;
    }
}

/*
 * ============================================================================
 * PART 4 — MESSAGE SERIALIZE
 * ============================================================================
 */

#define COMPACT_CHUNK_NODES  16
#define COMPACT_CHUNK_PEERS  32

static bowie_error_t write_span(bowie_bencode_writer_t *w,
                                const uint8_t *data, size_t len)
{
    bowie_span_t s;
    s.data = data;
    s.len  = len;
    return bowie_bencode_write_str(w, s);
}

static bowie_error_t write_node_id(bowie_bencode_writer_t *w,
                                   const bowie_dht_node_id_t *id)
{
    return write_span(w, id->bytes, BOWIE_DHT_NODE_ID_LEN);
}

static bowie_error_t write_info_hash(bowie_bencode_writer_t *w,
                                     const bowie_dht_info_hash_t *h)
{
    return write_span(w, h->bytes, BOWIE_DHT_INFO_HASH_LEN);
}

static bowie_error_t write_token(bowie_bencode_writer_t *w,
                                 const bowie_dht_token_t *t)
{
    return write_span(w, t->bytes, t->len);
}

static bowie_error_t write_dict_key(bowie_bencode_writer_t *w,
                                    const char *key)
{
    bowie_span_t s;
    s.data = (const uint8_t *)key;
    s.len  = strlen(key);
    return bowie_bencode_write_dict_key(w, s);
}

static bowie_error_t write_compact_nodes(
    bowie_bencode_writer_t          *w,
    const bowie_dht_compact_node_t  *nodes,
    size_t                           count)
{
    uint8_t chunk[COMPACT_CHUNK_NODES * BOWIE_DHT_COMPACT_NODE_LEN];

    size_t written = 0u;
    while (written < count) {
        size_t take = count - written;
        if (take > COMPACT_CHUNK_NODES) {
            take = COMPACT_CHUNK_NODES;
        }

        size_t chunk_len = 0u;
        bowie_error_t rc = bowie_dht_compact_nodes_encode(
            nodes + written, take,
            chunk, sizeof(chunk), &chunk_len);
        if (rc != BOWIE_OK) {
            return rc;
        }

        rc = write_span(w, chunk, chunk_len);
        if (rc != BOWIE_OK) {
            return rc;
        }

        written += take;
    }
    return BOWIE_OK;
}

static bowie_error_t write_query_name(bowie_bencode_writer_t *w,
                                      bowie_dht_query_type_t q)
{
    const char *name = NULL;
    switch (q) {
    case BOWIE_DHT_QUERY_PING:          name = "ping"; break;
    case BOWIE_DHT_QUERY_FIND_NODE:     name = "find_node"; break;
    case BOWIE_DHT_QUERY_GET_PEERS:     name = "get_peers"; break;
    case BOWIE_DHT_QUERY_ANNOUNCE_PEER: name = "announce_peer"; break;
    default:                            return BOWIE_ERR_INVAL;
    }

    bowie_span_t s;
    s.data = (const uint8_t *)name;
    s.len  = strlen(name);
    return bowie_bencode_write_str(w, s);
}

static bowie_error_t serialize_query(
    const bowie_dht_message_t *msg,
    bowie_bencode_writer_t    *w)
{
    bowie_error_t rc;

    rc = bowie_bencode_begin_dict(w);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "t");
    if (rc != BOWIE_OK) return rc;
    rc = write_span(w, msg->tid, msg->tid_len);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "y");
    if (rc != BOWIE_OK) return rc;
    {
        bowie_span_t s = { (const uint8_t *)"q", 1u };
        rc = bowie_bencode_write_str(w, s);
        if (rc != BOWIE_OK) return rc;
    }

    rc = write_dict_key(w, "q");
    if (rc != BOWIE_OK) return rc;
    rc = write_query_name(w, msg->query_type);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "a");
    if (rc != BOWIE_OK) return rc;
    rc = bowie_bencode_begin_dict(w);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "id");
    if (rc != BOWIE_OK) return rc;
    rc = write_node_id(w, &msg->sender_id);
    if (rc != BOWIE_OK) return rc;

    switch (msg->query_type) {
    case BOWIE_DHT_QUERY_PING:
        break;

    case BOWIE_DHT_QUERY_FIND_NODE:
        rc = write_dict_key(w, "target");
        if (rc != BOWIE_OK) return rc;
        rc = write_node_id(w, &msg->target);
        if (rc != BOWIE_OK) return rc;
        break;

    case BOWIE_DHT_QUERY_GET_PEERS:
        rc = write_dict_key(w, "info_hash");
        if (rc != BOWIE_OK) return rc;
        rc = write_info_hash(w, &msg->info_hash);
        if (rc != BOWIE_OK) return rc;
        break;

    case BOWIE_DHT_QUERY_ANNOUNCE_PEER:
        rc = write_dict_key(w, "info_hash");
        if (rc != BOWIE_OK) return rc;
        rc = write_info_hash(w, &msg->info_hash);
        if (rc != BOWIE_OK) return rc;

        rc = write_dict_key(w, "port");
        if (rc != BOWIE_OK) return rc;
        rc = bowie_bencode_write_int(w, (int64_t)msg->port);
        if (rc != BOWIE_OK) return rc;

        rc = write_dict_key(w, "token");
        if (rc != BOWIE_OK) return rc;
        rc = write_token(w, &msg->token);
        if (rc != BOWIE_OK) return rc;

        if (msg->implied_port) {
            rc = write_dict_key(w, "implied_port");
            if (rc != BOWIE_OK) return rc;
            rc = bowie_bencode_write_int(w, 1);
            if (rc != BOWIE_OK) return rc;
        }
        break;

    default:
        return BOWIE_ERR_INVAL;
    }

    rc = bowie_bencode_end_dict(w);
    if (rc != BOWIE_OK) return rc;

    return bowie_bencode_end_dict(w);
}

static bowie_error_t serialize_response(
    const bowie_dht_message_t *msg,
    bowie_bencode_writer_t    *w)
{
    bowie_error_t rc;

    rc = bowie_bencode_begin_dict(w);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "t");
    if (rc != BOWIE_OK) return rc;
    rc = write_span(w, msg->tid, msg->tid_len);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "y");
    if (rc != BOWIE_OK) return rc;
    {
        bowie_span_t s = { (const uint8_t *)"r", 1u };
        rc = bowie_bencode_write_str(w, s);
        if (rc != BOWIE_OK) return rc;
    }

    rc = write_dict_key(w, "r");
    if (rc != BOWIE_OK) return rc;
    rc = bowie_bencode_begin_dict(w);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "id");
    if (rc != BOWIE_OK) return rc;
    rc = write_node_id(w, &msg->sender_id);
    if (rc != BOWIE_OK) return rc;

    if (msg->nodes_count > 0u) {
        rc = write_dict_key(w, "nodes");
        if (rc != BOWIE_OK) return rc;
        rc = write_compact_nodes(w, msg->nodes, msg->nodes_count);
        if (rc != BOWIE_OK) return rc;
    }

    if (msg->peers_count > 0u) {
        rc = write_dict_key(w, "values");
        if (rc != BOWIE_OK) return rc;
        rc = bowie_bencode_begin_list(w);
        if (rc != BOWIE_OK) return rc;

        for (size_t i = 0u; i < msg->peers_count; i++) {
            uint8_t buf[BOWIE_DHT_COMPACT_PEER_LEN];
            size_t  n = 0u;
            rc = bowie_dht_compact_peers_encode(
                &msg->peers[i], 1u, buf, sizeof(buf), &n);
            if (rc != BOWIE_OK) return rc;

            rc = write_span(w, buf, n);
            if (rc != BOWIE_OK) return rc;
        }

        rc = bowie_bencode_end_list(w);
        if (rc != BOWIE_OK) return rc;
    }

    if (!bowie_dht_token_is_zero(&msg->token)) {
        rc = write_dict_key(w, "token");
        if (rc != BOWIE_OK) return rc;
        rc = write_token(w, &msg->token);
        if (rc != BOWIE_OK) return rc;
    }

    rc = bowie_bencode_end_dict(w);
    if (rc != BOWIE_OK) return rc;

    return bowie_bencode_end_dict(w);
}

static bowie_error_t serialize_error(
    const bowie_dht_message_t *msg,
    bowie_bencode_writer_t    *w)
{
    bowie_error_t rc;

    rc = bowie_bencode_begin_dict(w);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "t");
    if (rc != BOWIE_OK) return rc;
    rc = write_span(w, msg->tid, msg->tid_len);
    if (rc != BOWIE_OK) return rc;

    rc = write_dict_key(w, "y");
    if (rc != BOWIE_OK) return rc;
    {
        bowie_span_t s = { (const uint8_t *)"e", 1u };
        rc = bowie_bencode_write_str(w, s);
        if (rc != BOWIE_OK) return rc;
    }

    rc = write_dict_key(w, "e");
    if (rc != BOWIE_OK) return rc;
    rc = bowie_bencode_begin_list(w);
    if (rc != BOWIE_OK) return rc;

    rc = bowie_bencode_write_int(w, (int64_t)msg->error_code);
    if (rc != BOWIE_OK) return rc;

    size_t msg_len = msg->error_message.len;
    if (msg_len > BOWIE_DHT_MSG_ERR_MAX) {
        msg_len = BOWIE_DHT_MSG_ERR_MAX;
    }
    rc = write_span(w, msg->error_message.data, msg_len);
    if (rc != BOWIE_OK) return rc;

    rc = bowie_bencode_end_list(w);
    if (rc != BOWIE_OK) return rc;

    return bowie_bencode_end_dict(w);
}

bowie_error_t bowie_dht_message_serialize(
    const bowie_dht_message_t *msg,
    bowie_bencode_writer_t    *w)
{
    if (msg == NULL || w == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    switch (msg->type) {
    case BOWIE_DHT_MSG_QUERY:
        return serialize_query(msg, w);

    case BOWIE_DHT_MSG_RESPONSE:
        return serialize_response(msg, w);

    case BOWIE_DHT_MSG_ERROR:
        return serialize_error(msg, w);

    case BOWIE_DHT_MSG_UNKNOWN:
    default:
        return BOWIE_ERR_INVAL;
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
