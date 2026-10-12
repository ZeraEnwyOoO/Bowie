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
 * BOWIE — DHT MESSAGE
 * ============================================================================
 *
 * Mainline DHT message parsing and serialization.
 *
 * A Mainline message is a bencoded dictionary. The top-level
 * keys are:
 *
 *   t   transaction id (byte string, 2 bytes in practice)
 *   y   message type ("q" query, "r" response, "e" error)
 *   q   query name (present when y is "q")
 *   a   query arguments (present when y is "q")
 *   r   response values (present when y is "r")
 *   e   error (present when y is "e")
 *
 * The query name is one of:
 *
 *   ping
 *   find_node
 *   get_peers
 *   announce_peer
 *
 * The message layer is a thin translation between the bencode
 * tree and a C struct. It does not decide what to do with a
 * message; the routing and search layers do that.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. The message layer writes into a
 *     caller-supplied arena, like the bencode layer.
 *   - No I/O.
 *   - No policy. The message layer does not decide which
 *     queries to send or how to respond.
 *   - No routing. The message layer does not know about the
 *     routing table or the search state.
 *   - No storage. The message layer does not store anything.
 *   - No IPv6 by default. The compact formats in this file
 *     are the IPv4 ones. IPv6 (BEP 32) is a separate format
 *     and is not handled here.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A message is represented by a single struct. The struct has
 * fields for every query and response type. A field that does
 * not apply to a particular message is left at its default
 * value (zero for integers, an unset ID for identifiers).
 *
 * This is the same shape as the DHT types: one struct, all
 * fields, no union. It makes the code simpler and it makes
 * the message easy to inspect in a debugger. The cost is a
 * slightly larger struct; the benefit is a single code path
 * for every message.
 *
 * The message layer reads and writes the bencode tree. It
 * does not own the tree. The caller allocates the bencode
 * arena and the message arena, passes them to the parse
 * function, and keeps them alive for as long as the message
 * is used.
 *
 * A byte string in the message (a transaction id, a token, an
 * error message) is a borrowed span. It points into the input
 * buffer. The caller must keep the input buffer alive.
 *
 * The compact node list is an array of 26-byte entries. Each
 * entry is:
 *
 *   20 bytes   node id
 *    4 bytes   IPv4 address
 *    2 bytes   port, big-endian
 *
 * The compact peer list is an array of 6-byte entries. Each
 * entry is:
 *
 *    4 bytes   IPv4 address
 *    2 bytes   port, big-endian
 *
 * The IPv4 address is stored in network byte order in the
 * wire format. The parser converts it to the host byte order
 * used by bowie_addr_t. The serializer converts it back.
 *
 * A message that uses IPv6 is not handled here. A future
 * version can add a second compact format and a flag to
 * select it.
 *
 * ----------------------------------------------------------------------------
 * Transaction id
 * ----------------------------------------------------------------------------
 *
 * The transaction id is a byte string of 1 to 2 bytes in
 * practice, but the wire format allows any length. The struct
 * stores up to BOWIE_DHT_MSG_TID_MAX bytes and a length. A
 * longer id is rejected by the parser as BOWIE_ERR_TOO_LARGE.
 *
 * The transaction id is chosen by the sender. It is echoed in
 * the response. It is not a security token; it is a way to
 * match a response to a query.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint16_t, int64_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_span_t, bowie_addr_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                node id, info hash, token
 *   "dht/bencode.h"              arena, value, writer
 * ============================================================================
 */

#ifndef BOWIE_DHT_MESSAGE_H
#define BOWIE_DHT_MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/bencode.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * MESSAGE TYPE
 * ============================================================================
 */

typedef enum bowie_dht_msg_type {
    BOWIE_DHT_MSG_UNKNOWN  = 0,
    BOWIE_DHT_MSG_QUERY    = 1,   /* y = "q" */
    BOWIE_DHT_MSG_RESPONSE = 2,   /* y = "r" */
    BOWIE_DHT_MSG_ERROR    = 3,   /* y = "e" */
} bowie_dht_msg_type_t;

/*
 * ============================================================================
 * QUERY TYPE
 * ============================================================================
 */

typedef enum bowie_dht_query_type {
    BOWIE_DHT_QUERY_UNKNOWN       = 0,
    BOWIE_DHT_QUERY_PING          = 1,
    BOWIE_DHT_QUERY_FIND_NODE     = 2,
    BOWIE_DHT_QUERY_GET_PEERS     = 3,
    BOWIE_DHT_QUERY_ANNOUNCE_PEER = 4,
} bowie_dht_query_type_t;

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 *
 * The transaction id is at most 2 bytes in practice. The wire
 * format allows more; this limit is a policy choice. A sender
 * that uses a longer id is rejected by the parser.
 *
 * The error message is at most 256 bytes. A longer message is
 * truncated by the serializer.
 */

#define BOWIE_DHT_MSG_TID_MAX       2
#define BOWIE_DHT_MSG_ERR_MAX     256

 
/*
 * ============================================================================
 * COMPACT NODE
 * ============================================================================
 *
 * A node in a compact node list. The struct uses bowie_addr_t
 * so that an IPv6 variant can be added later without changing
 * the struct.
 *
 * The parser reads the IPv4 form and fills the addr field with
 * family BOWIE_AF_INET. The serializer writes the IPv4 form
 * and rejects a node that is not IPv4.
 */

typedef struct bowie_dht_compact_node {
    bowie_dht_node_id_t id;
    bowie_addr_t        addr;
} bowie_dht_compact_node_t;

/*
 * ============================================================================
 * COMPACT PEER
 * ============================================================================
 *
 * A peer in a compact peer list. Same IPv4 restriction as the
 * compact node.
 */

typedef struct bowie_dht_compact_peer {
    bowie_addr_t addr;
} bowie_dht_compact_peer_t;

/*
 * ============================================================================
 * MESSAGE
 * ============================================================================
 *
 * A parsed DHT message. Every field is present; a field that
 * does not apply to the message's type is left at its default
 * value.
 *
 * The "sender_id" is the "id" field in the query arguments or
 * the response values. It is the id of the node that sent the
 * message.
 *
 * The "target" is the "target" field of a find_node query.
 *
 * The "info_hash" is the "info_hash" field of a get_peers or
 * announce_peer query.
 *
 * The "port", "token", and "implied_port" are the fields of
 * an announce_peer query.
 *
 * The "nodes" and "peers" arrays are the decoded compact
 * lists from a response. They are stored in the message
 * arena.
 */

typedef struct bowie_dht_message {
    bowie_dht_msg_type_t   type;
    bowie_dht_query_type_t query_type;

    uint8_t                tid[BOWIE_DHT_MSG_TID_MAX];
    size_t                 tid_len;

    bowie_dht_node_id_t    sender_id;

    /* Query-specific: find_node */
    bowie_dht_node_id_t    target;

    /* Query-specific: get_peers, announce_peer */
    bowie_dht_info_hash_t  info_hash;

    /* Query-specific: announce_peer */
    uint16_t               port;
    bowie_dht_token_t      token;
    int                    implied_port;

    /* Response-specific: compact node list */
    bowie_dht_compact_node_t *nodes;
    size_t                    nodes_count;

    /* Response-specific: compact peer list */
    bowie_dht_compact_peer_t *peers;
    size_t                    peers_count;

    /* Error-specific */
    int                    error_code;
    bowie_span_t           error_message;
} bowie_dht_message_t;

/*
 * ============================================================================
 * MESSAGE ARENA
 * ============================================================================
 *
 * The message layer does not allocate. The caller supplies
 * arrays for the compact node list and the compact peer list.
 * The parser fills them and stores the counts in the message.
 *
 * The arrays are reset at the start of each parse. A parse
 * that needs more entries than the arena can hold is reported
 * as BOWIE_ERR_TOO_SMALL.
 */

typedef struct bowie_dht_message_arena {
    bowie_dht_compact_node_t *nodes;
    size_t                    nodes_cap;
    size_t                    nodes_used;

    bowie_dht_compact_peer_t *peers;
    size_t                    peers_cap;
    size_t                    peers_used;
} bowie_dht_message_arena_t;

/*
 * ============================================================================
 * PARSE
 * ============================================================================
 */

/*
 * Parse a bencoded DHT message.
 *
 * The input is a borrowed span. The decoded byte strings
 * point into it. The caller must keep the input alive for as
 * long as it uses the message.
 *
 * The bencode arena holds the decoded tree. The message
 * arena holds the compact node and peer lists. Both are
 * reset by this call.
 *
 * On success, the message is written through out_msg.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_FORMAT if the input is not a valid
 *   Mainline message.
 * Returns BOWIE_ERR_TOO_SMALL if either arena is too small.
 * Returns BOWIE_ERR_TOO_LARGE if a field exceeds its limit
 *   (transaction id, error message, compact list).
 * Returns BOWIE_ERR_TYPE if a required field has the wrong
 *   bencode type.
 */
bowie_error_t bowie_dht_message_parse(
    bowie_span_t                    encoded,
    bowie_bencode_arena_t          *benc_arena,
    bowie_dht_message_arena_t      *msg_arena,
    bowie_dht_message_t            *out_msg);

/*
 * ============================================================================
 * SERIALIZE
 * ============================================================================
 *
 * Serialize a message into a bencode writer. The writer is
 * initialized by the caller over a caller-supplied buffer.
 *
 * A query or response is written with all the fields that
 * apply to its type. A field that does not apply is not
 * written.
 *
 * The transaction id is written first. The message type
 * ("q", "r", or "e") determines the top-level structure.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_INVAL if the message type is UNKNOWN, or
 *   if a required field is unset.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is too
 *   small.
 * Returns BOWIE_ERR_TYPE if a message that needs a compact
 *   list has a non-IPv4 address in the list.
 */
bowie_error_t bowie_dht_message_serialize(
    const bowie_dht_message_t *msg,
    bowie_bencode_writer_t    *w);

/*
 * ============================================================================
 * COMPACT FORMAT HELPERS
 * ============================================================================
 *
 * The compact node and peer lists are byte strings in the
 * bencode tree. These helpers convert between the byte form
 * and the struct form.
 *
 * A caller that needs to build a compact list by hand, or to
 * parse one from a buffer that is not part of a full message,
 * uses these helpers.
 */

/*
 * Decode a compact node list.
 *
 * The input is a byte string whose length is a multiple of 26.
 * The output is an array of compact nodes in the message
 * arena.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_FORMAT if the input length is not a
 *   multiple of 26.
 * Returns BOWIE_ERR_TOO_SMALL if the arena is too small.
 */
bowie_error_t bowie_dht_compact_nodes_decode(
    bowie_span_t                encoded,
    bowie_dht_message_arena_t  *arena,
    bowie_dht_compact_node_t  **out_nodes,
    size_t                     *out_count);

/*
 * Encode a compact node list.
 *
 * The output is a byte string. Every node in the input must
 * have family BOWIE_AF_INET. A node with a different family
 * is rejected with BOWIE_ERR_TYPE.
 *
 * The output buffer is caller-supplied. The required size is
 * count * 26.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is too
 *   small.
 * Returns BOWIE_ERR_TYPE if a node is not IPv4.
 */
bowie_error_t bowie_dht_compact_nodes_encode(
    const bowie_dht_compact_node_t *nodes,
    size_t                          count,
    uint8_t                        *out,
    size_t                          out_cap,
    size_t                         *out_len);

/*
 * Decode a compact peer list.
 *
 * Same contract as the node list, with a 6-byte entry.
 */
bowie_error_t bowie_dht_compact_peers_decode(
    bowie_span_t                encoded,
    bowie_dht_message_arena_t  *arena,
    bowie_dht_compact_peer_t  **out_peers,
    size_t                     *out_count);

/*
 * Encode a compact peer list.
 *
 * Same contract as the node list, with a 6-byte entry.
 */
bowie_error_t bowie_dht_compact_peers_encode(
    const bowie_dht_compact_peer_t *peers,
    size_t                          count,
    uint8_t                        *out,
    size_t                          out_cap,
    size_t                         *out_len);

/*
 * ============================================================================
 * NAME HELPERS
 * ============================================================================
 */

/*
 * Return a stable, human-readable name for a message type.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_dht_msg_type_name(bowie_dht_msg_type_t t);

/*
 * Return a stable, human-readable name for a query type.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_dht_query_type_name(bowie_dht_query_type_t q);

/*
 * Parse a query name into a query type.
 *
 * The comparison is case-sensitive and matches the Mainline
 * query names exactly: "ping", "find_node", "get_peers",
 * "announce_peer". An unknown name returns
 * BOWIE_DHT_QUERY_UNKNOWN.
 */
bowie_dht_query_type_t bowie_dht_query_type_from_name(
    bowie_span_t name);

/*
 * ============================================================================
 * END OF DHT MESSAGE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_MESSAGE_H */
