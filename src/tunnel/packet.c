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
 * BOWIE — TUNNEL PACKET (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the IP packet helpers declared in
 * tunnel/packet.h.
 *
 * The helpers read a borrowed span and write a value. They
 * never allocate, never copy, and never modify the span.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No checksum verification.
 *   - No fragmentation.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every read is bounds-checked before it happens. A packet
 * that is shorter than the header it claims to contain is
 * rejected with BOWIE_ERR_TOO_SMALL; the helper never reads
 * past the end of the span.
 *
 * The version check reads only the high nibble of the first
 * byte. A packet with any other nibble is not an IP packet
 * and is rejected.
 *
 * IPv4 and IPv6 are parsed by two small helpers. Each helper
 * knows the layout of its own header and nothing more. The
 * public function dispatches on the version nibble.
 *
 * The header length for IPv4 is taken from the IHL field and
 * multiplied by four. The result is checked against the
 * minimum header size; an IHL of zero or one is a malformed
 * packet and is rejected.
 *
 * The header length for IPv6 is fixed at 40 bytes. Extension
 * headers follow the base header and are not parsed here;
 * the tunnel treats the packet as opaque payload after the
 * base header.
 *
 * The total length field is read as-is from the header. It is
 * not compared to the span length. A truncated packet and a
 * padded packet are both possible, and deciding what to do
 * about them is the caller's job.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>          memcpy, memset
 *   "bowie/types.h"     bowie_span_t
 *   "bowie/err.h"       bowie_error_t
 *   "tunnel/packet.h"   declarations and constants
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/packet.h"

/*
 * ============================================================================
 * INTERNAL — READ HELPERS
 * ============================================================================
 *
 * Small helpers for reading multi-byte fields out of a span.
 * The caller is responsible for checking that the offset and
 * the width are within the span; these helpers do not.
 *
 * The reads are done byte-by-byte. A direct uint16_t or
 * uint32_t load would be faster, but it would also be
 * unaligned on some platforms, and the compiler cannot always
 * prove alignment. Byte-by-byte is safe everywhere and the
 * cost is negligible for a header.
 */

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/*
 * ============================================================================
 * VERSION
 * ============================================================================
 */

uint8_t bowie_packet_version(bowie_span_t packet)
{
    uint8_t version;

    if (packet.len < 1 || packet.data == NULL) {
        return 0;
    }

    version = (uint8_t)(packet.data[0] >> 4);

    if (version != BOWIE_IP_VERSION_4 && version != BOWIE_IP_VERSION_6) {
        return 0;
    }

    return version;
}

/*
 * ============================================================================
 * PARSE — IPv4
 * ============================================================================
 *
 * The IPv4 header is at least 20 bytes. The IHL field in the
 * first byte gives the header length in 32-bit words.
 *
 * Layout (offsets in bytes):
 *
 *   0   version (4 bits) + IHL (4 bits)
 *   1   DSCP / ECN
 *   2   total length (big-endian)
 *   3   ...
 *   9   protocol
 *   12  source address (4 bytes)
 *   16  destination address (4 bytes)
 *   20  options (if IHL > 5)
 */

static bowie_error_t parse_ipv4(bowie_span_t packet,
                                bowie_ip_packet_t *out)
{
    uint8_t  ihl;
    size_t   header_len;

    if (packet.len < BOWIE_IPV4_HEADER_MIN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    ihl = (uint8_t)(packet.data[0] & 0x0Fu);

    if (ihl < 5) {
        return BOWIE_ERR_FORMAT;
    }

    header_len = (size_t)ihl * 4u;

    if (packet.len < header_len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    out->version    = BOWIE_IP_VERSION_4;
    out->header_len = (uint8_t)header_len;
    out->total_len  = read_be16(packet.data + 2);
    out->protocol   = packet.data[9];

    memset(out->src_addr, 0, sizeof(out->src_addr));
    memset(out->dst_addr, 0, sizeof(out->dst_addr));

    memcpy(out->src_addr, packet.data + 12, 4);
    memcpy(out->dst_addr, packet.data + 16, 4);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * PARSE — IPv6
 * ============================================================================
 *
 * The IPv6 header is exactly 40 bytes. Extension headers
 * follow it and are treated as payload.
 *
 * Layout (offsets in bytes):
 *
 *   0   version (4 bits) + traffic class (8 bits) + flow (20 bits)
 *   4   payload length (big-endian)
 *   6   next header
 *   7   hop limit
 *   8   source address (16 bytes)
 *   24  destination address (16 bytes)
 *
 * The total length reported here is the payload length plus
 * the fixed 40-byte header, which matches the IPv4 total_len
 * meaning.
 */

static bowie_error_t parse_ipv6(bowie_span_t packet,
                                bowie_ip_packet_t *out)
{
    uint16_t payload_len;

    if (packet.len < BOWIE_IPV6_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    payload_len = read_be16(packet.data + 4);

    out->version    = BOWIE_IP_VERSION_6;
    out->header_len = BOWIE_IPV6_HEADER_LEN;
    out->total_len  = (uint16_t)(payload_len + BOWIE_IPV6_HEADER_LEN);
    out->protocol   = packet.data[6];

    memcpy(out->src_addr, packet.data + 8, 16);
    memcpy(out->dst_addr, packet.data + 24, 16);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * PARSE — PUBLIC
 * ============================================================================
 */

bowie_error_t bowie_packet_parse(bowie_span_t packet,
                                 bowie_ip_packet_t *out)
{
    uint8_t version;

    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (packet.len > 0 && packet.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (packet.len < 1) {
        return BOWIE_ERR_TOO_SMALL;
    }

    version = (uint8_t)(packet.data[0] >> 4);

    if (version == BOWIE_IP_VERSION_4) {
        return parse_ipv4(packet, out);
    }

    if (version == BOWIE_IP_VERSION_6) {
        return parse_ipv6(packet, out);
    }

    return BOWIE_ERR_FORMAT;
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

int bowie_packet_is_protocol(bowie_span_t packet, uint8_t protocol)
{
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    rc = bowie_packet_parse(packet, &parsed);

    if (rc != BOWIE_OK) {
        return 0;
    }

    return (parsed.protocol == protocol) ? 1 : 0;
}

uint16_t bowie_packet_length(bowie_span_t packet)
{
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    rc = bowie_packet_parse(packet, &parsed);

    if (rc != BOWIE_OK) {
        return 0;
    }

    return parsed.total_len;
}

/*
 * ============================================================================
 * END OF TUNNEL PACKET IMPLEMENTATION
 * ============================================================================
 */
