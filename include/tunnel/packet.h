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
 * BOWIE — TUNNEL PACKET
 * ============================================================================
 *
 * IP packet parsing and validation for the Bowie tunnel.
 *
 * The tunnel forwards raw IP packets between peers. This
 * header declares the helpers that read a packet's version,
 * length, and protocol without taking ownership of the buffer.
 * The buffer is a borrowed span; the helpers never allocate,
 * never copy, and never modify it.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. Nothing here reads from a TUN device or sends
 *     over a socket.
 *   - No routing. The helpers describe a packet; they do not
 *     decide where it goes.
 *   - No fragmentation. A packet that is too large is the
 *     caller's problem; this header only reports the length.
 *   - No checksum verification. The helpers trust the
 *     transport or the crypto layer to have verified the
 *     packet; they only read the header fields.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every helper takes a borrowed span (a pointer and a length)
 * and returns a value or an error. The span is never modified.
 *
 * The helpers validate enough to be safe on a malicious
 * packet: a packet that is shorter than its own header is
 * rejected rather than read past its end.
 *
 * The version check is the first thing a caller should do.
 * The two supported versions are IPv4 and IPv6. A packet
 * with any other version is not an IP packet and is rejected.
 *
 * The length field in the IP header is reported as-is; the
 * helper does not check it against the span length. A caller
 * that wants to forward exactly the declared length must do
 * the comparison itself, because a truncated packet and a
 * packet with trailing padding are both possible.
 *
 * The checksum function verifies the IPv4 header checksum
 * only. IPv6 does not have a header checksum; its integrity
 * is provided by the transport layer or by the crypto layer
 * above the tunnel.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>          uint8_t, uint16_t
 *   <stddef.h>          size_t
 *   "bowie/types.h"     bowie_span_t
 *   "bowie/err.h"       bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_TUNNEL_PACKET_H
#define BOWIE_TUNNEL_PACKET_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The IP version nibble values the tunnel recognizes.
 *
 * A packet whose first nibble is neither of these is not an
 * IP packet and is rejected by the helpers.
 */
#define BOWIE_IP_VERSION_4   4u
#define BOWIE_IP_VERSION_6   6u

/*
 * The minimum size of an IPv4 header, in bytes.
 *
 * An IPv4 header is 20 bytes when it has no options. The
 * header length field can make it larger.
 */
#define BOWIE_IPV4_HEADER_MIN  20u

/*
 * The size of an IPv6 header, in bytes.
 *
 * An IPv6 header has a fixed size; extension headers follow
 * it and are part of the payload.
 */
#define BOWIE_IPV6_HEADER_LEN  40u

/*
 * ============================================================================
 * PARSE RESULT
 * ============================================================================
 *
 * The information the tunnel needs from an IP packet header.
 *
 * The struct is a value type. A caller may copy it, store it,
 * or discard it without any cleanup.
 *
 * The version field is 4 or 6.
 *
 * The header_len field is the size of the IP header, not the
 * size of the packet. For IPv4 it is derived from the IHL
 * field; for IPv6 it is the fixed header length.
 *
 * The total_len field is the length declared in the IP
 * header. It may be smaller or larger than the span length.
 *
 * The protocol field is the value of the IPv4 protocol field
 * or the IPv6 next-header field. It is not interpreted here.
 *
 * The src_addr and dst_addr fields hold the addresses as they
 * appear in the packet, in network byte order. For IPv4, the
 * first four bytes are meaningful and the rest are zero; for
 * IPv6, all sixteen bytes are meaningful.
 */

typedef struct bowie_ip_packet {
    uint8_t  version;
    uint8_t  header_len;
    uint16_t total_len;
    uint8_t  protocol;
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
} bowie_ip_packet_t;

/*
 * ============================================================================
 * VERSION
 * ============================================================================
 */

/*
 * Return the IP version of a packet.
 *
 * The version is the high nibble of the first byte.
 *
 * Returns BOWIE_IP_VERSION_4 or BOWIE_IP_VERSION_6 on
 * success. Returns 0 if the span is empty or the version
 * nibble is neither 4 nor 6.
 */
uint8_t bowie_packet_version(bowie_span_t packet);

/*
 * ============================================================================
 * PARSE
 * ============================================================================
 */

/*
 * Parse an IP packet header into a bowie_ip_packet_t.
 *
 * The span is not modified. The function reads only the
 * bytes that make up the header; it does not read the
 * payload.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if the span has a NULL data
 * pointer with a non-zero length.
 * Returns BOWIE_ERR_TOO_SMALL if the span is shorter than
 * the header it claims to contain.
 * Returns BOWIE_ERR_FORMAT if the version is not 4 or 6, or
 * if the header length field is smaller than the minimum for
 * the version.
 */
bowie_error_t bowie_packet_parse(bowie_span_t packet,
                                 bowie_ip_packet_t *out);

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True when the packet has the given protocol number.
 *
 * The protocol number is the value of the IPv4 protocol field
 * or the IPv6 next-header field. The comparison is a plain
 * byte equality; the helper does not interpret the value.
 *
 * Passing a zero-length span returns 0.
 */
int bowie_packet_is_protocol(bowie_span_t packet, uint8_t protocol);

/*
 * Return the length declared in the IP header, in bytes.
 *
 * The value is read from the packet; it is not checked
 * against the span length. A caller that wants to know how
 * much of the span is the packet must compare the two itself.
 *
 * Returns 0 if the span is too short to contain the length
 * field or the version is not recognized.
 */
uint16_t bowie_packet_length(bowie_span_t packet);

/*
 * ============================================================================
 * CHECKSUM
 * ============================================================================
 *
 * IPv4 has a header checksum; IPv6 does not. The checksum
 * function computes the IPv4 checksum and compares it against
 * the value in the header. For IPv6 it always returns 1,
 * because there is nothing to verify.
 */

/*
 * True when the packet's own header checksum is valid.
 *
 * For IPv4, the function computes the standard one's
 * complement sum over the header and compares it to the
 * checksum field in the header. The function returns 1 when
 * the header checksum is correct.
 *
 * For IPv6, the function returns 1. IPv6 has no header
 * checksum; the integrity of the packet is provided by the
 * transport layer or by the crypto layer above the tunnel.
 *
 * For any other version, the function returns 0.
 */
int bowie_packet_checksum_valid(bowie_span_t packet);

/*
 * ============================================================================
 * END OF TUNNEL PACKET
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_TUNNEL_PACKET_H */
