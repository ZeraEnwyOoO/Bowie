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
 * BOWIE — TUNNEL PACKET UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the IP packet helpers declared in
 * tunnel/packet.h.
 *
 * These tests exercise the contract: argument validation and
 * header parsing for both IPv4 and IPv6. They use synthetic
 * packet buffers, not real network traffic.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No network. The buffers are local arrays.
 *   - No checksum. The helpers do not verify checksums and the
 *     tests do not expect them to.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A minimal valid IPv4 header is 20 bytes. A minimal valid
 * IPv6 header is 40 bytes. The synthetic buffers are exactly
 * that size, with the fields the helpers read set to known
 * values and everything else zero.
 *
 * The suite is split into three cases:
 *
 *   version    — bowie_packet_version()
 *   parse      — bowie_packet_parse()
 *   helpers    — bowie_packet_length() and
 *                bowie_packet_is_protocol()
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         bowie_span_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "tunnel/packet.h"       public contract
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/packet.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build a minimal IPv4 packet in the supplied buffer.
 *
 * The header is 20 bytes. The version is 4, the IHL is 5 (20
 * bytes), the total length is 20, the protocol is UDP (17),
 * the source address is 192.0.2.1 and the destination is
 * 192.0.2.2.
 *
 * The buffer must be at least 20 bytes.
 */
static void make_ipv4(uint8_t *buf, size_t *len)
{
    memset(buf, 0, 20);

    buf[0]  = 0x45;   /* version 4, IHL 5 */
    buf[1]  = 0x00;   /* DSCP / ECN */
    buf[2]  = 0x00;   /* total length high */
    buf[3]  = 0x14;   /* total length low (20) */
    buf[8]  = 0x40;   /* TTL */
    buf[9]  = 0x11;   /* protocol: UDP */
    buf[12] = 192;
    buf[13] = 0;
    buf[14] = 2;
    buf[15] = 1;
    buf[16] = 192;
    buf[17] = 0;
    buf[18] = 2;
    buf[19] = 2;

    *len = 20;
}

/*
 * Build a minimal IPv6 packet in the supplied buffer.
 *
 * The header is 40 bytes. The version is 6, the payload
 * length is zero, the next header is UDP (17), the source
 * address is 2001:db8::1 and the destination is 2001:db8::2.
 *
 * The buffer must be at least 40 bytes.
 */
static void make_ipv6(uint8_t *buf, size_t *len)
{
    memset(buf, 0, 40);

    buf[0] = 0x60;   /* version 6 */
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;   /* payload length high */
    buf[5] = 0x00;   /* payload length low */
    buf[6] = 0x11;   /* next header: UDP */
    buf[7] = 0x40;   /* hop limit */

    /* Source: 2001:db8::1 */
    buf[8]  = 0x20;
    buf[9]  = 0x01;
    buf[10] = 0x0d;
    buf[11] = 0xb8;
    buf[23] = 0x01;

    /* Destination: 2001:db8::2 */
    buf[24] = 0x20;
    buf[25] = 0x01;
    buf[26] = 0x0d;
    buf[27] = 0xb8;
    buf[39] = 0x02;

    *len = 40;
}

/*
 * ============================================================================
 * VERSION
 * ============================================================================
 */

START_TEST(test_version_ipv4)
{
    uint8_t     buf[20];
    size_t      len;
    bowie_span_t span;
    uint8_t     version;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    version = bowie_packet_version(span);

    ck_assert_uint_eq(version, BOWIE_IP_VERSION_4);
}
END_TEST

START_TEST(test_version_ipv6)
{
    uint8_t     buf[40];
    size_t      len;
    bowie_span_t span;
    uint8_t     version;

    make_ipv6(buf, &len);

    span.data = buf;
    span.len  = len;

    version = bowie_packet_version(span);

    ck_assert_uint_eq(version, BOWIE_IP_VERSION_6);
}
END_TEST

START_TEST(test_version_empty)
{
    bowie_span_t span;
    uint8_t     version;

    span.data = NULL;
    span.len  = 0;

    version = bowie_packet_version(span);

    ck_assert_uint_eq(version, 0);
}
END_TEST

START_TEST(test_version_bad)
{
    uint8_t     buf[20];
    bowie_span_t span;
    uint8_t     version;

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x05;   /* version 5 (not IP) */

    span.data = buf;
    span.len  = sizeof(buf);

    version = bowie_packet_version(span);

    ck_assert_uint_eq(version, 0);
}
END_TEST

/*
 * ============================================================================
 * PARSE
 * ============================================================================
 */

START_TEST(test_parse_ipv4)
{
    uint8_t           buf[20];
    size_t            len;
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(parsed.version, BOWIE_IP_VERSION_4);
    ck_assert_uint_eq(parsed.header_len, 20);
    ck_assert_uint_eq(parsed.total_len, 20);
    ck_assert_uint_eq(parsed.protocol, 0x11);
    ck_assert_uint_eq(parsed.src_addr[0], 192);
    ck_assert_uint_eq(parsed.src_addr[3], 1);
    ck_assert_uint_eq(parsed.dst_addr[0], 192);
    ck_assert_uint_eq(parsed.dst_addr[3], 2);
}
END_TEST

START_TEST(test_parse_ipv6)
{
    uint8_t           buf[40];
    size_t            len;
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    make_ipv6(buf, &len);

    span.data = buf;
    span.len  = len;

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_uint_eq(parsed.version, BOWIE_IP_VERSION_6);
    ck_assert_uint_eq(parsed.header_len, 40);
    ck_assert_uint_eq(parsed.total_len, 40);
    ck_assert_uint_eq(parsed.protocol, 0x11);
    ck_assert_uint_eq(parsed.src_addr[0], 0x20);
    ck_assert_uint_eq(parsed.src_addr[1], 0x01);
    ck_assert_uint_eq(parsed.dst_addr[15], 0x02);
}
END_TEST

START_TEST(test_parse_null_out)
{
    uint8_t     buf[20];
    size_t      len;
    bowie_span_t span;
    bowie_error_t rc;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    rc = bowie_packet_parse(span, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_null_data)
{
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    span.data = NULL;
    span.len  = 20;

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_parse_too_short)
{
    uint8_t           buf[10];
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x45;   /* looks like IPv4 but too short */

    span.data = buf;
    span.len  = sizeof(buf);

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_parse_bad_version)
{
    uint8_t           buf[20];
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x55;   /* version 5 */

    span.data = buf;
    span.len  = sizeof(buf);

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_parse_bad_ihl)
{
    uint8_t           buf[20];
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x44;   /* version 4, IHL 4 (invalid, min is 5) */

    span.data = buf;
    span.len  = sizeof(buf);

    rc = bowie_packet_parse(span, &parsed);

    ck_assert_int_eq(rc, BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

START_TEST(test_length_ipv4)
{
    uint8_t     buf[20];
    size_t      len;
    bowie_span_t span;
    uint16_t    total;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    total = bowie_packet_length(span);

    ck_assert_uint_eq(total, 20);
}
END_TEST

START_TEST(test_length_ipv6)
{
    uint8_t     buf[40];
    size_t      len;
    bowie_span_t span;
    uint16_t    total;

    make_ipv6(buf, &len);

    span.data = buf;
    span.len  = len;

    total = bowie_packet_length(span);

    ck_assert_uint_eq(total, 40);
}
END_TEST

START_TEST(test_length_invalid)
{
    uint8_t     buf[10];
    bowie_span_t span;
    uint16_t    total;

    memset(buf, 0, sizeof(buf));

    span.data = buf;
    span.len  = sizeof(buf);

    total = bowie_packet_length(span);

    ck_assert_uint_eq(total, 0);
}
END_TEST

START_TEST(test_is_protocol_udp)
{
    uint8_t     buf[20];
    size_t      len;
    bowie_span_t span;
    int         is_udp;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    is_udp = bowie_packet_is_protocol(span, 0x11);

    ck_assert_int_eq(is_udp, 1);
}
END_TEST

START_TEST(test_is_protocol_tcp)
{
    uint8_t     buf[20];
    size_t      len;
    bowie_span_t span;
    int         is_tcp;

    make_ipv4(buf, &len);

    span.data = buf;
    span.len  = len;

    is_tcp = bowie_packet_is_protocol(span, 0x06);

    ck_assert_int_eq(is_tcp, 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *packet_suite(void)
{
    Suite *s;
    TCase *tc_version;
    TCase *tc_parse;
    TCase *tc_helpers;

    s = suite_create("TunnelPacket");

    tc_version = tcase_create("Version");
    tcase_add_test(tc_version, test_version_ipv4);
    tcase_add_test(tc_version, test_version_ipv6);
    tcase_add_test(tc_version, test_version_empty);
    tcase_add_test(tc_version, test_version_bad);
    suite_add_tcase(s, tc_version);

    tc_parse = tcase_create("Parse");
    tcase_add_test(tc_parse, test_parse_ipv4);
    tcase_add_test(tc_parse, test_parse_ipv6);
    tcase_add_test(tc_parse, test_parse_null_out);
    tcase_add_test(tc_parse, test_parse_null_data);
    tcase_add_test(tc_parse, test_parse_too_short);
    tcase_add_test(tc_parse, test_parse_bad_version);
    tcase_add_test(tc_parse, test_parse_bad_ihl);
    suite_add_tcase(s, tc_parse);

    tc_helpers = tcase_create("Helpers");
    tcase_add_test(tc_helpers, test_length_ipv4);
    tcase_add_test(tc_helpers, test_length_ipv6);
    tcase_add_test(tc_helpers, test_length_invalid);
    tcase_add_test(tc_helpers, test_is_protocol_udp);
    tcase_add_test(tc_helpers, test_is_protocol_tcp);
    suite_add_tcase(s, tc_helpers);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = packet_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
