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
 * These tests build real IPv4 and IPv6 packets (with valid
 * checksums) and check that the parse, length, protocol, and
 * checksum functions return the right answers. They also
 * corrupt a byte and check that the checksum verification
 * catches it.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A minimal IPv4 header is 20 bytes. A minimal IPv6 header is
 * 40 bytes. The packets are built by hand so that the test
 * controls every byte and does not depend on the kernel.
 *
 * The checksum is computed inside the test with a private
 * helper. It is the same algorithm as the one in packet.c,
 * but written independently so that a bug in one is not
 * automatically reflected in the other.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         bowie_span_t
 *   "bowie/err.h"           bowie_error_t
 *   "tunnel/packet.h"       declarations and constants
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/packet.h"

/*
 * ============================================================================
 * PRIVATE CHECKSUM
 * ============================================================================
 *
 * A private copy of the Internet checksum. The test uses it
 * to build a packet whose header checksum is correct.
 */

static uint16_t test_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t   i;

    for (i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)(((uint16_t)data[i] << 8) | data[i + 1]);
    }

    if (i < len) {
        sum += (uint32_t)((uint16_t)data[i] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFFu);
}

/*
 * ============================================================================
 * PACKET BUILDERS
 * ============================================================================
 */

/*
 * Build a minimal IPv4 header (20 bytes) with a valid
 * checksum.
 */
static void make_ipv4(uint8_t *buf)
{
    uint16_t sum;

    memset(buf, 0, 20);

    buf[0]  = 0x45;    /* version 4, IHL 5 */
    buf[8]  = 0x40;    /* TTL */
    buf[9]  = 0x11;    /* protocol: UDP */
    buf[12] = 192;
    buf[13] = 0;
    buf[14] = 2;
    buf[15] = 1;
    buf[16] = 192;
    buf[17] = 0;
    buf[18] = 2;
    buf[19] = 2;

    /* total length (20) */
    buf[2] = 0;
    buf[3] = 20;

    /* checksum field starts at offset 10 */
    buf[10] = 0;
    buf[11] = 0;

    sum = test_checksum(buf, 20);
    buf[10] = (uint8_t)(sum >> 8);
    buf[11] = (uint8_t)(sum & 0xFF);
}

/*
 * Build a minimal IPv6 header (40 bytes). IPv6 has no header
 * checksum, so no checksum is written.
 */
static void make_ipv6(uint8_t *buf)
{
    memset(buf, 0, 40);

    buf[0]  = 0x60;    /* version 6 */
    buf[6]  = 0x11;    /* next header: UDP */
    buf[7]  = 0x40;    /* hop limit */
    buf[8]  = 0x20;
    buf[9]  = 0x01;
    buf[10] = 0x0d;
    buf[11] = 0xb8;
    buf[23] = 0x01;
    buf[24] = 0x20;
    buf[25] = 0x01;
    buf[26] = 0x0d;
    buf[27] = 0xb8;
    buf[39] = 0x02;
}

/*
 * ============================================================================
 * VERSION
 * ============================================================================
 */

START_TEST(test_version_ipv4)
{
    uint8_t      buf[20];
    bowie_span_t span;

    make_ipv4(buf);
    span.data = buf;
    span.len  = sizeof(buf);

    ck_assert_uint_eq(bowie_packet_version(span), BOWIE_IP_VERSION_4);
}
END_TEST

START_TEST(test_version_ipv6)
{
    uint8_t      buf[40];
    bowie_span_t span;

    make_ipv6(buf);
    span.data = buf;
    span.len  = sizeof(buf);

    ck_assert_uint_eq(bowie_packet_version(span), BOWIE_IP_VERSION_6);
}
END_TEST

START_TEST(test_version_empty)
{
    bowie_span_t span;

    span.data = NULL;
    span.len  = 0;

    ck_assert_uint_eq(bowie_packet_version(span), 0);
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
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    make_ipv4(buf);
    span.data = buf;
    span.len  = sizeof(buf);

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
    bowie_span_t      span;
    bowie_ip_packet_t parsed;
    bowie_error_t     rc;

    make_ipv6(buf);
    span.data = buf;
    span.len  = sizeof(buf);

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

/*
 * ============================================================================
 * CHECKSUM
 * ============================================================================
 */

START_TEST(test_checksum_valid_ipv4)
{
    uint8_t      buf[20];
    bowie_span_t span;

    make_ipv4(buf);
    span.data = buf;
    span.len  = sizeof(buf);

    ck_assert_int_eq(bowie_packet_checksum_valid(span), 1);
}
END_TEST

START_TEST(test_checksum_invalid_ipv4)
{
    uint8_t      buf[20];
    bowie_span_t span;

    make_ipv4(buf);

    /*
     * Flip a bit in the source address. The header checksum
     * no longer matches.
     */
    buf[12] ^= 0x01;

    span.data = buf;
    span.len  = sizeof(buf);

    ck_assert_int_eq(bowie_packet_checksum_valid(span), 0);
}
END_TEST

START_TEST(test_checksum_valid_ipv6)
{
    uint8_t      buf[40];
    bowie_span_t span;

    make_ipv6(buf);
    span.data = buf;
    span.len  = sizeof(buf);

    /* IPv6 has no checksum, so the function always returns 1. */
    ck_assert_int_eq(bowie_packet_checksum_valid(span), 1);
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
    TCase *tc_checksum;

    s = suite_create("TunnelPacket");

    tc_version = tcase_create("Version");
    tcase_add_test(tc_version, test_version_ipv4);
    tcase_add_test(tc_version, test_version_ipv6);
    tcase_add_test(tc_version, test_version_empty);
    suite_add_tcase(s, tc_version);

    tc_parse = tcase_create("Parse");
    tcase_add_test(tc_parse, test_parse_ipv4);
    tcase_add_test(tc_parse, test_parse_ipv6);
    suite_add_tcase(s, tc_parse);

    tc_checksum = tcase_create("Checksum");
    tcase_add_test(tc_checksum, test_checksum_valid_ipv4);
    tcase_add_test(tc_checksum, test_checksum_invalid_ipv4);
    tcase_add_test(tc_checksum, test_checksum_valid_ipv6);
    suite_add_tcase(s, tc_checksum);

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
