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
 * BOWIE — ENDIAN TESTS
 * ============================================================================
 *
 * Unit tests for src/core/endian.c.
 *
 * Every public function declared in core/internal/endian.h is
 * covered here.
 *
 * The tests fall into four groups:
 *
 *   1. Byte swap. The property is involution: swapping twice
 *      returns the original value.
 *
 *   2. Host conversion. The property is round-trip: converting
 *      to a byte order and back returns the original value.
 *
 *   3. Buffer serialization. The property is round-trip: a put
 *      followed by a get returns the original value. The
 *      byte-level tests assert the exact layout for one or two
 *      known values, so that a swap of the put function that
 *      still round-trips is caught.
 *
 *   4. Peek. The property is that peek returns the same value
 *      as get. There is no separate "advance" behavior in the
 *      API; the caller advances the pointer.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset
 *   "core/internal/endian.h"        the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "core/internal/endian.h"

/*
 * ============================================================================
 * BYTE SWAP
 * ============================================================================
 */

START_TEST(test_bswap16_zero)
{
    ck_assert_uint_eq(bowie_bswap16(0x0000u), 0x0000u);
}
END_TEST

START_TEST(test_bswap16_max)
{
    ck_assert_uint_eq(bowie_bswap16(0xFFFFu), 0xFFFFu);
}
END_TEST

START_TEST(test_bswap16_known)
{
    ck_assert_uint_eq(bowie_bswap16(0x1234u), 0x3412u);
    ck_assert_uint_eq(bowie_bswap16(0x00FFu), 0xFF00u);
    ck_assert_uint_eq(bowie_bswap16(0xFF00u), 0x00FFu);
}
END_TEST

START_TEST(test_bswap16_involution)
{
    const uint16_t values[] = {
        0x0000u, 0x0001u, 0x1234u, 0xABCDu, 0xFFFEu, 0xFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_bswap16(bowie_bswap16(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_bswap32_known)
{
    ck_assert_uint_eq(bowie_bswap32(0x00000000u), 0x00000000u);
    ck_assert_uint_eq(bowie_bswap32(0xFFFFFFFFu), 0xFFFFFFFFu);
    ck_assert_uint_eq(bowie_bswap32(0x12345678u), 0x78563412u);
    ck_assert_uint_eq(bowie_bswap32(0xDEADBEEFu), 0xEFBEADDEu);
}
END_TEST

START_TEST(test_bswap32_involution)
{
    const uint32_t values[] = {
        0x00000000u, 0x00000001u, 0x12345678u,
        0xDEADBEEFu, 0xFFFFFFFEu, 0xFFFFFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_bswap32(bowie_bswap32(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_bswap64_known)
{
    ck_assert_uint_eq(bowie_bswap64(0x0000000000000000ull),
                      0x0000000000000000ull);
    ck_assert_uint_eq(bowie_bswap64(0xFFFFFFFFFFFFFFFFull),
                      0xFFFFFFFFFFFFFFFFull);
    ck_assert_uint_eq(bowie_bswap64(0x0123456789ABCDEFull),
                      0xEFCDAB8967452301ull);
}
END_TEST

START_TEST(test_bswap64_involution)
{
    const uint64_t values[] = {
        0x0000000000000000ull,
        0x0000000000000001ull,
        0x0123456789ABCDEFull,
        0xFEDCBA9876543210ull,
        0xFFFFFFFFFFFFFFFEull,
        0xFFFFFFFFFFFFFFFFull,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_bswap64(bowie_bswap64(values[i])),
                          values[i]);
    }
}
END_TEST

/*
 * ============================================================================
 * HOST CONVERSION — ROUND TRIP
 * ============================================================================
 *
 * The property is that htobe followed by be16toh (and the
 * little-endian pair) returns the original host value. This
 * holds regardless of the host byte order.
 */

START_TEST(test_htobe16_roundtrip)
{
    const uint16_t values[] = {
        0x0000u, 0x0001u, 0x1234u, 0xABCDu, 0xFFFEu, 0xFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_be16toh(bowie_htobe16(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_htobe32_roundtrip)
{
    const uint32_t values[] = {
        0x00000000u, 0x00000001u, 0x12345678u,
        0xDEADBEEFu, 0xFFFFFFFEu, 0xFFFFFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_be32toh(bowie_htobe32(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_htobe64_roundtrip)
{
    const uint64_t values[] = {
        0x0000000000000000ull,
        0x0000000000000001ull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFEull,
        0xFFFFFFFFFFFFFFFFull,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_be64toh(bowie_htobe64(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_htole16_roundtrip)
{
    const uint16_t values[] = {
        0x0000u, 0x0001u, 0x1234u, 0xABCDu, 0xFFFEu, 0xFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_le16toh(bowie_htole16(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_htole32_roundtrip)
{
    const uint32_t values[] = {
        0x00000000u, 0x00000001u, 0x12345678u,
        0xDEADBEEFu, 0xFFFFFFFEu, 0xFFFFFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_le32toh(bowie_htole32(values[i])),
                          values[i]);
    }
}
END_TEST

START_TEST(test_htole64_roundtrip)
{
    const uint64_t values[] = {
        0x0000000000000000ull,
        0x0000000000000001ull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFEull,
        0xFFFFFFFFFFFFFFFFull,
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0u; i < n; i++) {
        ck_assert_uint_eq(bowie_le64toh(bowie_htole64(values[i])),
                          values[i]);
    }
}
END_TEST

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER — KNOWN BYTES
 * ============================================================================
 */

START_TEST(test_be16_put_known_bytes)
{
    uint8_t buf[2];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_be16_put(buf, 0x1234u);
    ck_assert_uint_eq(n, 2u);
    ck_assert_uint_eq(buf[0], 0x12u);
    ck_assert_uint_eq(buf[1], 0x34u);
}
END_TEST

START_TEST(test_be32_put_known_bytes)
{
    uint8_t buf[4];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_be32_put(buf, 0x12345678u);
    ck_assert_uint_eq(n, 4u);
    ck_assert_uint_eq(buf[0], 0x12u);
    ck_assert_uint_eq(buf[1], 0x34u);
    ck_assert_uint_eq(buf[2], 0x56u);
    ck_assert_uint_eq(buf[3], 0x78u);
}
END_TEST

START_TEST(test_be64_put_known_bytes)
{
    uint8_t buf[8];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_be64_put(buf, 0x0123456789ABCDEFull);
    ck_assert_uint_eq(n, 8u);
    ck_assert_uint_eq(buf[0], 0x01u);
    ck_assert_uint_eq(buf[1], 0x23u);
    ck_assert_uint_eq(buf[2], 0x45u);
    ck_assert_uint_eq(buf[3], 0x67u);
    ck_assert_uint_eq(buf[4], 0x89u);
    ck_assert_uint_eq(buf[5], 0xABu);
    ck_assert_uint_eq(buf[6], 0xCDu);
    ck_assert_uint_eq(buf[7], 0xEFu);
}
END_TEST

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER — ROUND TRIP
 * ============================================================================
 */

START_TEST(test_be16_roundtrip)
{
    const uint16_t values[] = {
        0x0000u, 0x0001u, 0x1234u, 0xABCDu, 0xFFFEu, 0xFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[2];
        (void)bowie_be16_put(buf, values[i]);
        ck_assert_uint_eq(bowie_be16_get(buf), values[i]);
    }
}
END_TEST

START_TEST(test_be32_roundtrip)
{
    const uint32_t values[] = {
        0x00000000u, 0x00000001u, 0x12345678u,
        0xDEADBEEFu, 0xFFFFFFFEu, 0xFFFFFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[4];
        (void)bowie_be32_put(buf, values[i]);
        ck_assert_uint_eq(bowie_be32_get(buf), values[i]);
    }
}
END_TEST

START_TEST(test_be64_roundtrip)
{
    const uint64_t values[] = {
        0x0000000000000000ull,
        0x0000000000000001ull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFEull,
        0xFFFFFFFFFFFFFFFFull,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[8];
        (void)bowie_be64_put(buf, values[i]);
        ck_assert_uint_eq(bowie_be64_get(buf), values[i]);
    }
}
END_TEST

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER — SEQUENTIAL OFFSETS
 * ============================================================================
 */

START_TEST(test_be_sequential_offsets)
{
    /*
     * Write a 2-, 4-, and 8-byte value back to back in one
     * buffer, then read them back at the right offsets.
     */
    uint8_t buf[14];

    (void)bowie_be16_put(buf +  0u, 0x1234u);
    (void)bowie_be32_put(buf +  2u, 0xDEADBEEFu);
    (void)bowie_be64_put(buf +  6u, 0x0123456789ABCDEFull);

    ck_assert_uint_eq(bowie_be16_get(buf +  0u), 0x1234u);
    ck_assert_uint_eq(bowie_be32_get(buf +  2u), 0xDEADBEEFu);
    ck_assert_uint_eq(bowie_be64_get(buf +  6u),
                      0x0123456789ABCDEFull);
}
END_TEST

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER — PEEK
 * ============================================================================
 */

START_TEST(test_be16_peek_matches_get)
{
    uint8_t buf[2];
    (void)bowie_be16_put(buf, 0xABCDu);
    ck_assert_uint_eq(bowie_be16_peek(buf), bowie_be16_get(buf));
}
END_TEST

START_TEST(test_be32_peek_matches_get)
{
    uint8_t buf[4];
    (void)bowie_be32_put(buf, 0xDEADBEEFu);
    ck_assert_uint_eq(bowie_be32_peek(buf), bowie_be32_get(buf));
}
END_TEST

START_TEST(test_be64_peek_matches_get)
{
    uint8_t buf[8];
    (void)bowie_be64_put(buf, 0x0123456789ABCDEFull);
    ck_assert_uint_eq(bowie_be64_peek(buf), bowie_be64_get(buf));
}
END_TEST

START_TEST(test_peek_does_not_advance)
{
    /*
     * The API has no advancing form. The test asserts that a
     * peek is a pure read: the buffer is unchanged after the
     * call, and two peeks return the same value.
     */
    uint8_t buf[8];
    (void)bowie_be64_put(buf, 0x0123456789ABCDEFull);

    uint8_t before[8];
    memcpy(before, buf, sizeof(before));

    uint64_t a = bowie_be64_peek(buf);
    uint64_t b = bowie_be64_peek(buf);

    ck_assert_uint_eq(a, b);
    ck_assert_int_eq(memcmp(before, buf, sizeof(buf)), 0);
}
END_TEST

/*
 * ============================================================================
 * LITTLE-ENDIAN BUFFER — KNOWN BYTES
 * ============================================================================
 */

START_TEST(test_le16_put_known_bytes)
{
    uint8_t buf[2];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_le16_put(buf, 0x1234u);
    ck_assert_uint_eq(n, 2u);
    ck_assert_uint_eq(buf[0], 0x34u);
    ck_assert_uint_eq(buf[1], 0x12u);
}
END_TEST

START_TEST(test_le32_put_known_bytes)
{
    uint8_t buf[4];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_le32_put(buf, 0x12345678u);
    ck_assert_uint_eq(n, 4u);
    ck_assert_uint_eq(buf[0], 0x78u);
    ck_assert_uint_eq(buf[1], 0x56u);
    ck_assert_uint_eq(buf[2], 0x34u);
    ck_assert_uint_eq(buf[3], 0x12u);
}
END_TEST

START_TEST(test_le64_put_known_bytes)
{
    uint8_t buf[8];
    memset(buf, 0, sizeof(buf));

    size_t n = bowie_le64_put(buf, 0x0123456789ABCDEFull);
    ck_assert_uint_eq(n, 8u);
    ck_assert_uint_eq(buf[0], 0xEFu);
    ck_assert_uint_eq(buf[1], 0xCDu);
    ck_assert_uint_eq(buf[2], 0xABu);
    ck_assert_uint_eq(buf[3], 0x89u);
    ck_assert_uint_eq(buf[4], 0x67u);
    ck_assert_uint_eq(buf[5], 0x45u);
    ck_assert_uint_eq(buf[6], 0x23u);
    ck_assert_uint_eq(buf[7], 0x01u);
}
END_TEST

/*
 * ============================================================================
 * LITTLE-ENDIAN BUFFER — ROUND TRIP
 * ============================================================================
 */

START_TEST(test_le16_roundtrip)
{
    const uint16_t values[] = {
        0x0000u, 0x0001u, 0x1234u, 0xABCDu, 0xFFFEu, 0xFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[2];
        (void)bowie_le16_put(buf, values[i]);
        ck_assert_uint_eq(bowie_le16_get(buf), values[i]);
    }
}
END_TEST

START_TEST(test_le32_roundtrip)
{
    const uint32_t values[] = {
        0x00000000u, 0x00000001u, 0x12345678u,
        0xDEADBEEFu, 0xFFFFFFFEu, 0xFFFFFFFFu,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[4];
        (void)bowie_le32_put(buf, values[i]);
        ck_assert_uint_eq(bowie_le32_get(buf), values[i]);
    }
}
END_TEST

START_TEST(test_le64_roundtrip)
{
    const uint64_t values[] = {
        0x0000000000000000ull,
        0x0000000000000001ull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFEull,
        0xFFFFFFFFFFFFFFFFull,
    };
    size_t n = sizeof(values) / sizeof(values[0]);

    for (size_t i = 0u; i < n; i++) {
        uint8_t buf[8];
        (void)bowie_le64_put(buf, values[i]);
        ck_assert_uint_eq(bowie_le64_get(buf), values[i]);
    }
}
END_TEST

/*
 * ============================================================================
 * BIG-ENDIAN VS LITTLE-ENDIAN — DIFFERENT BYTE ORDER
 * ============================================================================
 *
 * A value written in the two orders must produce different
 * bytes for any value whose bytes are not all equal.
 */

START_TEST(test_be_le_differ)
{
    uint8_t be[4];
    uint8_t le[4];

    (void)bowie_be32_put(be, 0x12345678u);
    (void)bowie_le32_put(le, 0x12345678u);

    ck_assert_int_ne(memcmp(be, le, 4), 0);
}
END_TEST

START_TEST(test_be_le_same_for_palindrome)
{
    /*
     * A value whose four bytes are all equal has the same
     * representation in both orders.
     */
    uint8_t be[4];
    uint8_t le[4];

    (void)bowie_be32_put(be, 0xAAAAAAAAu);
    (void)bowie_le32_put(le, 0xAAAAAAAAu);

    ck_assert_int_eq(memcmp(be, le, 4), 0);
}
END_TEST

/*
 * ============================================================================
 * UNALIGNED ACCESS
 * ============================================================================
 *
 * The buffer functions are byte-by-byte and must not assume
 * alignment. Writing at an odd offset must produce the same
 * bytes as writing at offset zero.
 */

START_TEST(test_be32_unaligned_matches_aligned)
{
    uint8_t aligned[4];
    uint8_t unaligned[5];

    (void)bowie_be32_put(aligned, 0xDEADBEEFu);
    (void)bowie_be32_put(unaligned + 1u, 0xDEADBEEFu);

    ck_assert_int_eq(memcmp(aligned, unaligned + 1u, 4), 0);
}
END_TEST

START_TEST(test_le32_unaligned_matches_aligned)
{
    uint8_t aligned[4];
    uint8_t unaligned[5];

    (void)bowie_le32_put(aligned, 0xDEADBEEFu);
    (void)bowie_le32_put(unaligned + 1u, 0xDEADBEEFu);

    ck_assert_int_eq(memcmp(aligned, unaligned + 1u, 4), 0);
}
END_TEST

START_TEST(test_be64_unaligned_matches_aligned)
{
    uint8_t aligned[8];
    uint8_t unaligned[9];

    (void)bowie_be64_put(aligned, 0x0123456789ABCDEFull);
    (void)bowie_be64_put(unaligned + 1u, 0x0123456789ABCDEFull);

    ck_assert_int_eq(memcmp(aligned, unaligned + 1u, 8), 0);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *endian_suite(void)
{
    Suite *s = suite_create("Endian");

    TCase *tc_swap = tcase_create("ByteSwap");
    tcase_add_test(tc_swap, test_bswap16_zero);
    tcase_add_test(tc_swap, test_bswap16_max);
    tcase_add_test(tc_swap, test_bswap16_known);
    tcase_add_test(tc_swap, test_bswap16_involution);
    tcase_add_test(tc_swap, test_bswap32_known);
    tcase_add_test(tc_swap, test_bswap32_involution);
    tcase_add_test(tc_swap, test_bswap64_known);
    tcase_add_test(tc_swap, test_bswap64_involution);
    suite_add_tcase(s, tc_swap);

    TCase *tc_host = tcase_create("HostConversion");
    tcase_add_test(tc_host, test_htobe16_roundtrip);
    tcase_add_test(tc_host, test_htobe32_roundtrip);
    tcase_add_test(tc_host, test_htobe64_roundtrip);
    tcase_add_test(tc_host, test_htole16_roundtrip);
    tcase_add_test(tc_host, test_htole32_roundtrip);
    tcase_add_test(tc_host, test_htole64_roundtrip);
    suite_add_tcase(s, tc_host);

    TCase *tc_be_known = tcase_create("BigEndianKnownBytes");
    tcase_add_test(tc_be_known, test_be16_put_known_bytes);
    tcase_add_test(tc_be_known, test_be32_put_known_bytes);
    tcase_add_test(tc_be_known, test_be64_put_known_bytes);
    suite_add_tcase(s, tc_be_known);

    TCase *tc_be_rt = tcase_create("BigEndianRoundTrip");
    tcase_add_test(tc_be_rt, test_be16_roundtrip);
    tcase_add_test(tc_be_rt, test_be32_roundtrip);
    tcase_add_test(tc_be_rt, test_be64_roundtrip);
    tcase_add_test(tc_be_rt, test_be_sequential_offsets);
    suite_add_tcase(s, tc_be_rt);

    TCase *tc_peek = tcase_create("Peek");
    tcase_add_test(tc_peek, test_be16_peek_matches_get);
    tcase_add_test(tc_peek, test_be32_peek_matches_get);
    tcase_add_test(tc_peek, test_be64_peek_matches_get);
    tcase_add_test(tc_peek, test_peek_does_not_advance);
    suite_add_tcase(s, tc_peek);

    TCase *tc_le_known = tcase_create("LittleEndianKnownBytes");
    tcase_add_test(tc_le_known, test_le16_put_known_bytes);
    tcase_add_test(tc_le_known, test_le32_put_known_bytes);
    tcase_add_test(tc_le_known, test_le64_put_known_bytes);
    suite_add_tcase(s, tc_le_known);

    TCase *tc_le_rt = tcase_create("LittleEndianRoundTrip");
    tcase_add_test(tc_le_rt, test_le16_roundtrip);
    tcase_add_test(tc_le_rt, test_le32_roundtrip);
    tcase_add_test(tc_le_rt, test_le64_roundtrip);
    suite_add_tcase(s, tc_le_rt);

    TCase *tc_diff = tcase_create("ByteOrderDiff");
    tcase_add_test(tc_diff, test_be_le_differ);
    tcase_add_test(tc_diff, test_be_le_same_for_palindrome);
    suite_add_tcase(s, tc_diff);

    TCase *tc_unaligned = tcase_create("Unaligned");
    tcase_add_test(tc_unaligned, test_be32_unaligned_matches_aligned);
    tcase_add_test(tc_unaligned, test_le32_unaligned_matches_aligned);
    tcase_add_test(tc_unaligned, test_be64_unaligned_matches_aligned);
    suite_add_tcase(s, tc_unaligned);

    return s;
}

int main(void)
{
    Suite *s = endian_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
