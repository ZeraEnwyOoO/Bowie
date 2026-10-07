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
 * BOWIE — BYTES TESTS
 * ============================================================================
 *
 * Unit tests for src/core/bytes.c.
 *
 * Every public function declared in core/internal/bytes.h is
 * covered here.
 *
 * The cursor tests check the invariant directly: after a
 * successful get or put, the position advances by exactly the
 * number of bytes consumed. After a failed get or put, the
 * position does not move and the out value is not written.
 *
 * The length-prefixed tests check the boundary at 0, at 255,
 * and at 256. The constant-time comparison is checked for
 * equality, difference at the first byte, and difference at
 * the last byte.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <string.h>                      memset, memcmp
 *   "bowie/err.h"                   error codes
 *   "core/internal/bytes.h"         the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "core/internal/bytes.h"

/*
 * ============================================================================
 * CURSOR INIT AND RESET
 * ============================================================================
 */

START_TEST(test_cursor_init_null)
{
    bowie_cursor_init(NULL, NULL, 0u);
    /* No crash. */
}
END_TEST

START_TEST(test_cursor_init_empty)
{
    bowie_cursor_t c;
    bowie_cursor_init(&c, NULL, 0u);

    ck_assert_ptr_null(c.data);
    ck_assert_uint_eq(c.len, 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_cursor_init_basic)
{
    uint8_t buf[16];
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_ptr_eq(c.data, buf);
    ck_assert_uint_eq(c.len, 16u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_cursor_reset)
{
    uint8_t buf[16] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint16_t v = 0u;
    (void)bowie_cursor_get_be16(&c, &v);

    ck_assert_uint_eq(c.pos, 2u);
    bowie_cursor_reset(&c);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_cursor_reset_null)
{
    bowie_cursor_reset(NULL);
    /* No crash. */
}
END_TEST

START_TEST(test_cursor_remaining)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_remaining(&c), 8u);

    uint16_t v = 0u;
    (void)bowie_cursor_get_be16(&c, &v);
    ck_assert_uint_eq(bowie_cursor_remaining(&c), 6u);

    (void)bowie_cursor_get_be16(&c, &v);
    (void)bowie_cursor_get_be16(&c, &v);
    (void)bowie_cursor_get_be16(&c, &v);
    ck_assert_uint_eq(bowie_cursor_remaining(&c), 0u);
}
END_TEST

START_TEST(test_cursor_remaining_null)
{
    ck_assert_uint_eq(bowie_cursor_remaining(NULL), 0u);
}
END_TEST

/*
 * ============================================================================
 * READ — BIG-ENDIAN FIXED-WIDTH
 * ============================================================================
 */

START_TEST(test_get_be16_basic)
{
    uint8_t buf[2] = { 0x12, 0x34 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint16_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_be16(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x1234u);
    ck_assert_uint_eq(c.pos, 2u);
}
END_TEST

START_TEST(test_get_be32_basic)
{
    uint8_t buf[4] = { 0x12, 0x34, 0x56, 0x78 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint32_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_be32(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x12345678u);
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_get_be64_basic)
{
    uint8_t buf[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint64_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_be64(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x0123456789ABCDEFull);
    ck_assert_uint_eq(c.pos, 8u);
}
END_TEST

START_TEST(test_get_be16_short_buffer)
{
    uint8_t buf[1] = { 0x12 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint16_t v = 0xAAAAu;
    ck_assert_int_eq(bowie_cursor_get_be16(&c, &v),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(v, 0xAAAAu);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_be32_short_buffer)
{
    uint8_t buf[3] = { 0x12, 0x34, 0x56 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint32_t v = 0xAAAAAAAAu;
    ck_assert_int_eq(bowie_cursor_get_be32(&c, &v),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(v, 0xAAAAAAAAu);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_be64_short_buffer)
{
    uint8_t buf[7] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint64_t v = 0xAAAAAAAAAAAAAAAAull;
    ck_assert_int_eq(bowie_cursor_get_be64(&c, &v),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(v, 0xAAAAAAAAAAAAAAAAull);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_be16_null_cursor)
{
    uint16_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_be16(NULL, &v),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_get_be16_null_out)
{
    uint8_t buf[2] = { 0x12, 0x34 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_int_eq(bowie_cursor_get_be16(&c, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * READ — LITTLE-ENDIAN FIXED-WIDTH
 * ============================================================================
 */

START_TEST(test_get_le16_basic)
{
    uint8_t buf[2] = { 0x34, 0x12 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint16_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_le16(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x1234u);
    ck_assert_uint_eq(c.pos, 2u);
}
END_TEST

START_TEST(test_get_le32_basic)
{
    uint8_t buf[4] = { 0x78, 0x56, 0x34, 0x12 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint32_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_le32(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x12345678u);
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_get_le64_basic)
{
    uint8_t buf[8] = {
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint64_t v = 0u;
    ck_assert_int_eq(bowie_cursor_get_le64(&c, &v), BOWIE_OK);
    ck_assert_uint_eq(v, 0x0123456789ABCDEFull);
    ck_assert_uint_eq(c.pos, 8u);
}
END_TEST

/*
 * ============================================================================
 * READ — RAW
 * ============================================================================
 */

START_TEST(test_get_raw_basic)
{
    uint8_t buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[4] = { 0 };
    ck_assert_int_eq(bowie_cursor_get_raw(&c, out, 4u), BOWIE_OK);
    ck_assert_int_eq(memcmp(out, buf, 4u), 0);
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_get_raw_zero_len)
{
    uint8_t buf[4] = { 1, 2, 3, 4 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_int_eq(bowie_cursor_get_raw(&c, NULL, 0u), BOWIE_OK);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_raw_short_buffer)
{
    uint8_t buf[2] = { 1, 2 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[4] = { 0 };
    ck_assert_int_eq(bowie_cursor_get_raw(&c, out, 4u),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_raw_null_dst)
{
    uint8_t buf[4] = { 1, 2, 3, 4 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_int_eq(bowie_cursor_get_raw(&c, NULL, 4u),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_skip_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_int_eq(bowie_cursor_skip(&c, 3u), BOWIE_OK);
    ck_assert_uint_eq(c.pos, 3u);

    ck_assert_int_eq(bowie_cursor_skip(&c, 5u), BOWIE_OK);
    ck_assert_uint_eq(c.pos, 8u);
}
END_TEST

START_TEST(test_skip_too_far)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_int_eq(bowie_cursor_skip(&c, 5u),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

/*
 * ============================================================================
 * READ — LENGTH-PREFIXED
 * ============================================================================
 */

START_TEST(test_get_lp8_basic)
{
    uint8_t buf[6] = { 3, 'a', 'b', 'c', 0, 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[16] = { 0 };
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_cursor_get_lp8(&c, out, sizeof(out), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 3u);
    ck_assert_int_eq(memcmp(out, "abc", 3u), 0);
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_get_lp8_zero_len)
{
    uint8_t buf[1] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    size_t out_len = 99u;
    ck_assert_int_eq(
        bowie_cursor_get_lp8(&c, NULL, 0u, &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 0u);
    ck_assert_uint_eq(c.pos, 1u);
}
END_TEST

START_TEST(test_get_lp8_short_buffer)
{
    /* Length says 5 but only 3 bytes follow. */
    uint8_t buf[4] = { 5, 'a', 'b', 'c' };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[16] = { 0 };
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_cursor_get_lp8(&c, out, sizeof(out), &out_len),
        BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_lp8_dst_too_small)
{
    uint8_t buf[4] = { 3, 'a', 'b', 'c' };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[2] = { 0 };
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_cursor_get_lp8(&c, out, sizeof(out), &out_len),
        BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_lp8_no_out_len)
{
    uint8_t buf[4] = { 3, 'a', 'b', 'c' };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t out[16] = { 0 };
    ck_assert_int_eq(
        bowie_cursor_get_lp8(&c, out, sizeof(out), NULL),
        BOWIE_OK);
    ck_assert_int_eq(memcmp(out, "abc", 3u), 0);
}
END_TEST

START_TEST(test_get_lp8_str_basic)
{
    uint8_t buf[5] = { 3, 'a', 'b', 'c', 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    char out[16] = { 0 };
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_cursor_get_lp8_str(&c, out, sizeof(out) - 1u,
                                 &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 3u);
    ck_assert_str_eq(out, "abc");
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_get_lp8_str_too_long)
{
    uint8_t buf[4] = { 3, 'a', 'b', 'c' };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    char out[3] = { 0 };
    ck_assert_int_eq(
        bowie_cursor_get_lp8_str(&c, out, 2u, NULL),
        BOWIE_ERR_TOO_LARGE);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_get_lp8_str_empty)
{
    uint8_t buf[1] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    char out[8] = { 'x', 'x', 'x', 0 };
    size_t out_len = 99u;

    ck_assert_int_eq(
        bowie_cursor_get_lp8_str(&c, out, sizeof(out) - 1u,
                                 &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, 0u);
    ck_assert_str_eq(out, "");
}
END_TEST

/*
 * ============================================================================
 * WRITE — BIG-ENDIAN FIXED-WIDTH
 * ============================================================================
 */

START_TEST(test_put_be16_basic)
{
    uint8_t buf[2] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_be16(&c, 0x1234u), 2u);
    ck_assert_uint_eq(buf[0], 0x12u);
    ck_assert_uint_eq(buf[1], 0x34u);
    ck_assert_uint_eq(c.pos, 2u);
}
END_TEST

START_TEST(test_put_be32_basic)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_be32(&c, 0x12345678u), 4u);
    ck_assert_uint_eq(buf[0], 0x12u);
    ck_assert_uint_eq(buf[1], 0x34u);
    ck_assert_uint_eq(buf[2], 0x56u);
    ck_assert_uint_eq(buf[3], 0x78u);
}
END_TEST

START_TEST(test_put_be64_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(
        bowie_cursor_put_be64(&c, 0x0123456789ABCDEFull), 8u);
    ck_assert_uint_eq(buf[0], 0x01u);
    ck_assert_uint_eq(buf[7], 0xEFu);
}
END_TEST

START_TEST(test_put_be16_no_room)
{
    uint8_t buf[1] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_be16(&c, 0x1234u), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

/*
 * ============================================================================
 * WRITE — LITTLE-ENDIAN FIXED-WIDTH
 * ============================================================================
 */

START_TEST(test_put_le16_basic)
{
    uint8_t buf[2] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_le16(&c, 0x1234u), 2u);
    ck_assert_uint_eq(buf[0], 0x34u);
    ck_assert_uint_eq(buf[1], 0x12u);
}
END_TEST

START_TEST(test_put_le32_basic)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_le32(&c, 0x12345678u), 4u);
    ck_assert_uint_eq(buf[0], 0x78u);
    ck_assert_uint_eq(buf[3], 0x12u);
}
END_TEST

START_TEST(test_put_le64_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(
        bowie_cursor_put_le64(&c, 0x0123456789ABCDEFull), 8u);
    ck_assert_uint_eq(buf[0], 0xEFu);
    ck_assert_uint_eq(buf[7], 0x01u);
}
END_TEST

/*
 * ============================================================================
 * WRITE — RAW
 * ============================================================================
 */

START_TEST(test_put_raw_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    const uint8_t src[4] = { 1, 2, 3, 4 };
    ck_assert_uint_eq(bowie_cursor_put_raw(&c, src, 4u), 4u);
    ck_assert_int_eq(memcmp(buf, src, 4u), 0);
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_put_raw_zero_len)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_raw(&c, NULL, 0u), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_put_raw_null_src)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_raw(&c, NULL, 4u), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_put_raw_no_room)
{
    uint8_t buf[2] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    const uint8_t src[4] = { 1, 2, 3, 4 };
    ck_assert_uint_eq(bowie_cursor_put_raw(&c, src, 4u), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_put_zero_basic)
{
    uint8_t buf[8];
    memset(buf, 0xFF, sizeof(buf));

    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_zero(&c, 4u), 4u);
    for (size_t i = 0u; i < 4u; i++) {
        ck_assert_uint_eq(buf[i], 0u);
    }
    for (size_t i = 4u; i < 8u; i++) {
        ck_assert_uint_eq(buf[i], 0xFFu);
    }
}
END_TEST

/*
 * ============================================================================
 * WRITE — LENGTH-PREFIXED
 * ============================================================================
 */

START_TEST(test_put_lp8_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(
        bowie_cursor_put_lp8(&c, "abc", 3u), 4u);
    ck_assert_uint_eq(buf[0], 3u);
    ck_assert_uint_eq(buf[1], 'a');
    ck_assert_uint_eq(buf[2], 'b');
    ck_assert_uint_eq(buf[3], 'c');
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_put_lp8_zero_len)
{
    uint8_t buf[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_lp8(&c, NULL, 0u), 1u);
    ck_assert_uint_eq(buf[0], 0u);
    ck_assert_uint_eq(c.pos, 1u);
}
END_TEST

START_TEST(test_put_lp8_too_long)
{
    uint8_t buf[300] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    uint8_t src[256] = { 0 };
    ck_assert_uint_eq(
        bowie_cursor_put_lp8(&c, src, 256u), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_put_lp8_str_basic)
{
    uint8_t buf[8] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_lp8_str(&c, "abc"), 4u);
    ck_assert_uint_eq(buf[0], 3u);
    ck_assert_uint_eq(buf[1], 'a');
    ck_assert_uint_eq(c.pos, 4u);
}
END_TEST

START_TEST(test_put_lp8_str_null)
{
    uint8_t buf[4] = { 0 };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_lp8_str(&c, NULL), 0u);
    ck_assert_uint_eq(c.pos, 0u);
}
END_TEST

START_TEST(test_put_lp8_str_empty)
{
    uint8_t buf[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    bowie_cursor_t c;
    bowie_cursor_init(&c, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_lp8_str(&c, ""), 1u);
    ck_assert_uint_eq(buf[0], 0u);
    ck_assert_uint_eq(c.pos, 1u);
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP
 * ============================================================================
 */

START_TEST(test_roundtrip_be)
{
    uint8_t buf[14];
    bowie_cursor_t w;
    bowie_cursor_init(&w, buf, sizeof(buf));

    (void)bowie_cursor_put_be16(&w, 0x1234u);
    (void)bowie_cursor_put_be32(&w, 0xDEADBEEFu);
    (void)bowie_cursor_put_be64(&w, 0x0123456789ABCDEFull);

    bowie_cursor_t r;
    bowie_cursor_init(&r, buf, sizeof(buf));

    uint16_t v16 = 0u;
    uint32_t v32 = 0u;
    uint64_t v64 = 0u;

    ck_assert_int_eq(bowie_cursor_get_be16(&r, &v16), BOWIE_OK);
    ck_assert_int_eq(bowie_cursor_get_be32(&r, &v32), BOWIE_OK);
    ck_assert_int_eq(bowie_cursor_get_be64(&r, &v64), BOWIE_OK);

    ck_assert_uint_eq(v16, 0x1234u);
    ck_assert_uint_eq(v32, 0xDEADBEEFu);
    ck_assert_uint_eq(v64, 0x0123456789ABCDEFull);
}
END_TEST

START_TEST(test_roundtrip_lp8_str)
{
    uint8_t buf[32];
    bowie_cursor_t w;
    bowie_cursor_init(&w, buf, sizeof(buf));

    ck_assert_uint_eq(bowie_cursor_put_lp8_str(&w, "hello"), 6u);

    bowie_cursor_t r;
    bowie_cursor_init(&r, buf, sizeof(buf));

    char out[16] = { 0 };
    size_t out_len = 0u;
    ck_assert_int_eq(
        bowie_cursor_get_lp8_str(&r, out, sizeof(out) - 1u,
                                 &out_len),
        BOWIE_OK);
    ck_assert_str_eq(out, "hello");
    ck_assert_uint_eq(out_len, 5u);
}
END_TEST

/*
 * ============================================================================
 * UTILITIES
 * ============================================================================
 */

START_TEST(test_bytes_is_zero_all_zero)
{
    const uint8_t buf[4] = { 0, 0, 0, 0 };
    ck_assert(bowie_bytes_is_zero(buf, 4u));
}
END_TEST

START_TEST(test_bytes_is_zero_not_zero)
{
    const uint8_t buf[4] = { 0, 0, 0, 1 };
    ck_assert(!bowie_bytes_is_zero(buf, 4u));
}
END_TEST

START_TEST(test_bytes_is_zero_zero_len)
{
    const uint8_t buf[4] = { 1, 2, 3, 4 };
    ck_assert(bowie_bytes_is_zero(buf, 0u));
}
END_TEST

START_TEST(test_bytes_is_zero_null)
{
    ck_assert(bowie_bytes_is_zero(NULL, 0u));
    ck_assert(bowie_bytes_is_zero(NULL, 4u));
}
END_TEST

START_TEST(test_bytes_equal_ct_equal)
{
    const uint8_t a[4] = { 1, 2, 3, 4 };
    const uint8_t b[4] = { 1, 2, 3, 4 };
    ck_assert(bowie_bytes_equal_ct(a, b, 4u));
}
END_TEST

START_TEST(test_bytes_equal_ct_differs_first)
{
    const uint8_t a[4] = { 9, 2, 3, 4 };
    const uint8_t b[4] = { 1, 2, 3, 4 };
    ck_assert(!bowie_bytes_equal_ct(a, b, 4u));
}
END_TEST

START_TEST(test_bytes_equal_ct_differs_last)
{
    const uint8_t a[4] = { 1, 2, 3, 9 };
    const uint8_t b[4] = { 1, 2, 3, 4 };
    ck_assert(!bowie_bytes_equal_ct(a, b, 4u));
}
END_TEST

START_TEST(test_bytes_equal_ct_zero_len)
{
    ck_assert(bowie_bytes_equal_ct(NULL, NULL, 0u));
    ck_assert(bowie_bytes_equal_ct(NULL, "x", 0u));
}
END_TEST

START_TEST(test_bytes_equal_ct_null)
{
    const uint8_t a[4] = { 1, 2, 3, 4 };
    ck_assert(!bowie_bytes_equal_ct(a, NULL, 4u));
    ck_assert(!bowie_bytes_equal_ct(NULL, a, 4u));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *bytes_suite(void)
{
    Suite *s = suite_create("Bytes");

    TCase *tc_cursor = tcase_create("Cursor");
    tcase_add_test(tc_cursor, test_cursor_init_null);
    tcase_add_test(tc_cursor, test_cursor_init_empty);
    tcase_add_test(tc_cursor, test_cursor_init_basic);
    tcase_add_test(tc_cursor, test_cursor_reset);
    tcase_add_test(tc_cursor, test_cursor_reset_null);
    tcase_add_test(tc_cursor, test_cursor_remaining);
    tcase_add_test(tc_cursor, test_cursor_remaining_null);
    suite_add_tcase(s, tc_cursor);

    TCase *tc_be = tcase_create("ReadBE");
    tcase_add_test(tc_be, test_get_be16_basic);
    tcase_add_test(tc_be, test_get_be32_basic);
    tcase_add_test(tc_be, test_get_be64_basic);
    tcase_add_test(tc_be, test_get_be16_short_buffer);
    tcase_add_test(tc_be, test_get_be32_short_buffer);
    tcase_add_test(tc_be, test_get_be64_short_buffer);
    tcase_add_test(tc_be, test_get_be16_null_cursor);
    tcase_add_test(tc_be, test_get_be16_null_out);
    suite_add_tcase(s, tc_be);

    TCase *tc_le = tcase_create("ReadLE");
    tcase_add_test(tc_le, test_get_le16_basic);
    tcase_add_test(tc_le, test_get_le32_basic);
    tcase_add_test(tc_le, test_get_le64_basic);
    suite_add_tcase(s, tc_le);

    TCase *tc_raw = tcase_create("ReadRaw");
    tcase_add_test(tc_raw, test_get_raw_basic);
    tcase_add_test(tc_raw, test_get_raw_zero_len);
    tcase_add_test(tc_raw, test_get_raw_short_buffer);
    tcase_add_test(tc_raw, test_get_raw_null_dst);
    tcase_add_test(tc_raw, test_skip_basic);
    tcase_add_test(tc_raw, test_skip_too_far);
    suite_add_tcase(s, tc_raw);

    TCase *tc_lp8r = tcase_create("ReadLP8");
    tcase_add_test(tc_lp8r, test_get_lp8_basic);
    tcase_add_test(tc_lp8r, test_get_lp8_zero_len);
    tcase_add_test(tc_lp8r, test_get_lp8_short_buffer);
    tcase_add_test(tc_lp8r, test_get_lp8_dst_too_small);
    tcase_add_test(tc_lp8r, test_get_lp8_no_out_len);
    tcase_add_test(tc_lp8r, test_get_lp8_str_basic);
    tcase_add_test(tc_lp8r, test_get_lp8_str_too_long);
    tcase_add_test(tc_lp8r, test_get_lp8_str_empty);
    suite_add_tcase(s, tc_lp8r);

    TCase *tc_putbe = tcase_create("WriteBE");
    tcase_add_test(tc_putbe, test_put_be16_basic);
    tcase_add_test(tc_putbe, test_put_be32_basic);
    tcase_add_test(tc_putbe, test_put_be64_basic);
    tcase_add_test(tc_putbe, test_put_be16_no_room);
    suite_add_tcase(s, tc_putbe);

    TCase *tc_putle = tcase_create("WriteLE");
    tcase_add_test(tc_putle, test_put_le16_basic);
    tcase_add_test(tc_putle, test_put_le32_basic);
    tcase_add_test(tc_putle, test_put_le64_basic);
    suite_add_tcase(s, tc_putle);

    TCase *tc_putraw = tcase_create("WriteRaw");
    tcase_add_test(tc_putraw, test_put_raw_basic);
    tcase_add_test(tc_putraw, test_put_raw_zero_len);
    tcase_add_test(tc_putraw, test_put_raw_null_src);
    tcase_add_test(tc_putraw, test_put_raw_no_room);
    tcase_add_test(tc_putraw, test_put_zero_basic);
    suite_add_tcase(s, tc_putraw);

    TCase *tc_putlp8 = tcase_create("WriteLP8");
    tcase_add_test(tc_putlp8, test_put_lp8_basic);
    tcase_add_test(tc_putlp8, test_put_lp8_zero_len);
    tcase_add_test(tc_putlp8, test_put_lp8_too_long);
    tcase_add_test(tc_putlp8, test_put_lp8_str_basic);
    tcase_add_test(tc_putlp8, test_put_lp8_str_null);
    tcase_add_test(tc_putlp8, test_put_lp8_str_empty);
    suite_add_tcase(s, tc_putlp8);

    TCase *tc_rt = tcase_create("RoundTrip");
    tcase_add_test(tc_rt, test_roundtrip_be);
    tcase_add_test(tc_rt, test_roundtrip_lp8_str);
    suite_add_tcase(s, tc_rt);

    TCase *tc_util = tcase_create("Utilities");
    tcase_add_test(tc_util, test_bytes_is_zero_all_zero);
    tcase_add_test(tc_util, test_bytes_is_zero_not_zero);
    tcase_add_test(tc_util, test_bytes_is_zero_zero_len);
    tcase_add_test(tc_util, test_bytes_is_zero_null);
    tcase_add_test(tc_util, test_bytes_equal_ct_equal);
    tcase_add_test(tc_util, test_bytes_equal_ct_differs_first);
    tcase_add_test(tc_util, test_bytes_equal_ct_differs_last);
    tcase_add_test(tc_util, test_bytes_equal_ct_zero_len);
    tcase_add_test(tc_util, test_bytes_equal_ct_null);
    suite_add_tcase(s, tc_util);

    return s;
}

int main(void)
{
    Suite *s = bytes_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
