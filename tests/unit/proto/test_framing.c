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
 * BOWIE — PROTOCOL FRAMING TESTS
 * ============================================================================
 *
 * Unit tests for src/proto/framing.c.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "proto/framing.h"            the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "proto/framing.h"

/*
 * ============================================================================
 * FRAME HEADER ENCODE
 * ============================================================================
 */

START_TEST(test_hdr_encode_null_hdr)
{
    uint8_t buf[8];
    ck_assert_int_eq(
        bowie_proto_frame_header_encode(NULL, buf, sizeof(buf)),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hdr_encode_null_buf)
{
    bowie_proto_frame_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    ck_assert_int_eq(
        bowie_proto_frame_header_encode(&hdr, NULL, 8u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hdr_encode_too_small)
{
    bowie_proto_frame_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    uint8_t buf[2];

    ck_assert_int_eq(
        bowie_proto_frame_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_hdr_encode_too_large)
{
    bowie_proto_frame_header_t hdr;
    hdr.length = BOWIE_PROTO_MAX_FRAME + 1u;

    uint8_t buf[8];

    ck_assert_int_eq(
        bowie_proto_frame_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_hdr_encode_ok)
{
    /*
     * The length must be at most BOWIE_PROTO_MAX_FRAME (1200).
     * 0x00000400 = 1024 is used so that the byte order check
     * below can verify all four bytes without the value being
     * rejected by the encoder.
     */
    bowie_proto_frame_header_t hdr;
    hdr.length = 0x00000400u;  /* 1024 */

    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];

    ck_assert_int_eq(
        bowie_proto_frame_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_OK);

    /* Big-endian check. */
    ck_assert_uint_eq(buf[0], 0x00u);
    ck_assert_uint_eq(buf[1], 0x00u);
    ck_assert_uint_eq(buf[2], 0x04u);
    ck_assert_uint_eq(buf[3], 0x00u);
}
END_TEST

/*
 * ============================================================================
 * FRAME HEADER DECODE
 * ============================================================================
 */

START_TEST(test_hdr_decode_null_buf)
{
    bowie_proto_frame_header_t hdr;
    ck_assert_int_eq(
        bowie_proto_frame_header_decode(NULL, 8u, &hdr),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hdr_decode_null_hdr)
{
    uint8_t buf[8];
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(
        bowie_proto_frame_header_decode(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_hdr_decode_too_small)
{
    uint8_t buf[2];
    memset(buf, 0, sizeof(buf));
    bowie_proto_frame_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_frame_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_hdr_decode_too_large)
{
    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    uint32_t too_big = BOWIE_PROTO_MAX_FRAME + 1u;
    buf[0] = (uint8_t)((too_big >> 24) & 0xFFu);
    buf[1] = (uint8_t)((too_big >> 16) & 0xFFu);
    buf[2] = (uint8_t)((too_big >> 8) & 0xFFu);
    buf[3] = (uint8_t)(too_big & 0xFFu);

    bowie_proto_frame_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_frame_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_hdr_decode_ok)
{
    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    buf[0] = 0x00u;
    buf[1] = 0x00u;
    buf[2] = 0x00u;
    buf[3] = 0x10u;  /* length = 16 */

    bowie_proto_frame_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_frame_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_OK);
    ck_assert_uint_eq(hdr.length, 16u);
}
END_TEST

/*
 * ============================================================================
 * FRAME HEADER ROUND TRIP
 * ============================================================================
 */

START_TEST(test_hdr_round_trip)
{
    /*
     * The length must be at most BOWIE_PROTO_MAX_FRAME (1200).
     */
    bowie_proto_frame_header_t in;
    in.length = 1000u;

    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    ck_assert_int_eq(
        bowie_proto_frame_header_encode(&in, buf, sizeof(buf)),
        BOWIE_OK);

    bowie_proto_frame_header_t out;
    ck_assert_int_eq(
        bowie_proto_frame_header_decode(buf, sizeof(buf), &out),
        BOWIE_OK);

    ck_assert_uint_eq(out.length, in.length);
}
END_TEST

/*
 * ============================================================================
 * FRAME ENCODE
 * ============================================================================
 */

START_TEST(test_frame_encode_null_frame)
{
    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(NULL, buf, sizeof(buf), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_frame_encode_null_buf)
{
    bowie_proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&frame, NULL, 64u, &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_frame_encode_null_out)
{
    bowie_proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    uint8_t buf[64];

    ck_assert_int_eq(
        bowie_proto_frame_encode(&frame, buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_frame_encode_too_small)
{
    bowie_proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));

    uint8_t buf[2];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&frame, buf, sizeof(buf),
                                 &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_frame_encode_empty)
{
    bowie_proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));

    uint8_t buf[16];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&frame, buf, sizeof(buf),
                                 &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, BOWIE_PROTO_FRAME_HEADER_LEN);
}
END_TEST

START_TEST(test_frame_encode_with_data)
{
    const uint8_t data[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    bowie_proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.message.data = data;
    frame.message.len  = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&frame, buf, sizeof(buf),
                                 &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len,
                      BOWIE_PROTO_FRAME_HEADER_LEN + sizeof(data));

    /* Length field is big-endian. */
    ck_assert_uint_eq(buf[0], 0x00u);
    ck_assert_uint_eq(buf[1], 0x00u);
    ck_assert_uint_eq(buf[2], 0x00u);
    ck_assert_uint_eq(buf[3], 0x04u);

    /* Message bytes follow the header. */
    ck_assert_mem_eq(buf + BOWIE_PROTO_FRAME_HEADER_LEN,
                     data, sizeof(data));
}
END_TEST

/*
 * ============================================================================
 * FRAME DECODE
 * ============================================================================
 */

START_TEST(test_frame_decode_null_buf)
{
    bowie_proto_frame_t frame;
    ck_assert_int_eq(
        bowie_proto_frame_decode(NULL, 16u, &frame),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_frame_decode_null_frame)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_frame_decode_too_small_for_header)
{
    uint8_t buf[2];
    memset(buf, 0, sizeof(buf));
    bowie_proto_frame_t frame;

    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, sizeof(buf), &frame),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_frame_decode_message_truncated)
{
    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    memset(buf, 0, sizeof(buf));
    buf[3] = 16u;  /* says 16 bytes message, but only 0 provided */

    bowie_proto_frame_t frame;

    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, sizeof(buf), &frame),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_frame_decode_ok)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    buf[3] = 4u;  /* message length = 4 */
    buf[4] = 0xAAu;
    buf[5] = 0xBBu;
    buf[6] = 0xCCu;
    buf[7] = 0xDDu;

    bowie_proto_frame_t frame;

    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, 8u, &frame),
        BOWIE_OK);
    ck_assert_uint_eq(frame.header.length, 4u);
    ck_assert_uint_eq(frame.message.len, 4u);
    ck_assert_ptr_eq(frame.message.data,
                     buf + BOWIE_PROTO_FRAME_HEADER_LEN);
    ck_assert_uint_eq(frame.message.data[0], 0xAAu);
    ck_assert_uint_eq(frame.message.data[3], 0xDDu);
}
END_TEST

/*
 * ============================================================================
 * FRAME ROUND TRIP
 * ============================================================================
 */

START_TEST(test_frame_round_trip_empty)
{
    bowie_proto_frame_t in;
    memset(&in, 0, sizeof(in));

    uint8_t buf[16];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&in, buf, sizeof(buf),
                                 &out_len),
        BOWIE_OK);

    bowie_proto_frame_t out;
    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, out_len, &out),
        BOWIE_OK);
    ck_assert_uint_eq(out.message.len, 0u);
}
END_TEST

START_TEST(test_frame_round_trip_with_data)
{
    const uint8_t data[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    };

    bowie_proto_frame_t in;
    memset(&in, 0, sizeof(in));
    in.message.data = data;
    in.message.len  = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_encode(&in, buf, sizeof(buf),
                                 &out_len),
        BOWIE_OK);

    bowie_proto_frame_t out;
    ck_assert_int_eq(
        bowie_proto_frame_decode(buf, out_len, &out),
        BOWIE_OK);
    ck_assert_uint_eq(out.message.len, sizeof(data));
    ck_assert_mem_eq(out.message.data, data, sizeof(data));
}
END_TEST

/*
 * ============================================================================
 * WRAP / UNWRAP
 * ============================================================================
 */

START_TEST(test_wrap_null_buf)
{
    bowie_span_t msg = { NULL, 0u };
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_wrap(msg, NULL, 64u, &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_wrap_null_out)
{
    bowie_span_t msg = { NULL, 0u };
    uint8_t buf[64];

    ck_assert_int_eq(
        bowie_proto_frame_wrap(msg, buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_wrap_ok)
{
    const uint8_t data[] = { 0x01, 0x02, 0x03 };

    bowie_span_t msg;
    msg.data = data;
    msg.len  = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_wrap(msg, buf, sizeof(buf), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len,
                      BOWIE_PROTO_FRAME_HEADER_LEN + sizeof(data));
    ck_assert_uint_eq(buf[3], sizeof(data));
    ck_assert_mem_eq(buf + BOWIE_PROTO_FRAME_HEADER_LEN,
                     data, sizeof(data));
}
END_TEST

START_TEST(test_unwrap_null_buf)
{
    bowie_span_t out_msg;

    ck_assert_int_eq(
        bowie_proto_frame_unwrap(NULL, 16u, &out_msg),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_unwrap_null_out)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));

    ck_assert_int_eq(
        bowie_proto_frame_unwrap(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_unwrap_ok)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    buf[3] = 4u;
    buf[4] = 0x11u;
    buf[5] = 0x22u;
    buf[6] = 0x33u;
    buf[7] = 0x44u;

    bowie_span_t msg;

    ck_assert_int_eq(
        bowie_proto_frame_unwrap(buf, 8u, &msg),
        BOWIE_OK);
    ck_assert_uint_eq(msg.len, 4u);
    ck_assert_ptr_eq(msg.data, buf + BOWIE_PROTO_FRAME_HEADER_LEN);
    ck_assert_uint_eq(msg.data[0], 0x11u);
    ck_assert_uint_eq(msg.data[3], 0x44u);
}
END_TEST

START_TEST(test_wrap_unwrap_round_trip)
{
    const uint8_t data[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    };

    bowie_span_t in;
    in.data = data;
    in.len  = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_wrap(in, buf, sizeof(buf), &out_len),
        BOWIE_OK);

    bowie_span_t out;
    ck_assert_int_eq(
        bowie_proto_frame_unwrap(buf, out_len, &out),
        BOWIE_OK);

    ck_assert_uint_eq(out.len, in.len);
    ck_assert_mem_eq(out.data, in.data, in.len);
}
END_TEST

/*
 * ============================================================================
 * STREAM SIZE
 * ============================================================================
 */

START_TEST(test_stream_size_null_buf)
{
    size_t out_total = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_stream_size(NULL, 16u, &out_total),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_stream_size_null_out)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));

    ck_assert_int_eq(
        bowie_proto_frame_stream_size(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_stream_size_too_small)
{
    uint8_t buf[2];
    memset(buf, 0, sizeof(buf));
    size_t  out_total = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_stream_size(buf, sizeof(buf), &out_total),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_stream_size_too_large)
{
    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    uint32_t too_big = BOWIE_PROTO_MAX_FRAME + 1u;
    buf[0] = (uint8_t)((too_big >> 24) & 0xFFu);
    buf[1] = (uint8_t)((too_big >> 16) & 0xFFu);
    buf[2] = (uint8_t)((too_big >> 8) & 0xFFu);
    buf[3] = (uint8_t)(too_big & 0xFFu);

    size_t out_total = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_stream_size(buf, sizeof(buf), &out_total),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_stream_size_ok)
{
    uint8_t buf[BOWIE_PROTO_FRAME_HEADER_LEN];
    buf[0] = 0x00u;
    buf[1] = 0x00u;
    buf[2] = 0x00u;
    buf[3] = 0x10u;  /* message length = 16 */

    size_t out_total = 0u;

    ck_assert_int_eq(
        bowie_proto_frame_stream_size(buf, sizeof(buf), &out_total),
        BOWIE_OK);
    ck_assert_uint_eq(out_total,
                      BOWIE_PROTO_FRAME_HEADER_LEN + 16u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *framing_suite(void)
{
    Suite *s = suite_create("ProtoFraming");

    TCase *tc_henc = tcase_create("HeaderEncode");
    tcase_add_test(tc_henc, test_hdr_encode_null_hdr);
    tcase_add_test(tc_henc, test_hdr_encode_null_buf);
    tcase_add_test(tc_henc, test_hdr_encode_too_small);
    tcase_add_test(tc_henc, test_hdr_encode_too_large);
    tcase_add_test(tc_henc, test_hdr_encode_ok);
    suite_add_tcase(s, tc_henc);

    TCase *tc_hdec = tcase_create("HeaderDecode");
    tcase_add_test(tc_hdec, test_hdr_decode_null_buf);
    tcase_add_test(tc_hdec, test_hdr_decode_null_hdr);
    tcase_add_test(tc_hdec, test_hdr_decode_too_small);
    tcase_add_test(tc_hdec, test_hdr_decode_too_large);
    tcase_add_test(tc_hdec, test_hdr_decode_ok);
    tcase_add_test(tc_hdec, test_hdr_round_trip);
    suite_add_tcase(s, tc_hdec);

    TCase *tc_fenc = tcase_create("FrameEncode");
    tcase_add_test(tc_fenc, test_frame_encode_null_frame);
    tcase_add_test(tc_fenc, test_frame_encode_null_buf);
    tcase_add_test(tc_fenc, test_frame_encode_null_out);
    tcase_add_test(tc_fenc, test_frame_encode_too_small);
    tcase_add_test(tc_fenc, test_frame_encode_empty);
    tcase_add_test(tc_fenc, test_frame_encode_with_data);
    suite_add_tcase(s, tc_fenc);

    TCase *tc_fdec = tcase_create("FrameDecode");
    tcase_add_test(tc_fdec, test_frame_decode_null_buf);
    tcase_add_test(tc_fdec, test_frame_decode_null_frame);
    tcase_add_test(tc_fdec, test_frame_decode_too_small_for_header);
    tcase_add_test(tc_fdec, test_frame_decode_message_truncated);
    tcase_add_test(tc_fdec, test_frame_decode_ok);
    suite_add_tcase(s, tc_fdec);

    TCase *tc_rt = tcase_create("RoundTrip");
    tcase_add_test(tc_rt, test_frame_round_trip_empty);
    tcase_add_test(tc_rt, test_frame_round_trip_with_data);
    suite_add_tcase(s, tc_rt);

    TCase *tc_wrap = tcase_create("Wrap");
    tcase_add_test(tc_wrap, test_wrap_null_buf);
    tcase_add_test(tc_wrap, test_wrap_null_out);
    tcase_add_test(tc_wrap, test_wrap_ok);
    tcase_add_test(tc_wrap, test_unwrap_null_buf);
    tcase_add_test(tc_wrap, test_unwrap_null_out);
    tcase_add_test(tc_wrap, test_unwrap_ok);
    tcase_add_test(tc_wrap, test_wrap_unwrap_round_trip);
    suite_add_tcase(s, tc_wrap);

    TCase *tc_stream = tcase_create("StreamSize");
    tcase_add_test(tc_stream, test_stream_size_null_buf);
    tcase_add_test(tc_stream, test_stream_size_null_out);
    tcase_add_test(tc_stream, test_stream_size_too_small);
    tcase_add_test(tc_stream, test_stream_size_too_large);
    tcase_add_test(tc_stream, test_stream_size_ok);
    suite_add_tcase(s, tc_stream);

    return s;
}

int main(void)
{
    Suite *s = framing_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
