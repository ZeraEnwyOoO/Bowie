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
 * BOWIE — PROTOCOL MESSAGE TESTS
 * ============================================================================
 *
 * Unit tests for src/proto/message.c.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "bowie/err.h"                error codes
 *   "proto/message.h"            the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "proto/message.h"

/*
 * ============================================================================
 * NAME HELPERS
 * ============================================================================
 */

START_TEST(test_type_name_hello)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_HELLO),
        "hello");
}
END_TEST

START_TEST(test_type_name_hello_ack)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_HELLO_ACK),
        "hello_ack");
}
END_TEST

START_TEST(test_type_name_session_open)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_SESSION_OPEN),
        "session_open");
}
END_TEST

START_TEST(test_type_name_signal_offer)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_SIGNAL_OFFER),
        "signal_offer");
}
END_TEST

START_TEST(test_type_name_signal_answer)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_SIGNAL_ANSWER),
        "signal_answer");
}
END_TEST

START_TEST(test_type_name_signal_candidate)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_SIGNAL_CANDIDATE),
        "signal_candidate");
}
END_TEST

START_TEST(test_type_name_data)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_DATA),
        "data");
}
END_TEST

START_TEST(test_type_name_ping)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_PING),
        "ping");
}
END_TEST

START_TEST(test_type_name_error)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_ERROR),
        "error");
}
END_TEST

START_TEST(test_type_name_unknown)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name(BOWIE_PROTO_MSG_UNKNOWN),
        "unknown");
}
END_TEST

START_TEST(test_type_name_invalid)
{
    ck_assert_str_eq(
        bowie_proto_msg_type_name((bowie_proto_msg_type_t)999),
        "unknown");
}
END_TEST

/*
 * ============================================================================
 * TYPE VALIDITY
 * ============================================================================
 */

START_TEST(test_type_valid_hello)
{
    ck_assert(bowie_proto_msg_type_is_valid(
        BOWIE_PROTO_MSG_HELLO));
}
END_TEST

START_TEST(test_type_valid_signal_offer)
{
    ck_assert(bowie_proto_msg_type_is_valid(
        BOWIE_PROTO_MSG_SIGNAL_OFFER));
}
END_TEST

START_TEST(test_type_valid_data)
{
    ck_assert(bowie_proto_msg_type_is_valid(
        BOWIE_PROTO_MSG_DATA));
}
END_TEST

START_TEST(test_type_valid_unknown)
{
    ck_assert(!bowie_proto_msg_type_is_valid(
        BOWIE_PROTO_MSG_UNKNOWN));
}
END_TEST

START_TEST(test_type_valid_invalid)
{
    ck_assert(!bowie_proto_msg_type_is_valid(
        (bowie_proto_msg_type_t)999));
}
END_TEST

/*
 * ============================================================================
 * HEADER ENCODE
 * ============================================================================
 */

START_TEST(test_header_encode_null_hdr)
{
    uint8_t buf[16];
    ck_assert_int_eq(
        bowie_proto_header_encode(NULL, buf, sizeof(buf)),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_header_encode_null_buf)
{
    bowie_proto_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    ck_assert_int_eq(
        bowie_proto_header_encode(&hdr, NULL, 16u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_header_encode_too_small)
{
    bowie_proto_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    uint8_t buf[4];

    ck_assert_int_eq(
        bowie_proto_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_header_encode_too_large)
{
    bowie_proto_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.length = BOWIE_PROTO_MAX_PAYLOAD + 1u;

    uint8_t buf[16];

    ck_assert_int_eq(
        bowie_proto_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_header_encode_ok)
{
    bowie_proto_header_t hdr;
    hdr.version = BOWIE_PROTO_VERSION;
    hdr.type    = BOWIE_PROTO_MSG_PING;
    hdr.flags   = 0u;
    hdr.length  = 4u;
    hdr.msg_id  = 0x01020304u;

    uint8_t buf[BOWIE_PROTO_HEADER_LEN];

    ck_assert_int_eq(
        bowie_proto_header_encode(&hdr, buf, sizeof(buf)),
        BOWIE_OK);

    /* Byte order check: big-endian. */
    ck_assert_uint_eq(buf[0], BOWIE_PROTO_VERSION);
    ck_assert_uint_eq(buf[1], BOWIE_PROTO_MSG_PING);
    ck_assert_uint_eq(buf[2], 0x00u);
    ck_assert_uint_eq(buf[3], 0x00u);
    ck_assert_uint_eq(buf[4], 0x00u);
    ck_assert_uint_eq(buf[5], 0x00u);
    ck_assert_uint_eq(buf[6], 0x00u);
    ck_assert_uint_eq(buf[7], 0x04u);
    ck_assert_uint_eq(buf[8],  0x01u);
    ck_assert_uint_eq(buf[9],  0x02u);
    ck_assert_uint_eq(buf[10], 0x03u);
    ck_assert_uint_eq(buf[11], 0x04u);
}
END_TEST

/*
 * ============================================================================
 * HEADER DECODE
 * ============================================================================
 */

START_TEST(test_header_decode_null_buf)
{
    bowie_proto_header_t hdr;
    ck_assert_int_eq(
        bowie_proto_header_decode(NULL, 16u, &hdr),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_header_decode_null_hdr)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_header_decode_too_small)
{
    uint8_t buf[4];
    memset(buf, 0, sizeof(buf));
    bowie_proto_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_header_decode_bad_version)
{
    uint8_t buf[BOWIE_PROTO_HEADER_LEN];
    memset(buf, 0, sizeof(buf));
    buf[0] = 99u;  /* wrong version */

    bowie_proto_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_ERR_NOT_SUPPORTED);
}
END_TEST

START_TEST(test_header_decode_too_large)
{
    uint8_t buf[BOWIE_PROTO_HEADER_LEN];
    memset(buf, 0, sizeof(buf));
    buf[0] = BOWIE_PROTO_VERSION;
    buf[1] = BOWIE_PROTO_MSG_DATA;
    /* length = BOWIE_PROTO_MAX_PAYLOAD + 1 (big-endian) */
    buf[4] = (uint8_t)(((BOWIE_PROTO_MAX_PAYLOAD + 1u) >> 24) & 0xFFu);
    buf[5] = (uint8_t)(((BOWIE_PROTO_MAX_PAYLOAD + 1u) >> 16) & 0xFFu);
    buf[6] = (uint8_t)(((BOWIE_PROTO_MAX_PAYLOAD + 1u) >> 8) & 0xFFu);
    buf[7] = (uint8_t)((BOWIE_PROTO_MAX_PAYLOAD + 1u) & 0xFFu);

    bowie_proto_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_ERR_TOO_LARGE);
}
END_TEST

START_TEST(test_header_decode_ok)
{
    uint8_t buf[BOWIE_PROTO_HEADER_LEN];
    buf[0] = BOWIE_PROTO_VERSION;
    buf[1] = BOWIE_PROTO_MSG_DATA;
    buf[2] = 0x00u;
    buf[3] = 0x00u;
    buf[4] = 0x00u;
    buf[5] = 0x00u;
    buf[6] = 0x00u;
    buf[7] = 0x10u;  /* length = 16 */
    buf[8]  = 0x00u;
    buf[9]  = 0x00u;
    buf[10] = 0x00u;
    buf[11] = 0x42u;

    bowie_proto_header_t hdr;

    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), &hdr),
        BOWIE_OK);
    ck_assert_uint_eq(hdr.version, BOWIE_PROTO_VERSION);
    ck_assert_uint_eq(hdr.type, BOWIE_PROTO_MSG_DATA);
    ck_assert_uint_eq(hdr.flags, 0u);
    ck_assert_uint_eq(hdr.length, 16u);
    ck_assert_uint_eq(hdr.msg_id, 0x42u);
}
END_TEST

/*
 * ============================================================================
 * HEADER ROUND TRIP
 * ============================================================================
 */

START_TEST(test_header_round_trip)
{
    bowie_proto_header_t in;
    in.version = BOWIE_PROTO_VERSION;
    in.type    = BOWIE_PROTO_MSG_SIGNAL_OFFER;
    in.flags   = 0u;
    in.length  = 100u;
    in.msg_id  = 0xDEADBEEFu;

    uint8_t buf[BOWIE_PROTO_HEADER_LEN];
    ck_assert_int_eq(
        bowie_proto_header_encode(&in, buf, sizeof(buf)),
        BOWIE_OK);

    bowie_proto_header_t out;
    ck_assert_int_eq(
        bowie_proto_header_decode(buf, sizeof(buf), &out),
        BOWIE_OK);

    ck_assert_uint_eq(out.version, in.version);
    ck_assert_uint_eq(out.type,    in.type);
    ck_assert_uint_eq(out.flags,   in.flags);
    ck_assert_uint_eq(out.length,  in.length);
    ck_assert_uint_eq(out.msg_id,  in.msg_id);
}
END_TEST

/*
 * ============================================================================
 * MESSAGE ENCODE
 * ============================================================================
 */

START_TEST(test_msg_encode_null_msg)
{
    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(NULL, buf, sizeof(buf), &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_msg_encode_null_buf)
{
    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    size_t out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&msg, NULL, 64u, &out_len),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_msg_encode_null_out)
{
    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    uint8_t buf[64];

    ck_assert_int_eq(
        bowie_proto_msg_encode(&msg, buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_msg_encode_too_small)
{
    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_PING;

    uint8_t buf[4];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&msg, buf, sizeof(buf), &out_len),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_msg_encode_empty_payload)
{
    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_PING;
    msg.header.msg_id  = 0x11223344u;

    uint8_t buf[32];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&msg, buf, sizeof(buf), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len, BOWIE_PROTO_HEADER_LEN);
    ck_assert_uint_eq(buf[0], BOWIE_PROTO_VERSION);
    ck_assert_uint_eq(buf[1], BOWIE_PROTO_MSG_PING);
}
END_TEST

START_TEST(test_msg_encode_with_payload)
{
    const uint8_t data[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_DATA;
    msg.header.msg_id  = 0x42u;
    msg.payload.data   = data;
    msg.payload.len    = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&msg, buf, sizeof(buf), &out_len),
        BOWIE_OK);
    ck_assert_uint_eq(out_len,
                      BOWIE_PROTO_HEADER_LEN + sizeof(data));

    /* Header length field must be set from payload. */
    uint8_t len_be[4];
    memcpy(len_be, buf + 4, 4u);
    uint32_t len = ((uint32_t)len_be[0] << 24)
                 | ((uint32_t)len_be[1] << 16)
                 | ((uint32_t)len_be[2] << 8)
                 | ((uint32_t)len_be[3]);
    ck_assert_uint_eq(len, sizeof(data));

    /* Payload bytes must follow the header. */
    ck_assert_mem_eq(buf + BOWIE_PROTO_HEADER_LEN,
                     data, sizeof(data));
}
END_TEST

/*
 * ============================================================================
 * MESSAGE DECODE
 * ============================================================================
 */

START_TEST(test_msg_decode_null_buf)
{
    bowie_proto_msg_t msg;
    ck_assert_int_eq(
        bowie_proto_msg_decode(NULL, 16u, &msg),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_msg_decode_null_msg)
{
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, sizeof(buf), NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_msg_decode_too_small_for_header)
{
    uint8_t buf[4];
    memset(buf, 0, sizeof(buf));
    bowie_proto_msg_t msg;

    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, sizeof(buf), &msg),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_msg_decode_payload_truncated)
{
    /* Header says 16 bytes of payload, but only 0 provided. */
    uint8_t buf[BOWIE_PROTO_HEADER_LEN];
    memset(buf, 0, sizeof(buf));
    buf[0] = BOWIE_PROTO_VERSION;
    buf[1] = BOWIE_PROTO_MSG_DATA;
    buf[7] = 16u;  /* length = 16 */

    bowie_proto_msg_t msg;

    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, sizeof(buf), &msg),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

START_TEST(test_msg_decode_ok)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = BOWIE_PROTO_VERSION;
    buf[1] = BOWIE_PROTO_MSG_DATA;
    buf[7] = 4u;  /* length = 4 */
    buf[12] = 0xAAu;
    buf[13] = 0xBBu;
    buf[14] = 0xCCu;
    buf[15] = 0xDDu;

    bowie_proto_msg_t msg;

    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, 16u, &msg),
        BOWIE_OK);
    ck_assert_uint_eq(msg.header.version, BOWIE_PROTO_VERSION);
    ck_assert_uint_eq(msg.header.type, BOWIE_PROTO_MSG_DATA);
    ck_assert_uint_eq(msg.header.length, 4u);
    ck_assert_uint_eq(msg.payload.len, 4u);
    ck_assert_ptr_eq(msg.payload.data, buf + BOWIE_PROTO_HEADER_LEN);
    ck_assert_uint_eq(msg.payload.data[0], 0xAAu);
    ck_assert_uint_eq(msg.payload.data[3], 0xDDu);
}
END_TEST

/*
 * ============================================================================
 * MESSAGE ROUND TRIP
 * ============================================================================
 */

START_TEST(test_msg_round_trip_empty)
{
    bowie_proto_msg_t in;
    memset(&in, 0, sizeof(in));
    in.header.version = BOWIE_PROTO_VERSION;
    in.header.type    = BOWIE_PROTO_MSG_PING;
    in.header.msg_id  = 0x12345678u;

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&in, buf, sizeof(buf), &out_len),
        BOWIE_OK);

    bowie_proto_msg_t out;
    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, out_len, &out),
        BOWIE_OK);

    ck_assert_uint_eq(out.header.version, in.header.version);
    ck_assert_uint_eq(out.header.type,    in.header.type);
    ck_assert_uint_eq(out.header.msg_id,  in.header.msg_id);
    ck_assert_uint_eq(out.payload.len, 0u);
}
END_TEST

START_TEST(test_msg_round_trip_with_payload)
{
    const uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    bowie_proto_msg_t in;
    memset(&in, 0, sizeof(in));
    in.header.version = BOWIE_PROTO_VERSION;
    in.header.type    = BOWIE_PROTO_MSG_SIGNAL_OFFER;
    in.header.msg_id  = 0xCAFEBABEu;
    in.payload.data   = data;
    in.payload.len    = sizeof(data);

    uint8_t buf[64];
    size_t  out_len = 0u;

    ck_assert_int_eq(
        bowie_proto_msg_encode(&in, buf, sizeof(buf), &out_len),
        BOWIE_OK);

    bowie_proto_msg_t out;
    ck_assert_int_eq(
        bowie_proto_msg_decode(buf, out_len, &out),
        BOWIE_OK);

    ck_assert_uint_eq(out.header.type, in.header.type);
    ck_assert_uint_eq(out.header.msg_id, in.header.msg_id);
    ck_assert_uint_eq(out.payload.len, sizeof(data));
    ck_assert_mem_eq(out.payload.data, data, sizeof(data));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *message_suite(void)
{
    Suite *s = suite_create("ProtoMessage");

    TCase *tc_names = tcase_create("Names");
    tcase_add_test(tc_names, test_type_name_hello);
    tcase_add_test(tc_names, test_type_name_hello_ack);
    tcase_add_test(tc_names, test_type_name_session_open);
    tcase_add_test(tc_names, test_type_name_signal_offer);
    tcase_add_test(tc_names, test_type_name_signal_answer);
    tcase_add_test(tc_names, test_type_name_signal_candidate);
    tcase_add_test(tc_names, test_type_name_data);
    tcase_add_test(tc_names, test_type_name_ping);
    tcase_add_test(tc_names, test_type_name_error);
    tcase_add_test(tc_names, test_type_name_unknown);
    tcase_add_test(tc_names, test_type_name_invalid);
    suite_add_tcase(s, tc_names);

    TCase *tc_valid = tcase_create("Valid");
    tcase_add_test(tc_valid, test_type_valid_hello);
    tcase_add_test(tc_valid, test_type_valid_signal_offer);
    tcase_add_test(tc_valid, test_type_valid_data);
    tcase_add_test(tc_valid, test_type_valid_unknown);
    tcase_add_test(tc_valid, test_type_valid_invalid);
    suite_add_tcase(s, tc_valid);

    TCase *tc_henc = tcase_create("HeaderEncode");
    tcase_add_test(tc_henc, test_header_encode_null_hdr);
    tcase_add_test(tc_henc, test_header_encode_null_buf);
    tcase_add_test(tc_henc, test_header_encode_too_small);
    tcase_add_test(tc_henc, test_header_encode_too_large);
    tcase_add_test(tc_henc, test_header_encode_ok);
    suite_add_tcase(s, tc_henc);

    TCase *tc_hdec = tcase_create("HeaderDecode");
    tcase_add_test(tc_hdec, test_header_decode_null_buf);
    tcase_add_test(tc_hdec, test_header_decode_null_hdr);
    tcase_add_test(tc_hdec, test_header_decode_too_small);
    tcase_add_test(tc_hdec, test_header_decode_bad_version);
    tcase_add_test(tc_hdec, test_header_decode_too_large);
    tcase_add_test(tc_hdec, test_header_decode_ok);
    tcase_add_test(tc_hdec, test_header_round_trip);
    suite_add_tcase(s, tc_hdec);

    TCase *tc_menc = tcase_create("MsgEncode");
    tcase_add_test(tc_menc, test_msg_encode_null_msg);
    tcase_add_test(tc_menc, test_msg_encode_null_buf);
    tcase_add_test(tc_menc, test_msg_encode_null_out);
    tcase_add_test(tc_menc, test_msg_encode_too_small);
    tcase_add_test(tc_menc, test_msg_encode_empty_payload);
    tcase_add_test(tc_menc, test_msg_encode_with_payload);
    suite_add_tcase(s, tc_menc);

    TCase *tc_mdec = tcase_create("MsgDecode");
    tcase_add_test(tc_mdec, test_msg_decode_null_buf);
    tcase_add_test(tc_mdec, test_msg_decode_null_msg);
    tcase_add_test(tc_mdec, test_msg_decode_too_small_for_header);
    tcase_add_test(tc_mdec, test_msg_decode_payload_truncated);
    tcase_add_test(tc_mdec, test_msg_decode_ok);
    suite_add_tcase(s, tc_mdec);

    TCase *tc_rt = tcase_create("RoundTrip");
    tcase_add_test(tc_rt, test_msg_round_trip_empty);
    tcase_add_test(tc_rt, test_msg_round_trip_with_payload);
    suite_add_tcase(s, tc_rt);

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
