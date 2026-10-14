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
 * BOWIE — PROTOCOL HANDSHAKE TESTS
 * ============================================================================
 *
 * Unit tests for src/proto/handshake.c.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset, memcpy
 *   "bowie/err.h"                error codes
 *   "proto/handshake.h"          the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "proto/handshake.h"

/*
 * ============================================================================
 * TEST CALLBACKS
 * ============================================================================
 *
 * The handshake does not know how to sign or verify. The tests
 * provide simple callbacks that do a deterministic transform.
 *
 * The sign callback writes a byte pattern derived from the
 * message. The verify callback recomputes the same pattern and
 * compares.
 *
 * The callbacks are not cryptographic. They test the state
 * machine, not the crypto.
 */

static uint8_t xor_byte(const uint8_t *msg, size_t len)
{
    uint8_t acc = 0u;
    for (size_t i = 0u; i < len; i++) {
        acc ^= msg[i];
    }
    return acc;
}

static bowie_error_t test_sign(
    void *ctx,
    const uint8_t *msg, size_t msg_len,
    uint8_t *sig)
{
    (void)ctx;
    if (msg == NULL || sig == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    uint8_t x = xor_byte(msg, msg_len);
    for (size_t i = 0u; i < BOWIE_PROTO_SIG_LEN; i++) {
        sig[i] = (uint8_t)(x + i);
    }
    return BOWIE_OK;
}

static int test_verify(
    void *ctx,
    const bowie_public_id_t *id,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig)
{
    (void)ctx;
    (void)id;
    if (msg == NULL || sig == NULL) {
        return 0;
    }
    uint8_t x = xor_byte(msg, msg_len);
    for (size_t i = 0u; i < BOWIE_PROTO_SIG_LEN; i++) {
        if (sig[i] != (uint8_t)(x + i)) {
            return 0;
        }
    }
    return 1;
}

static bowie_error_t failing_sign(
    void *ctx,
    const uint8_t *msg, size_t msg_len,
    uint8_t *sig)
{
    (void)ctx; (void)msg; (void)msg_len; (void)sig;
    return BOWIE_ERR_CRYPTO;
}

static void make_id(bowie_public_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_PUBLIC_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

/*
 * ============================================================================
 * INIT
 * ============================================================================
 */

START_TEST(test_init_null_hs)
{
    bowie_public_id_t id;
    make_id(&id, 1u);

    ck_assert_int_eq(
        bowie_proto_handshake_init(NULL,
                                    BOWIE_PROTO_HS_INITIATOR,
                                    &id, test_sign, test_verify,
                                    NULL, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_id)
{
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    BOWIE_PROTO_HS_INITIATOR,
                                    NULL, test_sign, test_verify,
                                    NULL, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_sign)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    BOWIE_PROTO_HS_INITIATOR,
                                    &id, NULL, test_verify,
                                    NULL, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_verify)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    BOWIE_PROTO_HS_INITIATOR,
                                    &id, test_sign, NULL,
                                    NULL, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_bad_role)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    (bowie_proto_hs_role_t)99,
                                    &id, test_sign, test_verify,
                                    NULL, 0u, 0u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_init_ok_initiator)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    BOWIE_PROTO_HS_INITIATOR,
                                    &id, test_sign, test_verify,
                                    NULL, 0u, 100u),
        BOWIE_OK);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_int_eq(hs.role, BOWIE_PROTO_HS_INITIATOR);
    ck_assert_uint_eq(hs.timeout_ms,
                      BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS);
    ck_assert_uint_eq(hs.started_at_ms, 100u);
}
END_TEST

START_TEST(test_init_ok_responder)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs,
                                    BOWIE_PROTO_HS_RESPONDER,
                                    &id, test_sign, test_verify,
                                    NULL, 5000u, 100u),
        BOWIE_OK);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_int_eq(hs.role, BOWIE_PROTO_HS_RESPONDER);
    ck_assert_uint_eq(hs.timeout_ms, 5000u);
}
END_TEST

/*
 * ============================================================================
 * CLEAR
 * ============================================================================
 */

START_TEST(test_clear_null)
{
    bowie_proto_handshake_clear(NULL);
}
END_TEST

START_TEST(test_clear_preserves_callbacks)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;

    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 1000u, 100u);

    bowie_proto_handshake_clear(&hs);

    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_uint_eq(hs.timeout_ms, 1000u);
    ck_assert(bowie_public_id_equal(&hs.local_id, &id));

    /*
     * The callbacks are still usable. A second output call
     * succeeds, which is only possible if the sign callback
     * is still set.
     */
    bowie_proto_msg_t msg;
    int has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
}
END_TEST

/*
 * ============================================================================
 * OUTPUT
 * ============================================================================
 */

START_TEST(test_output_null_hs)
{
    bowie_proto_msg_t msg;
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(NULL, &msg, &has),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_null_msg)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, NULL, &has),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_null_has)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);
    bowie_proto_msg_t msg;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_initiator_produces_hello)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 100u);

    bowie_proto_msg_t msg;
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(msg.header.type, BOWIE_PROTO_MSG_HELLO);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_SENT_HELLO);
}
END_TEST

START_TEST(test_output_initiator_second_call_no_message)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 100u);

    bowie_proto_msg_t msg;
    int has = 0;
    (void)bowie_proto_handshake_output(&hs, &msg, &has);

    has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_ERR_STATE);
}
END_TEST

START_TEST(test_output_responder_idle_no_message)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 100u);

    bowie_proto_msg_t msg;
    int has = 99;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
}
END_TEST

START_TEST(test_output_responder_after_hello_produces_ack)
{
    bowie_public_id_t id_a;
    bowie_public_id_t id_b;
    make_id(&id_a, 1u);
    make_id(&id_b, 50u);

    bowie_proto_handshake_t hs_a;
    bowie_proto_handshake_t hs_b;
    (void)bowie_proto_handshake_init(&hs_a,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id_a, test_sign, test_verify,
                                      NULL, 0u, 100u);
    (void)bowie_proto_handshake_init(&hs_b,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id_b, test_sign, test_verify,
                                      NULL, 0u, 100u);

    /* A produces HELLO. */
    bowie_proto_msg_t hello;
    int has = 0;
    (void)bowie_proto_handshake_output(&hs_a, &hello, &has);
    ck_assert_int_eq(has, 1);

    /* B consumes HELLO. */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_b, &hello, 200u),
        BOWIE_OK);

    /* B produces HELLO_ACK. */
    bowie_proto_msg_t ack;
    has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs_b, &ack, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(ack.header.type, BOWIE_PROTO_MSG_HELLO_ACK);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_SENT_ACK);
}
END_TEST

/*
 * ============================================================================
 * INPUT — ERRORS
 * ============================================================================
 */

START_TEST(test_input_null_hs)
{
    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    ck_assert_int_eq(
        bowie_proto_handshake_input(NULL, &msg, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_input_null_msg)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, NULL, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_input_timeout)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id, test_sign, test_verify,
                                      NULL, 1000u, 100u);

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 100u + 1000u + 1u),
        BOWIE_ERR_TIMEOUT);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_FAILED);
}
END_TEST

/*
 * ============================================================================
 * FULL HANDSHAKE
 * ============================================================================
 */

START_TEST(test_full_handshake)
{
    bowie_public_id_t id_a;
    bowie_public_id_t id_b;
    make_id(&id_a, 1u);
    make_id(&id_b, 50u);

    bowie_proto_handshake_t hs_a;
    bowie_proto_handshake_t hs_b;
    (void)bowie_proto_handshake_init(&hs_a,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id_a, test_sign, test_verify,
                                      NULL, 0u, 100u);
    (void)bowie_proto_handshake_init(&hs_b,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id_b, test_sign, test_verify,
                                      NULL, 0u, 100u);

    /* A produces HELLO. */
    bowie_proto_msg_t hello;
    int has = 0;
    (void)bowie_proto_handshake_output(&hs_a, &hello, &has);
    ck_assert_int_eq(has, 1);

    /* B consumes HELLO. */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_b, &hello, 200u),
        BOWIE_OK);

    /* B produces HELLO_ACK. */
    bowie_proto_msg_t ack;
    has = 0;
    (void)bowie_proto_handshake_output(&hs_b, &ack, &has);
    ck_assert_int_eq(has, 1);

    /* A consumes HELLO_ACK. */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_a, &ack, 200u),
        BOWIE_OK);
    ck_assert(bowie_proto_handshake_is_done(&hs_a));

    /*
     * The responder does not reach DONE after sending
     * HELLO_ACK. It has no way to know whether the initiator
     * received the message. The responder stays in SENT_ACK
     * until the first session message arrives.
     */
    ck_assert(!bowie_proto_handshake_is_done(&hs_b));
    ck_assert_int_eq(bowie_proto_handshake_state(&hs_b),
                     BOWIE_PROTO_HS_SENT_ACK);

    /* Both sides agree on the remote IDs. */
    bowie_public_id_t remote_a;
    bowie_public_id_t remote_b;
    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_a, &remote_a),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_b, &remote_b),
        BOWIE_OK);
    ck_assert(bowie_public_id_equal(&remote_a, &id_b));
    ck_assert(bowie_public_id_equal(&remote_b, &id_a));
}
END_TEST

START_TEST(test_full_handshake_bad_signature)
{
    bowie_public_id_t id_a;
    bowie_public_id_t id_b;
    make_id(&id_a, 1u);
    make_id(&id_b, 50u);

    bowie_proto_handshake_t hs_a;
    bowie_proto_handshake_t hs_b;
    (void)bowie_proto_handshake_init(&hs_a,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id_a, test_sign, test_verify,
                                      NULL, 0u, 100u);
    (void)bowie_proto_handshake_init(&hs_b,
                                      BOWIE_PROTO_HS_RESPONDER,
                                      &id_b, test_sign, test_verify,
                                      NULL, 0u, 100u);

    bowie_proto_msg_t hello;
    int has = 0;
    (void)bowie_proto_handshake_output(&hs_a, &hello, &has);

    /* Corrupt the signature. */
    ((uint8_t *)hello.payload.data)[BOWIE_PUBLIC_ID_LEN +
                                    BOWIE_PROTO_NONCE_LEN] ^= 0xFFu;

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_b, &hello, 200u),
        BOWIE_ERR_SIGN_INVALID);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_FAILED);
}
END_TEST

START_TEST(test_sign_callback_failure)
{
    bowie_public_id_t id;
    make_id(&id, 1u);

    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, failing_sign, test_verify,
                                      NULL, 0u, 100u);

    bowie_proto_msg_t msg;
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_ERR_CRYPTO);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_state_null)
{
    ck_assert_int_eq(bowie_proto_handshake_state(NULL),
                     BOWIE_PROTO_HS_FAILED);
}
END_TEST

START_TEST(test_remote_id_null_hs)
{
    bowie_public_id_t out;
    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(NULL, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remote_id_null_out)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remote_id_not_found)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);

    bowie_public_id_t out;
    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs, &out),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_is_done_null)
{
    ck_assert(!bowie_proto_handshake_is_done(NULL));
}
END_TEST

START_TEST(test_is_failed_null)
{
    ck_assert(bowie_proto_handshake_is_failed(NULL));
}
END_TEST

START_TEST(test_is_failed_false)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 0u);

    ck_assert(!bowie_proto_handshake_is_failed(&hs));
}
END_TEST

START_TEST(test_timed_out_null)
{
    ck_assert(!bowie_proto_handshake_timed_out(NULL, 1000u));
}
END_TEST

START_TEST(test_timed_out_zero_timeout)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 0u, 100u);
    /* timeout_ms is 0 -> default is used (10000). */
    ck_assert(!bowie_proto_handshake_timed_out(&hs, 100u + 500u));
}
END_TEST

START_TEST(test_timed_out_yes)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 1000u, 100u);

    ck_assert(bowie_proto_handshake_timed_out(&hs, 100u + 1000u));
}
END_TEST

START_TEST(test_timed_out_backward_clock)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    bowie_proto_handshake_t hs;
    (void)bowie_proto_handshake_init(&hs,
                                      BOWIE_PROTO_HS_INITIATOR,
                                      &id, test_sign, test_verify,
                                      NULL, 1000u, 5000u);

    ck_assert(!bowie_proto_handshake_timed_out(&hs, 100u));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *handshake_suite(void)
{
    Suite *s = suite_create("ProtoHandshake");

    TCase *tc_init = tcase_create("Init");
    tcase_add_test(tc_init, test_init_null_hs);
    tcase_add_test(tc_init, test_init_null_id);
    tcase_add_test(tc_init, test_init_null_sign);
    tcase_add_test(tc_init, test_init_null_verify);
    tcase_add_test(tc_init, test_init_bad_role);
    tcase_add_test(tc_init, test_init_ok_initiator);
    tcase_add_test(tc_init, test_init_ok_responder);
    suite_add_tcase(s, tc_init);

    TCase *tc_clear = tcase_create("Clear");
    tcase_add_test(tc_clear, test_clear_null);
    tcase_add_test(tc_clear, test_clear_preserves_callbacks);
    suite_add_tcase(s, tc_clear);

    TCase *tc_out = tcase_create("Output");
    tcase_add_test(tc_out, test_output_null_hs);
    tcase_add_test(tc_out, test_output_null_msg);
    tcase_add_test(tc_out, test_output_null_has);
    tcase_add_test(tc_out, test_output_initiator_produces_hello);
    tcase_add_test(tc_out,
                   test_output_initiator_second_call_no_message);
    tcase_add_test(tc_out, test_output_responder_idle_no_message);
    tcase_add_test(tc_out,
                   test_output_responder_after_hello_produces_ack);
    suite_add_tcase(s, tc_out);

    TCase *tc_in_err = tcase_create("InputErrors");
    tcase_add_test(tc_in_err, test_input_null_hs);
    tcase_add_test(tc_in_err, test_input_null_msg);
    tcase_add_test(tc_in_err, test_input_timeout);
    suite_add_tcase(s, tc_in_err);

    TCase *tc_full = tcase_create("FullHandshake");
    tcase_add_test(tc_full, test_full_handshake);
    tcase_add_test(tc_full, test_full_handshake_bad_signature);
    tcase_add_test(tc_full, test_sign_callback_failure);
    suite_add_tcase(s, tc_full);

    TCase *tc_q = tcase_create("Query");
    tcase_add_test(tc_q, test_state_null);
    tcase_add_test(tc_q, test_remote_id_null_hs);
    tcase_add_test(tc_q, test_remote_id_null_out);
    tcase_add_test(tc_q, test_remote_id_not_found);
    tcase_add_test(tc_q, test_is_done_null);
    tcase_add_test(tc_q, test_is_failed_null);
    tcase_add_test(tc_q, test_is_failed_false);
    tcase_add_test(tc_q, test_timed_out_null);
    tcase_add_test(tc_q, test_timed_out_zero_timeout);
    tcase_add_test(tc_q, test_timed_out_yes);
    tcase_add_test(tc_q, test_timed_out_backward_clock);
    suite_add_tcase(s, tc_q);

    return s;
}

int main(void)
{
    Suite *s = handshake_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
