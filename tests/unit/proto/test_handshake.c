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
 * The tests use a fake sign/verify pair. The sign callback
 * writes a byte pattern derived from the message; the verify
 * callback checks the pattern. This is not a real signature;
 * it is enough to test the state machine and the payload
 * layout. A real signature is tested in the crypto layer.
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
#include "proto/message.h"
#include "proto/handshake.h"

/*
 * ============================================================================
 * FAKE SIGN / VERIFY
 * ============================================================================
 *
 * The fake signer writes a deterministic byte pattern derived
 * from the message and the signing ID. The fake verifier
 * recomputes the pattern and compares it to the signature.
 *
 * The pattern is the message bytes XORed with a key derived
 * from the first byte of the ID. This is not secure; it is a
 * deterministic mapping that a test can predict.
 */

typedef struct fake_ctx {
    bowie_public_id_t signer_id;
    int               fail_sign;
    int               fail_verify;
} fake_ctx_t;

static uint8_t pattern_key(const bowie_public_id_t *id)
{
    return (uint8_t)(id->bytes[0] ^ 0x5Au);
}

static bowie_error_t fake_sign(
    void *ctx,
    const uint8_t *msg, size_t msg_len,
    uint8_t *sig)
{
    fake_ctx_t *fc = (fake_ctx_t *)ctx;

    if (fc != NULL && fc->fail_sign) {
        return BOWIE_ERR_CRYPTO;
    }

    uint8_t key = pattern_key(&fc->signer_id);
    for (size_t i = 0u; i < BOWIE_PROTO_SIG_LEN; i++) {
        uint8_t m = (msg_len > 0u) ? msg[i % msg_len] : 0u;
        sig[i] = (uint8_t)(m ^ key ^ (uint8_t)i);
    }
    return BOWIE_OK;
}

static int fake_verify(
    void *ctx,
    const bowie_public_id_t *id,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig)
{
    fake_ctx_t *fc = (fake_ctx_t *)ctx;

    if (fc != NULL && fc->fail_verify) {
        return 0;
    }

    uint8_t key = pattern_key(id);
    for (size_t i = 0u; i < BOWIE_PROTO_SIG_LEN; i++) {
        uint8_t m = (msg_len > 0u) ? msg[i % msg_len] : 0u;
        uint8_t expected = (uint8_t)(m ^ key ^ (uint8_t)i);
        if (sig[i] != expected) {
            return 0;
        }
    }
    return 1;
}

static void make_id(bowie_public_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_PUBLIC_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_nonce(uint8_t *nonce, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_PROTO_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)(seed + i);
    }
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_init_null_hs)
{
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(NULL, BOWIE_PROTO_HS_INITIATOR,
                                   &id, fake_sign, fake_verify,
                                   &fc, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_id)
{
    bowie_proto_handshake_t hs;
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs, BOWIE_PROTO_HS_INITIATOR,
                                   NULL, fake_sign, fake_verify,
                                   &fc, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_sign)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs, BOWIE_PROTO_HS_INITIATOR,
                                   &id, NULL, fake_verify,
                                   &fc, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_verify)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs, BOWIE_PROTO_HS_INITIATOR,
                                   &id, fake_sign, NULL,
                                   &fc, 0u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_bad_role)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs, (bowie_proto_hs_role_t)99,
                                   &id, fake_sign, fake_verify,
                                   &fc, 0u, 0u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_init_ok)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    ck_assert_int_eq(
        bowie_proto_handshake_init(&hs, BOWIE_PROTO_HS_INITIATOR,
                                   &id, fake_sign, fake_verify,
                                   &fc, 0u, 1000u),
        BOWIE_OK);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_int_eq(hs.role, BOWIE_PROTO_HS_INITIATOR);
    ck_assert_uint_eq(hs.timeout_ms,
                      BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS);
    ck_assert_uint_eq(hs.started_at_ms, 1000u);
}
END_TEST

START_TEST(test_clear_preserves_config)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 1u);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 5000u, 1000u);

    bowie_proto_handshake_clear(&hs);

    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_uint_eq(hs.timeout_ms, 5000u);
    ck_assert_ptr_eq((void *)hs.sign, (void *)fake_sign);
    ck_assert_ptr_eq((void *)hs.verify, (void *)fake_verify);
    ck_assert(bowie_public_id_equal(&hs.local_id, &id));
}
END_TEST

START_TEST(test_clear_null)
{
    bowie_proto_handshake_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * OUTPUT — INITIATOR
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
    bowie_proto_handshake_t hs;
    memset(&hs, 0, sizeof(hs));
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, NULL, &has),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_null_has)
{
    bowie_proto_handshake_t hs;
    memset(&hs, 0, sizeof(hs));
    bowie_proto_msg_t msg;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_initiator_first_output_is_hello)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);
    make_nonce(hs.local_nonce, 0x10u);

    bowie_proto_msg_t msg;
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(msg.header.type, BOWIE_PROTO_MSG_HELLO);
    ck_assert_uint_eq(msg.payload.len,
                      BOWIE_PUBLIC_ID_LEN +
                      BOWIE_PROTO_NONCE_LEN +
                      BOWIE_PROTO_SIG_LEN);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_SENT_HELLO);
}
END_TEST

START_TEST(test_initiator_second_output_no_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);
    make_nonce(hs.local_nonce, 0x10u);

    bowie_proto_msg_t msg;
    int has = 0;

    (void)bowie_proto_handshake_output(&hs, &msg, &has);
    ck_assert_int_eq(has, 1);

    has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
}
END_TEST

/*
 * ============================================================================
 * OUTPUT — RESPONDER
 * ============================================================================
 */

START_TEST(test_responder_first_output_no_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xBBu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_RESPONDER,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

    bowie_proto_msg_t msg;
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
}
END_TEST

/*
 * ============================================================================
 * INPUT — INITIATOR
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
    bowie_proto_handshake_t hs;
    memset(&hs, 0, sizeof(hs));

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, NULL, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_input_wrong_type_initiator)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.type = BOWIE_PROTO_MSG_HELLO;  /* wrong: initiator */

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_STATE);
}
END_TEST

/*
 * ============================================================================
 * TIMEOUT
 * ============================================================================
 */

START_TEST(test_timed_out_null)
{
    ck_assert(!bowie_proto_handshake_timed_out(NULL, 1000u));
}
END_TEST

START_TEST(test_timed_out_not_yet)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 5000u, 1000u);

    ck_assert(!bowie_proto_handshake_timed_out(&hs, 4000u));
}
END_TEST

START_TEST(test_timed_out_yes)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 5000u, 1000u);

    ck_assert(bowie_proto_handshake_timed_out(&hs, 7000u));
}
END_TEST

START_TEST(test_input_after_timeout_fails)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 100u, 0u);

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 1000u),
        BOWIE_ERR_TIMEOUT);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_FAILED);
}
END_TEST

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

START_TEST(test_state_null)
{
    ck_assert_int_eq(
        bowie_proto_handshake_state(NULL),
        BOWIE_PROTO_HS_FAILED);
}
END_TEST

START_TEST(test_state_ok)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

    ck_assert_int_eq(
        bowie_proto_handshake_state(&hs),
        BOWIE_PROTO_HS_IDLE);
}
END_TEST

START_TEST(test_remote_id_null)
{
    bowie_public_id_t out;

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(NULL, &out),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remote_id_not_known)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

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

START_TEST(test_is_done_false)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

    ck_assert(!bowie_proto_handshake_is_done(&hs));
}
END_TEST

START_TEST(test_is_failed_null)
{
    ck_assert(bowie_proto_handshake_is_failed(NULL));
}
END_TEST

START_TEST(test_is_failed_false)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0xAAu);
    fake_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.signer_id = id;

    (void)bowie_proto_handshake_init(&hs,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id, fake_sign, fake_verify,
                                     &fc, 0u, 0u);

    ck_assert(!bowie_proto_handshake_is_failed(&hs));
}
END_TEST

/*
 * ============================================================================
 * FULL HANDSHAKE
 * ============================================================================
 */

START_TEST(test_full_handshake_success)
{
    /*
     * The initiator and the responder each get their own
     * handshake and their own fake context. The contexts
     * share the signer_id fields through the verify calls.
     */
    bowie_public_id_t id_a;
    bowie_public_id_t id_b;
    make_id(&id_a, 0x10u);
    make_id(&id_b, 0x20u);

    fake_ctx_t ctx_a;
    fake_ctx_t ctx_b;
    memset(&ctx_a, 0, sizeof(ctx_a));
    memset(&ctx_b, 0, sizeof(ctx_b));
    ctx_a.signer_id = id_a;
    ctx_b.signer_id = id_b;

    bowie_proto_handshake_t hs_a;
    bowie_proto_handshake_t hs_b;

    (void)bowie_proto_handshake_init(&hs_a,
                                     BOWIE_PROTO_HS_INITIATOR,
                                     &id_a, fake_sign, fake_verify,
                                     &ctx_a, 0u, 0u);
    (void)bowie_proto_handshake_init(&hs_b,
                                     BOWIE_PROTO_HS_RESPONDER,
                                     &id_b, fake_sign, fake_verify,
                                     &ctx_b, 0u, 0u);

    make_nonce(hs_a.local_nonce, 0x01u);
    make_nonce(hs_b.local_nonce, 0x02u);

    /* A -> B: HELLO */
    bowie_proto_msg_t hello;
    int has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs_a, &hello, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);

    /* B processes HELLO. It must use B's own context for
     * verification because the verify callback uses the
     * ctx. The verify function is given the remote ID. */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_b, &hello, 0u),
        BOWIE_OK);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_IDLE);

    /* B -> A: HELLO_ACK */
    bowie_proto_msg_t ack;
    has = 0;
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs_b, &ack, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(ack.header.type, BOWIE_PROTO_MSG_HELLO_ACK);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_SENT_ACK);

    /* A processes HELLO_ACK. */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_a, &ack, 0u),
        BOWIE_OK);
    ck_assert(bowie_proto_handshake_is_done(&hs_a));

    /* B is not done yet: it sent ACK but has not seen a
     * confirmation. In this two-message handshake B treats
     * its own send as done. */
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_SENT_ACK);

    /* Remote IDs. */
    bowie_public_id_t remote_a;
    bowie_public_id_t remote_b;

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_a, &remote_a),
        BOWIE_OK);
    ck_assert(bowie_public_id_equal(&remote_a, &id_b));

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_b, &remote_b),
        BOWIE_OK);
    ck_assert(bowie_public_id_equal(&remote_b, &id_a));
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

    TCase *tc_life = tcase_create("Lifecycle");
    tcase_add_test(tc_life, test_init_null_hs);
    tcase_add_test(tc_life, test_init_null_id);
    tcase_add_test(tc_life, test_init_null_sign);
    tcase_add_test(tc_life, test_init_null_verify);
    tcase_add_test(tc_life, test_init_bad_role);
    tcase_add_test(tc_life, test_init_ok);
    tcase_add_test(tc_life, test_clear_preserves_config);
    tcase_add_test(tc_life, test_clear_null);
    suite_add_tcase(s, tc_life);

    TCase *tc_out = tcase_create("Output");
    tcase_add_test(tc_out, test_output_null_hs);
    tcase_add_test(tc_out, test_output_null_msg);
    tcase_add_test(tc_out, test_output_null_has);
    tcase_add_test(tc_out, test_initiator_first_output_is_hello);
    tcase_add_test(tc_out, test_initiator_second_output_no_message);
    tcase_add_test(tc_out, test_responder_first_output_no_message);
    suite_add_tcase(s, tc_out);

    TCase *tc_in = tcase_create("Input");
    tcase_add_test(tc_in, test_input_null_hs);
    tcase_add_test(tc_in, test_input_null_msg);
    tcase_add_test(tc_in, test_input_wrong_type_initiator);
    suite_add_tcase(s, tc_in);

    TCase *tc_to = tcase_create("Timeout");
    tcase_add_test(tc_to, test_timed_out_null);
    tcase_add_test(tc_to, test_timed_out_not_yet);
    tcase_add_test(tc_to, test_timed_out_yes);
    tcase_add_test(tc_to, test_input_after_timeout_fails);
    suite_add_tcase(s, tc_to);

    TCase *tc_q = tcase_create("Query");
    tcase_add_test(tc_q, test_state_null);
    tcase_add_test(tc_q, test_state_ok);
    tcase_add_test(tc_q, test_remote_id_null);
    tcase_add_test(tc_q, test_remote_id_not_known);
    tcase_add_test(tc_q, test_is_done_null);
    tcase_add_test(tc_q, test_is_done_false);
    tcase_add_test(tc_q, test_is_failed_null);
    tcase_add_test(tc_q, test_is_failed_false);
    suite_add_tcase(s, tc_q);

    TCase *tc_full = tcase_create("Full");
    tcase_add_test(tc_full, test_full_handshake_success);
    suite_add_tcase(s, tc_full);

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
