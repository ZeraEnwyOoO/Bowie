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
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No real crypto. The sign and verify callbacks are
 *     deterministic fakes so that a test does not depend on
 *     OpenSSL.
 *   - No transport. Messages are built in memory.
 *   - No allocation. Every buffer is on the stack.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The fake signer writes a signature that is a function of the
 * signed data and the signer's key id. The fake verifier
 * recomputes the expected signature from the public ID and the
 * signed data. A wrong key or wrong data produces a different
 * signature, so the fake exercises the same path a real
 * signature would.
 *
 * The handshake does not generate the local nonce. Every test
 * that needs a nonce writes one into the handshake before
 * calling output. This mirrors how the real caller is expected
 * to use the handshake.
 *
 * The clear function preserves the callbacks, the local ID,
 * the local nonce, and the timeout. It resets the state, the
 * remote ID, and the remote nonce.
 *
 * The output function returns BOWIE_ERR_STATE when the state
 * does not allow output. For an initiator, that means any
 * state other than IDLE. For a responder, that means any
 * state other than IDLE or SENT_HELLO. The responder has
 * nothing to send in IDLE; it returns BOWIE_OK with
 * out_has_msg == 0 in that case.
 *
 * Function pointers are compared directly, not through
 * ck_assert_ptr_eq, because ISO C does not allow a function
 * pointer to be converted to void *.
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
 * FAKE CRYPTO
 * ============================================================================
 */

typedef struct fake_crypto {
    uint8_t local_key_id;
    int     sign_calls;
    int     verify_calls;
    int     force_sign_fail;
    int     force_verify_fail;
} fake_crypto_t;

static bowie_error_t fake_sign(
    void          *ctx,
    const uint8_t *data,
    size_t         len,
    uint8_t       *out_sig)
{
    fake_crypto_t *fc = (fake_crypto_t *)ctx;

    if (fc == NULL || data == NULL || out_sig == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (fc->force_sign_fail) {
        return BOWIE_ERR_CRYPTO;
    }

    fc->sign_calls++;

    for (size_t i = 0; i < BOWIE_PROTO_SIG_LEN; i++) {
        uint8_t d = (len > 0u) ? data[i % len] : 0u;
        out_sig[i] = (uint8_t)(d ^ fc->local_key_id ^ (uint8_t)i);
    }

    return BOWIE_OK;
}

static int fake_verify(
    void                    *ctx,
    const bowie_public_id_t *id,
    const uint8_t           *data,
    size_t                   len,
    const uint8_t           *sig)
{
    fake_crypto_t *fc = (fake_crypto_t *)ctx;

    if (fc == NULL || id == NULL || data == NULL || sig == NULL) {
        return 0;
    }

    fc->verify_calls++;

    if (fc->force_verify_fail) {
        return 0;
    }

    uint8_t key_id = id->bytes[0];

    for (size_t i = 0; i < BOWIE_PROTO_SIG_LEN; i++) {
        uint8_t d = (len > 0u) ? data[i % len] : 0u;
        uint8_t expect = (uint8_t)(d ^ key_id ^ (uint8_t)i);
        if (sig[i] != expect) {
            return 0;
        }
    }

    return 1;
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_id(bowie_public_id_t *id, uint8_t seed)
{
    memset(id, 0, sizeof(*id));

    id->bytes[0] = seed;

    if (seed == 0u) {
        id->bytes[1] = 1u;
    }
}

static void make_nonce(uint8_t *nonce, uint8_t seed)
{
    for (size_t i = 0; i < BOWIE_PROTO_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

/*
 * Init a handshake and set a local nonce in one step. Used by
 * every test that needs to call output.
 */
static void init_with_nonce(
    bowie_proto_handshake_t *hs,
    bowie_proto_hs_role_t    role,
    const bowie_public_id_t *id,
    fake_crypto_t           *fc,
    bowie_mtime_t            timeout_ms,
    bowie_mtime_t            now_ms,
    uint8_t                  nonce_seed)
{
    ck_assert_int_eq(
        bowie_proto_handshake_init(
            hs, role, id,
            fake_sign, fake_verify, fc,
            timeout_ms, now_ms),
        BOWIE_OK);

    make_nonce(hs->local_nonce, nonce_seed);
    hs->have_local_nonce = 1;
}

/*
 * Pull one message out of a handshake. The message payload
 * points into the handshake's out_payload buffer, so the
 * handshake must stay alive for as long as the message is
 * used.
 */
static void take_msg(
    bowie_proto_handshake_t *hs,
    bowie_proto_msg_t       *out_msg)
{
    int has = 0;

    ck_assert_int_eq(
        bowie_proto_handshake_output(hs, out_msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);
}

/*
 * ============================================================================
 * INIT
 * ============================================================================
 */

START_TEST(test_init_null_hs)
{
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            NULL, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_local_id)
{
    bowie_proto_handshake_t hs;
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, NULL,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_sign)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            NULL, fake_verify, NULL, 1000u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_null_verify)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, NULL, NULL, 1000u, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_init_invalid_role)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, (bowie_proto_hs_role_t)99, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_ERR_INVAL);
}
END_TEST

START_TEST(test_init_initiator_ok)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_int_eq(hs.role, BOWIE_PROTO_HS_INITIATOR);
    ck_assert_uint_eq(hs.local_id.bytes[0], 0x11u);
    ck_assert_uint_eq(hs.timeout_ms, 1000u);
    ck_assert_uint_eq(hs.started_at_ms, 100u);
    ck_assert(hs.sign == fake_sign);
    ck_assert(hs.verify == fake_verify);
    ck_assert_ptr_eq(hs.ctx, &fc);
}
END_TEST

START_TEST(test_init_responder_ok)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_int_eq(hs.role, BOWIE_PROTO_HS_RESPONDER);
}
END_TEST

START_TEST(test_init_default_timeout)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 0u, 0u),
        BOWIE_OK);

    ck_assert_uint_eq(hs.timeout_ms,
                      BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS);
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

START_TEST(test_clear_resets_state_and_remote)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    make_nonce(hs.local_nonce, 0xA0);
    hs.have_local_nonce = 1;
    make_id(&hs.remote_id, 0xBB);
    make_nonce(hs.remote_nonce, 0xB0);
    hs.have_remote_nonce = 1;
    hs.state = BOWIE_PROTO_HS_SENT_HELLO;

    bowie_proto_handshake_clear(&hs);

    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
    ck_assert_uint_eq(hs.remote_id.bytes[0], 0u);
    ck_assert_uint_eq(hs.have_remote_nonce, 0);
    ck_assert_uint_eq(hs.remote_nonce[0], 0u);
}
END_TEST

START_TEST(test_clear_preserves_callbacks_and_local)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    make_nonce(hs.local_nonce, 0xA0);
    hs.have_local_nonce = 1;

    bowie_proto_handshake_clear(&hs);

    ck_assert(hs.sign == fake_sign);
    ck_assert(hs.verify == fake_verify);
    ck_assert_ptr_eq(hs.ctx, &fc);
    ck_assert_uint_eq(hs.local_id.bytes[0], 0x11u);
    ck_assert_uint_eq(hs.timeout_ms, 1000u);

    /*
     * The clear function preserves the local nonce and the
     * have_local_nonce flag.
     */
    ck_assert_uint_eq(hs.have_local_nonce, 1);
    ck_assert_uint_eq(hs.local_nonce[0], 0xA0u);
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
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    int has = 0;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, NULL, &has),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_null_has)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_output_initiator_produces_hello)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;
    int has = 0;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);

    ck_assert_int_eq(has, 1);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_SENT_HELLO);
    ck_assert_uint_eq(msg.header.type, BOWIE_PROTO_MSG_HELLO);
    ck_assert_uint_eq(msg.header.version, BOWIE_PROTO_VERSION);
    ck_assert_uint_eq(msg.payload.len,
                      BOWIE_PROTO_HELLO_PAYLOAD_LEN);
    ck_assert_uint_eq(fc.sign_calls, 1);
}
END_TEST

START_TEST(test_output_initiator_no_second_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;
    int has = 0;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 1);

    /*
     * A second call in the SENT_HELLO state is rejected with
     * BOWIE_ERR_STATE. The initiator has already sent HELLO
     * and has nothing more to send until HELLO_ACK arrives.
     */
    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_ERR_STATE);
}
END_TEST

START_TEST(test_output_responder_idle_no_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;
    int has = 99;

    init_with_nonce(&hs, BOWIE_PROTO_HS_RESPONDER, &id,
                    &fc, 1000u, 0u, 0xC0);

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_IDLE);
}
END_TEST

START_TEST(test_output_done_no_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;
    int has = 99;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    hs.state = BOWIE_PROTO_HS_DONE;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
}
END_TEST

START_TEST(test_output_failed_no_message)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_proto_msg_t msg;
    int has = 99;

    init_with_nonce(&hs, BOWIE_PROTO_HS_INITIATOR, &id,
                    &fc, 1000u, 0u, 0xA0);

    hs.state = BOWIE_PROTO_HS_FAILED;

    ck_assert_int_eq(
        bowie_proto_handshake_output(&hs, &msg, &has),
        BOWIE_OK);
    ck_assert_int_eq(has, 0);
}
END_TEST

/*
 * ============================================================================
 * INPUT
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
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, NULL, 0u),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_input_wrong_payload_length)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    uint8_t short_payload[16];
    memset(short_payload, 0, sizeof(short_payload));

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_HELLO;
    msg.payload.data   = short_payload;
    msg.payload.len    = sizeof(short_payload);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_input_wrong_role)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    /*
     * An initiator receiving HELLO must fail with STATE.
     * Only a responder accepts HELLO.
     */
    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    uint8_t payload[BOWIE_PROTO_HELLO_PAYLOAD_LEN];
    memset(payload, 0, sizeof(payload));

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_HELLO;
    msg.payload.data   = payload;
    msg.payload.len    = sizeof(payload);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_STATE);
}
END_TEST

START_TEST(test_input_wrong_state)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    /*
     * The responder is already past IDLE. A second HELLO is
     * rejected with STATE.
     */
    hs.state = BOWIE_PROTO_HS_SENT_ACK;

    uint8_t payload[BOWIE_PROTO_HELLO_PAYLOAD_LEN];
    memset(payload, 0, sizeof(payload));

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_HELLO;
    msg.payload.data   = payload;
    msg.payload.len    = sizeof(payload);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_STATE);
}
END_TEST

START_TEST(test_input_bad_signature)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };
    fc.force_verify_fail = 1;

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    uint8_t payload[BOWIE_PROTO_HELLO_PAYLOAD_LEN];
    memset(payload, 0xAA, sizeof(payload));

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_HELLO;
    msg.payload.data   = payload;
    msg.payload.len    = sizeof(payload);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_SIGN_INVALID);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_FAILED);
}
END_TEST

START_TEST(test_input_timeout)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    uint8_t payload[BOWIE_PROTO_HELLO_PAYLOAD_LEN];
    memset(payload, 0, sizeof(payload));

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_HELLO;
    msg.payload.data   = payload;
    msg.payload.len    = sizeof(payload);

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 2000u),
        BOWIE_ERR_TIMEOUT);
    ck_assert_int_eq(hs.state, BOWIE_PROTO_HS_FAILED);
}
END_TEST

START_TEST(test_input_unknown_type)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x22);
    fake_crypto_t fc = { 0x22, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_RESPONDER, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    bowie_proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.version = BOWIE_PROTO_VERSION;
    msg.header.type    = BOWIE_PROTO_MSG_DATA;
    msg.payload.data   = NULL;
    msg.payload.len    = 0u;

    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs, &msg, 0u),
        BOWIE_ERR_STATE);
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
    make_id(&id_a, 0x0A);
    make_id(&id_b, 0x0B);

    fake_crypto_t fc_a = { 0x0A, 0, 0, 0, 0 };
    fake_crypto_t fc_b = { 0x0B, 0, 0, 0, 0 };

    bowie_proto_handshake_t hs_a;
    bowie_proto_handshake_t hs_b;

    init_with_nonce(&hs_a, BOWIE_PROTO_HS_INITIATOR, &id_a,
                    &fc_a, 1000u, 0u, 0xA0);
    init_with_nonce(&hs_b, BOWIE_PROTO_HS_RESPONDER, &id_b,
                    &fc_b, 1000u, 0u, 0xB0);

    /*
     * A outputs HELLO.
     */
    bowie_proto_msg_t hello;
    take_msg(&hs_a, &hello);
    ck_assert_uint_eq(hello.header.type, BOWIE_PROTO_MSG_HELLO);
    ck_assert_int_eq(hs_a.state, BOWIE_PROTO_HS_SENT_HELLO);

    /*
     * B receives HELLO. The responder stays in IDLE because
     * handle_hello does not change the state. The output
     * function is what moves the responder forward.
     */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_b, &hello, 10u),
        BOWIE_OK);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_IDLE);

    /*
     * B sets a nonce and outputs HELLO_ACK. The output
     * function is what the responder calls after a HELLO to
     * produce the ACK.
     */
    make_nonce(hs_b.local_nonce, 0xB0);
    hs_b.have_local_nonce = 1;
    hs_b.state = BOWIE_PROTO_HS_SENT_HELLO;

    bowie_proto_msg_t ack;
    take_msg(&hs_b, &ack);
    ck_assert_uint_eq(ack.header.type, BOWIE_PROTO_MSG_HELLO_ACK);
    ck_assert_int_eq(hs_b.state, BOWIE_PROTO_HS_SENT_ACK);

    /*
     * A receives HELLO_ACK and completes.
     */
    ck_assert_int_eq(
        bowie_proto_handshake_input(&hs_a, &ack, 20u),
        BOWIE_OK);
    ck_assert_int_eq(hs_a.state, BOWIE_PROTO_HS_DONE);

    /*
     * Both sides have the peer's public ID.
     */
    bowie_public_id_t remote_a;
    bowie_public_id_t remote_b;

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_a, &remote_a),
        BOWIE_OK);
    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs_b, &remote_b),
        BOWIE_OK);

    ck_assert_uint_eq(remote_a.bytes[0], id_b.bytes[0]);
    ck_assert_uint_eq(remote_b.bytes[0], id_a.bytes[0]);

    ck_assert(bowie_proto_handshake_is_done(&hs_a));
    ck_assert(bowie_proto_handshake_is_done(&hs_b));
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
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs, NULL),
        BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_remote_id_not_found)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };
    bowie_public_id_t out;

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 0u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_remote_id(&hs, &out),
        BOWIE_ERR_NOT_FOUND);
}
END_TEST

START_TEST(test_is_done_null)
{
    ck_assert_int_eq(bowie_proto_handshake_is_done(NULL), 0);
}
END_TEST

START_TEST(test_is_failed_null)
{
    ck_assert_int_eq(bowie_proto_handshake_is_failed(NULL), 1);
}
END_TEST

START_TEST(test_timed_out_null)
{
    ck_assert_int_eq(
        bowie_proto_handshake_timed_out(NULL, 100u), 0);
}
END_TEST

START_TEST(test_timed_out_zero_timeout)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    /*
     * A timeout of zero is treated as "no timeout" by the
     * timed_out helper. The init function replaces a zero
     * timeout with the default, so this case is reached only
     * by writing the field directly.
     */
    hs.timeout_ms = 0u;

    ck_assert_int_eq(
        bowie_proto_handshake_timed_out(&hs, 99999u), 0);
}
END_TEST

START_TEST(test_timed_out_clock_backwards)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 5000u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_timed_out(&hs, 1000u), 0);
}
END_TEST

START_TEST(test_timed_out_before_deadline)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_timed_out(&hs, 500u), 0);
}
END_TEST

START_TEST(test_timed_out_at_deadline)
{
    bowie_proto_handshake_t hs;
    bowie_public_id_t id;
    make_id(&id, 0x11);
    fake_crypto_t fc = { 0x11, 0, 0, 0, 0 };

    ck_assert_int_eq(
        bowie_proto_handshake_init(
            &hs, BOWIE_PROTO_HS_INITIATOR, &id,
            fake_sign, fake_verify, &fc, 1000u, 100u),
        BOWIE_OK);

    ck_assert_int_eq(
        bowie_proto_handshake_timed_out(&hs, 1100u), 1);
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
    tcase_add_test(tc_init, test_init_null_local_id);
    tcase_add_test(tc_init, test_init_null_sign);
    tcase_add_test(tc_init, test_init_null_verify);
    tcase_add_test(tc_init, test_init_invalid_role);
    tcase_add_test(tc_init, test_init_initiator_ok);
    tcase_add_test(tc_init, test_init_responder_ok);
    tcase_add_test(tc_init, test_init_default_timeout);
    suite_add_tcase(s, tc_init);

    TCase *tc_clear = tcase_create("Clear");
    tcase_add_test(tc_clear, test_clear_null);
    tcase_add_test(tc_clear, test_clear_resets_state_and_remote);
    tcase_add_test(tc_clear, test_clear_preserves_callbacks_and_local);
    suite_add_tcase(s, tc_clear);

    TCase *tc_output = tcase_create("Output");
    tcase_add_test(tc_output, test_output_null_hs);
    tcase_add_test(tc_output, test_output_null_msg);
    tcase_add_test(tc_output, test_output_null_has);
    tcase_add_test(tc_output, test_output_initiator_produces_hello);
    tcase_add_test(tc_output, test_output_initiator_no_second_message);
    tcase_add_test(tc_output, test_output_responder_idle_no_message);
    tcase_add_test(tc_output, test_output_done_no_message);
    tcase_add_test(tc_output, test_output_failed_no_message);
    suite_add_tcase(s, tc_output);

    TCase *tc_input = tcase_create("Input");
    tcase_add_test(tc_input, test_input_null_hs);
    tcase_add_test(tc_input, test_input_null_msg);
    tcase_add_test(tc_input, test_input_wrong_payload_length);
    tcase_add_test(tc_input, test_input_wrong_role);
    tcase_add_test(tc_input, test_input_wrong_state);
    tcase_add_test(tc_input, test_input_bad_signature);
    tcase_add_test(tc_input, test_input_timeout);
    tcase_add_test(tc_input, test_input_unknown_type);
    suite_add_tcase(s, tc_input);

    TCase *tc_full = tcase_create("FullHandshake");
    tcase_add_test(tc_full, test_full_handshake);
    suite_add_tcase(s, tc_full);

    TCase *tc_query = tcase_create("Query");
    tcase_add_test(tc_query, test_state_null);
    tcase_add_test(tc_query, test_remote_id_null_hs);
    tcase_add_test(tc_query, test_remote_id_null_out);
    tcase_add_test(tc_query, test_remote_id_not_found);
    tcase_add_test(tc_query, test_is_done_null);
    tcase_add_test(tc_query, test_is_failed_null);
    tcase_add_test(tc_query, test_timed_out_null);
    tcase_add_test(tc_query, test_timed_out_zero_timeout);
    tcase_add_test(tc_query, test_timed_out_clock_backwards);
    tcase_add_test(tc_query, test_timed_out_before_deadline);
    tcase_add_test(tc_query, test_timed_out_at_deadline);
    suite_add_tcase(s, tc_query);

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
