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
 * BOWIE — ENGINE (IMPLEMENTATION)
 * ============================================================================
 */

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "core/internal/rand.h"
#include "core/internal/time.h"
#include "crypto/hash.h"
#include "dht/dht.h"
#include "dht/search.h"
#include "nat/nat.h"
#include "tunnel/tun.h"
#include "gateway/gateway.h"
#include "security/grant.h"
#include "security/keypair.h"
#include "security/ownership.h"
#include "security/permission.h"
#include "security/revoke.h"
#include "security/session.h"
#include "security/sign.h"
#include "security/kdf.h"
#include "proto/stream.h"
#include "net/peer.h"
#include "engine/engine.h"
#include "engine/internal/engine.h"
#include "engine/internal/state.h"
#include "engine/internal/event.h"
#include "engine/internal/signal.h"
#include "engine/internal/diag.h"

/*
 * ============================================================================
 * INTERNAL — LOG
 * ============================================================================
 */

#define ENGINE_LOG(level, ...) \
    do { bowie_engine_diag_level("BowieEngine", (level), __VA_ARGS__); } while (0)

static int engine_grant_is_revoked(bowie_engine_t *e,
                                   const bowie_grant_id_t *grant_id)
{
    int revoked;
    pthread_mutex_lock(&e->lock);
    revoked = bowie_revoke_list_contains(&e->revoke_list, grant_id);
    pthread_mutex_unlock(&e->lock);
    return revoked;
}

/* Caller holds e->lock. Keep grant counters separate so switching friends or
 * reconnecting with a different grant cannot reset another grant's usage. */
static int engine_grant_usage_slot(bowie_engine_t *e, const bowie_grant_t *grant)
{
    size_t free_slot = BOWIE_ENGINE_GRANT_USAGE_MAX;
    for (size_t i = 0u; i < BOWIE_ENGINE_GRANT_USAGE_MAX; ++i) {
        bowie_engine_grant_usage_t *usage = &e->grant_usage[i];
        if (bowie_grant_id_equal(&usage->grant_id, &grant->grant_id)) {
            return usage->bytes_limit == grant->max_egress_bytes ? (int)i : -1;
        }
        if (free_slot == BOWIE_ENGINE_GRANT_USAGE_MAX &&
            bowie_grant_id_is_zero(&usage->grant_id)) free_slot = i;
    }
    if (free_slot == BOWIE_ENGINE_GRANT_USAGE_MAX) return -1;
    uint64_t stored_used = 0u;
    if (e->cfg.grant_usage_load != NULL) {
        int load_rc = e->cfg.grant_usage_load(e->cfg.grant_usage_context,
                         &grant->grant_id, grant->max_egress_bytes, &stored_used);
        if (load_rc < 0 || stored_used > grant->max_egress_bytes) return -1;
    }
    e->grant_usage[free_slot].grant_id = grant->grant_id;
    e->grant_usage[free_slot].bytes_limit = grant->max_egress_bytes;
    e->grant_usage[free_slot].bytes_used = stored_used;
    e->grant_usage[free_slot].durable_bytes = stored_used;
    return (int)free_slot;
}

static int engine_grant_usage_save(void *context, uint64_t used)
{
    bowie_engine_t *e = (bowie_engine_t *)context;
    int slot = e != NULL ? e->active_quota_slot : -1;
    if (e == NULL || slot < 0 || (size_t)slot >= BOWIE_ENGINE_GRANT_USAGE_MAX)
        return 0;
    if (e->cfg.grant_usage_save == NULL) return 1;
    bowie_engine_grant_usage_t *usage = &e->grant_usage[slot];
    if (used <= usage->durable_bytes) return 1;
    const uint64_t quantum = 64u * 1024u;
    uint64_t reserved = used > UINT64_MAX - (quantum - 1u)
        ? UINT64_MAX : ((used + quantum - 1u) / quantum) * quantum;
    if (reserved > usage->bytes_limit) reserved = usage->bytes_limit;
    if (!e->cfg.grant_usage_save(e->cfg.grant_usage_context, &usage->grant_id,
                                 usage->bytes_limit, reserved)) return 0;
    usage->durable_bytes = reserved;
    return 1;
}

static void *engine_quota_monitor(void *context)
{
    bowie_engine_t *e = (bowie_engine_t *)context;
    pthread_mutex_lock(&e->lock);
    for (;;) {
        if (__atomic_load_n(&e->quota_monitor_stop, __ATOMIC_ACQUIRE)) break;
        if (__atomic_exchange_n(&e->quota_disconnect_pending, 0, __ATOMIC_ACQ_REL)) {
            pthread_mutex_unlock(&e->lock);
            /* Let the NAT data callback that reported exhaustion unwind
             * before disconnect destroys/recreates the ICE agent. */
            struct timespec callback_grace = { 0, 100000000L };
            nanosleep(&callback_grace, NULL);
            (void)bowie_engine_disconnect(e);
            pthread_mutex_lock(&e->lock);
            continue;
        }
        struct timespec wake;
        (void)clock_gettime(CLOCK_REALTIME, &wake);
        wake.tv_nsec += 100000000L;
        if (wake.tv_nsec >= 1000000000L) { wake.tv_sec++; wake.tv_nsec -= 1000000000L; }
        (void)pthread_cond_timedwait(&e->nat_cond, &e->lock, &wake);
    }
    pthread_mutex_unlock(&e->lock);
    return NULL;
}

static void engine_quota_exceeded(void *context)
{
    bowie_engine_t *e = (bowie_engine_t *)context;
    if (e == NULL) return;
    __atomic_store_n(&e->quota_disconnect_pending, 1, __ATOMIC_RELEASE);
    pthread_cond_signal(&e->nat_cond);
    bowie_diag_json_emit("WARN", "Engine", "GRANT_DATA_LIMIT_REACHED", NULL,
                         "{\"action\":\"disconnect\"}");
}

/*
 * ============================================================================
 * INTERNAL — DERIVE IDS
 * ============================================================================
 */

static bowie_error_t derive_ids(bowie_engine_t *e)
{
    bowie_hash_sha1_t h;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memcpy(e->own_public_id.bytes, e->own_sign_pub.bytes,
           BOWIE_PUBLIC_ID_LEN);

    bowie_error_t rc = bowie_hash_sha1(e->own_public_id.bytes,
                                        BOWIE_PUBLIC_ID_LEN, &h);
    if (rc != BOWIE_OK) {
        return rc;
    }

    memcpy(e->own_peer_id.bytes, h.bytes, BOWIE_PEER_ID_LEN);
    memcpy(e->own_dht_id.bytes, h.bytes, BOWIE_DHT_NODE_ID_LEN);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — DEFAULT DHT CONFIG
 * ============================================================================
 */

static void make_dht_config(const bowie_engine_config_t *cfg,
                            bowie_dht_config_t *out)
{
    memset(out, 0, sizeof(*out));

    if (cfg->bootstrap_count <= BOWIE_DHT_BOOTSTRAP_MAX) {
        out->bootstrap_count = cfg->bootstrap_count;
        memcpy(out->bootstrap, cfg->bootstrap,
               cfg->bootstrap_count * sizeof(cfg->bootstrap[0]));
    }
    out->prepare_underlay_address = cfg->prepare_underlay_address;
    out->underlay_context = cfg->underlay_context;

    out->max_buckets         = BOWIE_DHT_DEFAULT_MAX_BUCKETS;
    out->max_nodes_per_bucket = BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET;
    out->max_hashes          = BOWIE_ENGINE_DHT_HASHES_CAP;
    out->max_peers_per_hash  = BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH;
    out->max_storage_peers   = BOWIE_ENGINE_DHT_PEERS_CAP;
    out->refresh_interval_s  = BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S;
    out->peer_lifetime_s     = BOWIE_DHT_DEFAULT_PEER_LIFETIME_S;
    out->token_rotate_s      = BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S;
    out->search_timeout_ms   = BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS;

    out->sec_level           = BOWIE_DHT_SEC_BASIC;
    out->max_requests_per_window = BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS;

    (void)cfg;
}

/*
 * ============================================================================
 * INTERNAL — DEFAULT NAT CONFIG
 * ============================================================================
 */

static void make_nat_config(const bowie_engine_config_t *cfg,
                            bowie_nat_config_t *out)
{
    bowie_nat_default_config(out);

    out->allow_server = (cfg->allow_server ||
        cfg->signal_backend == BOWIE_SIGNAL_BACKEND_METERED) ? 1 : 0;
    out->bind_address = cfg->nat_bind_address;

    if (cfg->allow_server) {
        out->stun_server_host = cfg->stun_host;
        out->stun_server_port = cfg->stun_port;

        out->turn_server_host = cfg->turn_host;
        out->turn_server_port = cfg->turn_port;
        out->turn_username    = cfg->turn_user;
        out->turn_password    = cfg->turn_pass;
    }
}

/*
 * ============================================================================
 * INTERNAL — X25519 SESSION KEY EXCHANGE
 * ============================================================================
 */

static const uint8_t kSessionInfo[] = "bowie session key v1";

#define ENGINE_HS_ID_LEN       BOWIE_PUBLIC_ID_LEN
#define ENGINE_HS_EPH_LEN      BOWIE_KEYPAIR_PUBLIC_LEN
#define ENGINE_HS_NONCE_LEN    16u
#define ENGINE_HS_SIG_LEN      BOWIE_SIGN_SIGNATURE_LEN
#define ENGINE_HS_PREFIX_LEN   (ENGINE_HS_ID_LEN + ENGINE_HS_EPH_LEN + ENGINE_HS_NONCE_LEN)
#define ENGINE_HS_MESSAGE_LEN  (ENGINE_HS_PREFIX_LEN + ENGINE_HS_SIG_LEN)
#define ENGINE_HS_TRANSCRIPT_LEN (ENGINE_HS_MESSAGE_LEN * 2u)
#define ENGINE_ROOM_CONTEXT_LEN BOWIE_DHT_INFO_HASH_LEN

static bowie_error_t read_handshake_msg(bowie_proto_stream_t *stream,
                                        uint8_t out[ENGINE_HS_MESSAGE_LEN])
{
    size_t n = 0u;
    for (unsigned retries = 0u; retries < 300u; retries++) {
        bowie_error_t rc = bowie_proto_stream_read_msg(stream, out,
                                                       ENGINE_HS_MESSAGE_LEN, &n);
        if (rc == BOWIE_OK) {
            if (n == 1u && out[0] == 0u) return BOWIE_ERR_PERMISSION;
            return n == ENGINE_HS_MESSAGE_LEN ? BOWIE_OK : BOWIE_ERR_FORMAT;
        }
        if (rc != BOWIE_ERR_AGAIN) return rc;
        struct timespec ts = { 0, 10000000L };
        nanosleep(&ts, NULL);
    }
    return BOWIE_ERR_TIMEOUT;
}

static bowie_error_t read_owner_grant(bowie_proto_stream_t *stream,
                                      bowie_grant_t *grant)
{
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    size_t n = 0u;
    for (unsigned retries = 0u; retries < 300u; retries++) {
        bowie_error_t rc = bowie_proto_stream_read_msg(stream, wire,
                                                       sizeof(wire), &n);
        if (rc == BOWIE_OK) {
            if (n != sizeof(wire)) return BOWIE_ERR_FORMAT;
            return bowie_grant_deserialize(wire, n, grant);
        }
        if (rc != BOWIE_ERR_AGAIN) return rc;
        struct timespec pause = { 0, 10000000L };
        nanosleep(&pause, NULL);
    }
    return BOWIE_ERR_TIMEOUT;
}

static bowie_error_t send_grant_denial(bowie_proto_stream_t *stream)
{
    const uint8_t denied = 0u;
    (void)bowie_proto_stream_write_msg(stream, &denied, sizeof(denied));
    return BOWIE_ERR_PERMISSION;
}

static bowie_error_t write_presented_grant(bowie_engine_t *e,
                                            bowie_proto_stream_t *stream)
{
    bowie_grant_t grant;
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    int present;
    pthread_mutex_lock(&e->lock);
    present = e->has_presented_grant;
    grant = e->presented_grant;
    pthread_mutex_unlock(&e->lock);
    if (!present && !e->cfg.allow_ungranted_peers) return BOWIE_ERR_PERMISSION;
    memset(wire, 0, sizeof(wire));
    if (present) {
        long len = bowie_grant_serialize(&grant, wire,
                                         BOWIE_GRANT_WIRE_LEN - 64u);
        if (len != (long)(BOWIE_GRANT_WIRE_LEN - 64u))
            return BOWIE_ERR_FORMAT;
        memcpy(wire + len, grant.signature, sizeof(grant.signature));
    }
    return bowie_proto_stream_write_msg(stream, wire, sizeof(wire));
}

static int presented_grant_matches_owner(bowie_engine_t *e,
                                         const bowie_sign_public_t *owner)
{
    bowie_grant_t grant;
    int present;
    pthread_mutex_lock(&e->lock);
    present = e->has_presented_grant;
    grant = e->presented_grant;
    pthread_mutex_unlock(&e->lock);
    return present && memcmp(grant.issuer.bytes, owner->bytes,
                             BOWIE_PUBLIC_ID_LEN) == 0;
}

static bowie_error_t read_authorization_ack(bowie_proto_stream_t *stream,
                                            uint8_t *ack)
{
    size_t length = 0u;
    for (unsigned retries = 0u; retries < 300u; retries++) {
        bowie_error_t rc = bowie_proto_stream_read_msg(stream, ack, 1u, &length);
        if (rc == BOWIE_OK) return length == 1u ? BOWIE_OK : BOWIE_ERR_FORMAT;
        if (rc != BOWIE_ERR_AGAIN) return rc;
        struct timespec pause = { 0, 10000000L };
        nanosleep(&pause, NULL);
    }
    return BOWIE_ERR_TIMEOUT;
}

static void destroy_handshake_stream(bowie_engine_t *e,
                                     bowie_proto_stream_t *stream)
{
    if (e != NULL && e->nat != NULL) (void)bowie_nat_set_recv(e->nat, NULL, NULL);
    bowie_proto_stream_destroy(stream);
}

static bowie_error_t peer_id_from_public(const uint8_t public_id[BOWIE_PUBLIC_ID_LEN],
                                         bowie_peer_id_t *out)
{
    bowie_hash_sha1_t hash;
    bowie_error_t rc = bowie_hash_sha1(public_id, BOWIE_PUBLIC_ID_LEN, &hash);
    if (rc == BOWIE_OK) memcpy(out->bytes, hash.bytes, BOWIE_PEER_ID_LEN);
    return rc;
}

static bowie_error_t exchange_authenticated(bowie_engine_t *e,
                                            bowie_proto_stream_t *stream,
                                            const bowie_peer_id_t *expected_peer,
                                            int initiator,
                                            bowie_keypair_shared_t *out_shared,
                                            uint8_t transcript[ENGINE_HS_TRANSCRIPT_LEN],
                                            bowie_peer_id_t *out_remote_peer,
                                            bowie_grant_t *out_owner_grant)
{
    static const uint8_t domain[] = "Bowie authenticated session v1";
    static const uint8_t room_domain[] = "Bowie room ownership proof v1";
    uint8_t first[ENGINE_HS_MESSAGE_LEN];
    uint8_t second[ENGINE_HS_MESSAGE_LEN];
    uint8_t signed_data[sizeof(domain) + sizeof(room_domain) + 2u + ENGINE_HS_MESSAGE_LEN + ENGINE_HS_PREFIX_LEN + BOWIE_PEER_ID_LEN + ENGINE_ROOM_CONTEXT_LEN];
    uint8_t room_context[ENGINE_ROOM_CONTEXT_LEN] = {0};
    int room_context_active;
    bowie_keypair_public_t local_eph_pub, remote_eph_pub;
    bowie_keypair_private_t local_eph_priv;
    bowie_peer_id_t remote_peer_id;
    bowie_sign_public_t remote_sign_pub;
    bowie_sign_signature_t sig;
    size_t signed_len;
    bowie_error_t rc;
    uint8_t authorization_ack = 0u;

    if (e == NULL || stream == NULL || out_shared == NULL || transcript == NULL ||
        out_remote_peer == NULL) return BOWIE_ERR_NULL_ARG;
    if (out_owner_grant != NULL) bowie_grant_clear(out_owner_grant);

    pthread_mutex_lock(&e->lock);
    room_context_active = e->active_room;
    if (room_context_active) memcpy(room_context, e->active_room_hash.bytes,
                                    sizeof(room_context));
    pthread_mutex_unlock(&e->lock);

    if (initiator) {
        pthread_mutex_lock(&e->lock);
        int has_grant = e->has_presented_grant;
        pthread_mutex_unlock(&e->lock);
        if (!has_grant && !e->cfg.allow_ungranted_peers)
            return BOWIE_ERR_PERMISSION;
        bowie_engine_diag("BowieHandshake", "initiator: generating and signing first handshake message");
        rc = bowie_security_keypair_generate(&local_eph_pub, &local_eph_priv);
        if (rc != BOWIE_OK) return rc;
        memcpy(first, e->own_public_id.bytes, ENGINE_HS_ID_LEN);
        memcpy(first + ENGINE_HS_ID_LEN, local_eph_pub.bytes, ENGINE_HS_EPH_LEN);
        rc = bowie_rand_secure_bytes(first + ENGINE_HS_ID_LEN + ENGINE_HS_EPH_LEN,
                                     ENGINE_HS_NONCE_LEN);
        if (rc != BOWIE_OK) return rc;
        signed_len = 0u;
        memcpy(signed_data + signed_len, domain, sizeof(domain)); signed_len += sizeof(domain);
        signed_data[signed_len++] = 0u;
        memcpy(signed_data + signed_len, first, ENGINE_HS_PREFIX_LEN); signed_len += ENGINE_HS_PREFIX_LEN;
        if (expected_peer != NULL)
            memcpy(signed_data + signed_len, expected_peer->bytes, BOWIE_PEER_ID_LEN);
        else
            memset(signed_data + signed_len, 0, BOWIE_PEER_ID_LEN);
        signed_len += BOWIE_PEER_ID_LEN;
        if (room_context_active) {
            memcpy(signed_data + signed_len, room_domain, sizeof(room_domain));
            signed_len += sizeof(room_domain);
            memcpy(signed_data + signed_len, room_context, sizeof(room_context));
            signed_len += sizeof(room_context);
        }
        rc = bowie_security_sign(&e->own_sign_priv, signed_data, signed_len, &sig);
        if (rc != BOWIE_OK) return rc;
        memcpy(first + ENGINE_HS_PREFIX_LEN, sig.bytes, ENGINE_HS_SIG_LEN);
        bowie_engine_diag("BowieHandshake", "initiator: sending first handshake message (%u bytes)",
                          (unsigned)sizeof(first));
        rc = bowie_proto_stream_write_msg(stream, first, sizeof(first));
        if (rc != BOWIE_OK) {
            bowie_engine_diag("BowieHandshake", "initiator: first message send failed (%d)", (int)rc);
            return rc;
        }
        rc = write_presented_grant(e, stream);
        if (rc != BOWIE_OK) return rc;
        bowie_engine_diag("BowieHandshake", "initiator: waiting for responder handshake message");
        rc = read_handshake_msg(stream, second);
        if (rc != BOWIE_OK) {
            bowie_engine_diag("BowieHandshake", "initiator: responder message read failed (%d)", (int)rc);
            return rc;
        }

        rc = peer_id_from_public(second, &remote_peer_id);
        if (rc != BOWIE_OK || (expected_peer != NULL &&
            memcmp(remote_peer_id.bytes, expected_peer->bytes, BOWIE_PEER_ID_LEN) != 0)) {
            char expected_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            if (expected_peer != NULL)
                bowie_diag_hex(expected_peer->bytes, BOWIE_PEER_ID_LEN,
                               expected_hex, sizeof(expected_hex));
            else strcpy(expected_hex, "un-pinned");
            bowie_diag_json_emit("WARN", "Handshake", "PEER_ID_MISMATCH",
                                  expected_hex, "{\"role\":\"initiator\"}");
            return BOWIE_ERR_PERMISSION;
        }
        memcpy(remote_sign_pub.bytes, second, BOWIE_PUBLIC_ID_LEN);
        signed_len = 0u;
        memcpy(signed_data + signed_len, domain, sizeof(domain)); signed_len += sizeof(domain);
        signed_data[signed_len++] = 1u;
        memcpy(signed_data + signed_len, first, sizeof(first)); signed_len += sizeof(first);
        memcpy(signed_data + signed_len, second, ENGINE_HS_PREFIX_LEN); signed_len += ENGINE_HS_PREFIX_LEN;
        if (room_context_active) {
            memcpy(signed_data + signed_len, room_domain, sizeof(room_domain));
            signed_len += sizeof(room_domain);
            memcpy(signed_data + signed_len, room_context, sizeof(room_context));
            signed_len += sizeof(room_context);
        }
        memcpy(sig.bytes, second + ENGINE_HS_PREFIX_LEN, ENGINE_HS_SIG_LEN);
        bowie_public_id_t remote_public_id;
        bowie_span_t proof_challenge = { signed_data, signed_len };
        bowie_span_t proof_signature = { sig.bytes, sizeof(sig.bytes) };
        memcpy(remote_public_id.bytes, remote_sign_pub.bytes, sizeof(remote_public_id.bytes));
        rc = bowie_ownership_verify(&remote_public_id, proof_challenge, proof_signature);
        if (rc != BOWIE_OK) {
            char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            bowie_diag_hex(remote_peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            bowie_diag_json_emit("ERROR", "Handshake", "SIGNATURE_VERIFY_FAILED",
                                  peer_hex, "{\"role\":\"initiator\"}");
            bowie_engine_diag("BowieHandshake", "initiator: responder signature verification failed (%d)", (int)rc);
            return BOWIE_ERR_PERMISSION;
        }
        {
            char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            bowie_diag_hex(remote_peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            bowie_diag_json_emit("INFO", "Handshake", "SIGNATURE_VERIFIED",
                                  peer_hex, "{\"role\":\"initiator\"}");
        }
        int authorized = e->cfg.allow_ungranted_peers || expected_peer != NULL ||
                         presented_grant_matches_owner(e, &remote_sign_pub);
        if (e->cfg.authorize_discovered_peer != NULL)
            authorized = authorized && e->cfg.authorize_discovered_peer(
                e->cfg.authorize_discovered_peer_context, &remote_peer_id);
        authorization_ack = authorized ? 1u : 0u;
        *out_remote_peer = remote_peer_id;
        bowie_engine_diag("BowieHandshake", "initiator: responder identity and signature verified");
        memcpy(&remote_eph_pub.bytes, second + ENGINE_HS_ID_LEN, ENGINE_HS_EPH_LEN);
        memcpy(transcript, first, sizeof(first));
        memcpy(transcript + sizeof(first), second, sizeof(second));
        rc = bowie_proto_stream_write_msg(stream, &authorization_ack,
                                          sizeof(authorization_ack));
        if (rc != BOWIE_OK) return rc;
        if (authorization_ack == 0u) return BOWIE_ERR_PERMISSION;
    } else {
        bowie_engine_diag("BowieHandshake", "responder: waiting for initiator handshake message");
        rc = read_handshake_msg(stream, first);
        if (rc != BOWIE_OK) {
            bowie_engine_diag("BowieHandshake", "responder: initiator message read failed (%d)", (int)rc);
            return rc;
        }
        rc = peer_id_from_public(first, &remote_peer_id);
        if (rc != BOWIE_OK || (expected_peer != NULL &&
            memcmp(remote_peer_id.bytes, expected_peer->bytes, BOWIE_PEER_ID_LEN) != 0)) {
            char expected_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            if (expected_peer != NULL)
                bowie_diag_hex(expected_peer->bytes, BOWIE_PEER_ID_LEN,
                               expected_hex, sizeof(expected_hex));
            else strcpy(expected_hex, "un-pinned");
            bowie_diag_json_emit("WARN", "Handshake", "PEER_ID_MISMATCH",
                                  expected_hex, "{\"role\":\"responder\"}");
            return BOWIE_ERR_PERMISSION;
        }
        memcpy(remote_sign_pub.bytes, first, BOWIE_PUBLIC_ID_LEN);
        signed_len = 0u;
        memcpy(signed_data + signed_len, domain, sizeof(domain)); signed_len += sizeof(domain);
        signed_data[signed_len++] = 0u;
        memcpy(signed_data + signed_len, first, ENGINE_HS_PREFIX_LEN); signed_len += ENGINE_HS_PREFIX_LEN;
        if (expected_peer != NULL)
            memcpy(signed_data + signed_len, e->own_peer_id.bytes, BOWIE_PEER_ID_LEN);
        else
            memset(signed_data + signed_len, 0, BOWIE_PEER_ID_LEN);
        signed_len += BOWIE_PEER_ID_LEN;
        if (room_context_active) {
            memcpy(signed_data + signed_len, room_domain, sizeof(room_domain));
            signed_len += sizeof(room_domain);
            memcpy(signed_data + signed_len, room_context, sizeof(room_context));
            signed_len += sizeof(room_context);
        }
        memcpy(sig.bytes, first + ENGINE_HS_PREFIX_LEN, ENGINE_HS_SIG_LEN);
        bowie_public_id_t remote_public_id;
        bowie_span_t proof_challenge = { signed_data, signed_len };
        bowie_span_t proof_signature = { sig.bytes, sizeof(sig.bytes) };
        memcpy(remote_public_id.bytes, remote_sign_pub.bytes, sizeof(remote_public_id.bytes));
        rc = bowie_ownership_verify(&remote_public_id, proof_challenge, proof_signature);
        if (rc != BOWIE_OK) {
            char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            bowie_diag_hex(remote_peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            bowie_diag_json_emit("ERROR", "Handshake", "SIGNATURE_VERIFY_FAILED",
                                  peer_hex, "{\"role\":\"responder\"}");
            bowie_engine_diag("BowieHandshake", "responder: initiator signature verification failed (%d)", (int)rc);
            return BOWIE_ERR_PERMISSION;
        }
        {
            char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
            bowie_diag_hex(remote_peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            bowie_diag_json_emit("INFO", "Handshake", "SIGNATURE_VERIFIED",
                                  peer_hex, "{\"role\":\"responder\"}");
        }
        int grant_authorized = 0;
        {
            bowie_grant_t grant;
            bowie_wtime_t now = bowie_time_wallclock_ms();
            int has_grant;
            rc = read_owner_grant(stream, &grant);
            if (rc != BOWIE_OK) return send_grant_denial(stream);
            has_grant = !bowie_peer_id_is_zero(&grant.subject);
            if (!e->cfg.allow_ungranted_peers && !has_grant)
                return send_grant_denial(stream);
            if (has_grant &&
                (!bowie_grant_matches_issuer(&grant, &e->own_public_id) ||
                 !bowie_grant_matches_subject(&grant, &remote_peer_id) ||
                 !bowie_grant_is_time_valid(&grant, now) ||
                 !bowie_grant_allows(&grant, BOWIE_GRANT_INTERNET_USE) ||
                 engine_grant_is_revoked(e, &grant.grant_id) ||
                 bowie_grant_verify(&grant) != BOWIE_OK))
                return send_grant_denial(stream);
            if (has_grant && grant.max_egress_bytes != 0u) {
                int slot;
                int exhausted;
                pthread_mutex_lock(&e->lock);
                slot = engine_grant_usage_slot(e, &grant);
                exhausted = slot < 0 ||
                    e->grant_usage[slot].bytes_used >= grant.max_egress_bytes;
                pthread_mutex_unlock(&e->lock);
                if (exhausted) return send_grant_denial(stream);
            }
            if (has_grant && out_owner_grant != NULL) *out_owner_grant = grant;
            grant_authorized = has_grant;
        }
        int authorized = e->cfg.allow_ungranted_peers || grant_authorized ||
                         expected_peer != NULL;
        if (e->cfg.authorize_discovered_peer != NULL)
            authorized = authorized && e->cfg.authorize_discovered_peer(
                e->cfg.authorize_discovered_peer_context, &remote_peer_id);
        authorization_ack = authorized ? 1u : 0u;
        *out_remote_peer = remote_peer_id;
        bowie_engine_diag("BowieHandshake", "responder: initiator identity and signature verified");

        rc = bowie_security_keypair_generate(&local_eph_pub, &local_eph_priv);
        if (rc != BOWIE_OK) return rc;
        memcpy(second, e->own_public_id.bytes, ENGINE_HS_ID_LEN);
        memcpy(second + ENGINE_HS_ID_LEN, local_eph_pub.bytes, ENGINE_HS_EPH_LEN);
        rc = bowie_rand_secure_bytes(second + ENGINE_HS_ID_LEN + ENGINE_HS_EPH_LEN,
                                     ENGINE_HS_NONCE_LEN);
        if (rc != BOWIE_OK) return rc;
        signed_len = 0u;
        memcpy(signed_data + signed_len, domain, sizeof(domain)); signed_len += sizeof(domain);
        signed_data[signed_len++] = 1u;
        memcpy(signed_data + signed_len, first, sizeof(first)); signed_len += sizeof(first);
        memcpy(signed_data + signed_len, second, ENGINE_HS_PREFIX_LEN); signed_len += ENGINE_HS_PREFIX_LEN;
        if (room_context_active) {
            memcpy(signed_data + signed_len, room_domain, sizeof(room_domain));
            signed_len += sizeof(room_domain);
            memcpy(signed_data + signed_len, room_context, sizeof(room_context));
            signed_len += sizeof(room_context);
        }
        rc = bowie_security_sign(&e->own_sign_priv, signed_data, signed_len, &sig);
        if (rc != BOWIE_OK) return rc;
        memcpy(second + ENGINE_HS_PREFIX_LEN, sig.bytes, ENGINE_HS_SIG_LEN);
        bowie_engine_diag("BowieHandshake", "responder: sending signed response (%u bytes)",
                          (unsigned)sizeof(second));
        rc = bowie_proto_stream_write_msg(stream, second, sizeof(second));
        if (rc != BOWIE_OK) {
            bowie_engine_diag("BowieHandshake", "responder: response send failed (%d)", (int)rc);
            return rc;
        }
        rc = read_authorization_ack(stream, &authorization_ack);
        if (rc != BOWIE_OK || authorization_ack != 1u) {
            bowie_engine_diag("BowieHandshake", "responder: initiator did not authorize the verified identity");
            return rc == BOWIE_OK ? BOWIE_ERR_PERMISSION : rc;
        }
        bowie_engine_diag("BowieHandshake", "responder: authenticated exchange complete");
        memcpy(&remote_eph_pub.bytes, first + ENGINE_HS_ID_LEN, ENGINE_HS_EPH_LEN);
        memcpy(transcript, first, sizeof(first));
        memcpy(transcript + sizeof(first), second, sizeof(second));
    }

    rc = bowie_security_keypair_shared(&local_eph_priv, &remote_eph_pub, out_shared);
    memset(&local_eph_priv, 0, sizeof(local_eph_priv));
    return rc;
}

/*
 * ============================================================================
 * LIFECYCLE — DEFAULTS
 * ============================================================================
 */

void bowie_engine_default_config(bowie_engine_config_t *cfg)
{
    if (cfg == NULL) return;

    memset(cfg, 0, sizeof(*cfg));
    cfg->dht_port       = 0;
    cfg->signal_backend = BOWIE_SIGNAL_BACKEND_UDP;
    cfg->signal_metered_api_key = NULL;
    cfg->signal_metered_channel = NULL;
    cfg->nat_port       = 0;
    cfg->allow_server   = 0;
    cfg->stun_host      = NULL;
    cfg->stun_port      = 0;
    cfg->turn_host      = NULL;
    cfg->turn_port      = 0;
    cfg->turn_user      = NULL;
    cfg->turn_pass      = NULL;
    cfg->signal_relay_host = NULL;
    cfg->signal_relay_port = 0;
    cfg->tunnel_mtu     = 0;
}

/*
 * ============================================================================
 * LIFECYCLE — NEW
 * ============================================================================
 */

bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg, bowie_engine_t **out)
{
    bowie_engine_t *e;
    bowie_error_t   rc;

    if (out == NULL) return BOWIE_ERR_NULL_ARG;
    *out = NULL;
    if (cfg != NULL && cfg->bootstrap_count > BOWIE_DHT_BOOTSTRAP_MAX)
        return BOWIE_ERR_TOO_LARGE;
    if (cfg != NULL && cfg->signal_backend != BOWIE_SIGNAL_BACKEND_UDP &&
        cfg->signal_backend != BOWIE_SIGNAL_BACKEND_METERED)
        return BOWIE_ERR_INVAL;
    if (cfg != NULL && cfg->signal_backend == BOWIE_SIGNAL_BACKEND_METERED &&
        (cfg->signal_metered_api_key == NULL || cfg->signal_metered_channel == NULL ||
         cfg->signal_metered_api_key[0] == '\0' || cfg->signal_metered_channel[0] == '\0' ||
         strnlen(cfg->signal_metered_api_key, BOWIE_ENGINE_METERED_KEY_MAX) >= BOWIE_ENGINE_METERED_KEY_MAX ||
         strnlen(cfg->signal_metered_channel, BOWIE_ENGINE_METERED_CHANNEL_MAX) >= BOWIE_ENGINE_METERED_CHANNEL_MAX))
        return BOWIE_ERR_INVAL;
    if (cfg != NULL && ((cfg->signal_relay_host == NULL) !=
                        (cfg->signal_relay_port == 0u)))
        return BOWIE_ERR_INVAL;
    if (cfg != NULL && cfg->signal_relay_host != NULL &&
        (cfg->signal_relay_host[0] == '\0' ||
         strnlen(cfg->signal_relay_host, BOWIE_ENGINE_SIGNAL_RELAY_HOST_MAX) >=
             BOWIE_ENGINE_SIGNAL_RELAY_HOST_MAX))
        return BOWIE_ERR_INVAL;

    e = (bowie_engine_t *)calloc(1, sizeof(*e));
    if (e == NULL) return BOWIE_ERR_NOMEM;

    {
        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr) != 0) { free(e); return BOWIE_ERR_INTERNAL; }
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        if (pthread_mutex_init(&e->lock, &attr) != 0) {
            pthread_mutexattr_destroy(&attr); free(e); return BOWIE_ERR_INTERNAL;
        }
        pthread_mutexattr_destroy(&attr);
    }

    if (pthread_cond_init(&e->nat_cond, NULL) != 0) {
        pthread_mutex_destroy(&e->lock); free(e); return BOWIE_ERR_INTERNAL;
    }

    if (cfg != NULL) e->cfg = *cfg;
    else bowie_engine_default_config(&e->cfg);
    if (e->cfg.signal_relay_host != NULL) {
        (void)snprintf(e->signal_relay_host, sizeof(e->signal_relay_host), "%s",
                       e->cfg.signal_relay_host);
        e->cfg.signal_relay_host = e->signal_relay_host;
    }
    if (e->cfg.signal_metered_api_key != NULL) {
        (void)snprintf(e->signal_metered_key, sizeof(e->signal_metered_key), "%s",
                       e->cfg.signal_metered_api_key);
        e->cfg.signal_metered_api_key = e->signal_metered_key;
    }
    if (e->cfg.signal_metered_channel != NULL) {
        (void)snprintf(e->signal_metered_channel, sizeof(e->signal_metered_channel), "%s",
                       e->cfg.signal_metered_channel);
        e->cfg.signal_metered_channel = e->signal_metered_channel;
    }

    if (e->cfg.identity_seed != NULL) {
        rc = bowie_security_sign_from_seed(e->cfg.identity_seed,
                                           &e->own_sign_pub,
                                           &e->own_sign_priv);
    } else {
        rc = bowie_security_sign_generate(&e->own_sign_pub, &e->own_sign_priv);
    }
    /* The caller only needs to keep the optional key alive through new(). */
    e->cfg.identity_seed = NULL;
    if (rc != BOWIE_OK) {
        pthread_cond_destroy(&e->nat_cond); pthread_mutex_destroy(&e->lock); free(e); return rc;
    }

    rc = derive_ids(e);
    if (rc != BOWIE_OK) {
        pthread_cond_destroy(&e->nat_cond); pthread_mutex_destroy(&e->lock); free(e); return rc;
    }

    e->state = BOWIE_ENGINE_STOPPED;
    e->active_quota_slot = -1;
    bowie_revoke_list_clear(&e->revoke_list);
    bowie_engine_event_queue_clear(&e->events);

    e->signal_fd   = -1;
    e->signal_port = 0;

    if (pthread_create(&e->quota_monitor_thread, NULL, engine_quota_monitor, e) != 0) {
        pthread_cond_destroy(&e->nat_cond);
        pthread_mutex_destroy(&e->lock);
        free(e);
        return BOWIE_ERR_INTERNAL;
    }
    e->quota_monitor_started = 1;

    *out = e;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * LIFECYCLE — FREE
 * ============================================================================
 */

void bowie_engine_free(bowie_engine_t *e)
{
    if (e == NULL) return;
    if (e->state != BOWIE_ENGINE_STOPPED) (void)bowie_engine_stop(e);

    __atomic_store_n(&e->quota_monitor_stop, 1, __ATOMIC_RELEASE);
    pthread_cond_signal(&e->nat_cond);
    if (e->quota_monitor_started) pthread_join(e->quota_monitor_thread, NULL);

    memset(&e->own_sign_priv, 0, sizeof(e->own_sign_priv));
    pthread_cond_destroy(&e->nat_cond);
    pthread_mutex_destroy(&e->lock);
    free(e);
}

/*
 * ============================================================================
 * LIFECYCLE — START
 * ============================================================================
 */

bowie_error_t bowie_engine_start(bowie_engine_t *e, bowie_tun_t *tun)
{
    bowie_dht_config_t  dht_cfg;
    bowie_nat_config_t  nat_cfg;
    bowie_error_t       rc;

    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    if (e->state != BOWIE_ENGINE_STOPPED) return BOWIE_ERR_STATE;
    pthread_mutex_lock(&e->lock);

    make_dht_config(&e->cfg, &dht_cfg);

    e->dht = (bowie_dht_t *)calloc(1, sizeof(*e->dht));
    if (e->dht == NULL) { pthread_mutex_unlock(&e->lock); return BOWIE_ERR_NOMEM; }

    e->dht_hashes = (bowie_dht_hash_entry_t *)calloc(BOWIE_ENGINE_DHT_HASHES_CAP, sizeof(*e->dht_hashes));
    e->dht_peers  = (bowie_dht_peer_entry_t *)calloc(BOWIE_ENGINE_DHT_PEERS_CAP, sizeof(*e->dht_peers));
    e->dht_rate_limits = (bowie_dht_rate_limit_t *)calloc(BOWIE_ENGINE_DHT_RATE_LIMIT_CAP, sizeof(*e->dht_rate_limits));

    if (!e->dht_hashes || !e->dht_peers || !e->dht_rate_limits) {
        rc = BOWIE_ERR_NOMEM;
        goto fail_dht_alloc;
    }

    rc = bowie_dht_init(e->dht, &dht_cfg, &e->own_dht_id,
                        e->dht_hashes, BOWIE_ENGINE_DHT_HASHES_CAP,
                        e->dht_peers, BOWIE_ENGINE_DHT_PEERS_CAP, NULL,
                        e->dht_rate_limits, BOWIE_ENGINE_DHT_RATE_LIMIT_CAP,
                        bowie_time_monotonic_ms());
    if (rc != BOWIE_OK) goto fail_dht_alloc;

    rc = bowie_dht_start(e->dht, e->cfg.dht_port);
    if (rc != BOWIE_OK) goto fail_dht_alloc;

    e->dht_port = e->cfg.dht_port;

    make_nat_config(&e->cfg, &nat_cfg);

    rc = bowie_nat_new(&nat_cfg, &e->nat);
    if (rc != BOWIE_OK) goto fail_dht;

    rc = bowie_nat_start(e->nat);
    if (rc != BOWIE_OK) goto fail_nat;

    rc = bowie_engine_signal_open(e, e->cfg.nat_port);
    if (rc != BOWIE_OK) goto fail_nat_started;

    {
        bowie_dht_info_hash_t announce_hash;
        memcpy(announce_hash.bytes, e->own_peer_id.bytes,
               sizeof(announce_hash.bytes));
        rc = bowie_dht_set_announce(e->dht, &announce_hash, e->signal_port);
        if (rc != BOWIE_OK) goto fail_signal;
    }

    e->tun   = tun;
    e->state = BOWIE_ENGINE_STARTED;

    pthread_mutex_unlock(&e->lock);
    ENGINE_LOG(BOWIE_LOG_INFO, "engine started (dht port %u, signal port %u)", e->dht_port, e->signal_port);
    return BOWIE_OK;

fail_signal:
    bowie_engine_signal_close(e);

fail_nat_started:
    (void)bowie_nat_stop(e->nat);
fail_nat:
    bowie_nat_free(e->nat); e->nat = NULL;
fail_dht:
    (void)bowie_dht_stop(e->dht);
fail_dht_alloc:
    if (e->dht != NULL) { bowie_dht_shutdown(e->dht); free(e->dht); e->dht = NULL; }
    free(e->dht_hashes);      e->dht_hashes      = NULL;
    free(e->dht_peers);       e->dht_peers       = NULL;
    free(e->dht_rate_limits); e->dht_rate_limits = NULL;

    e->state = BOWIE_ENGINE_STOPPED;
    pthread_mutex_unlock(&e->lock);
    return rc;
}

/*
 * ============================================================================
 * LIFECYCLE — STOP
 * ============================================================================
 */

bowie_error_t bowie_engine_stop(bowie_engine_t *e)
{
    if (e == NULL) return BOWIE_ERR_NULL_ARG;

    pthread_mutex_lock(&e->lock);
    if (e->state == BOWIE_ENGINE_STOPPED) { pthread_mutex_unlock(&e->lock); return BOWIE_OK; }

    bowie_engine_signal_close(e);

    if (e->nat != NULL && e->nat_connected != 0) {
        (void)bowie_nat_disconnect(e->nat);
        e->nat_connected = 0;
    }

    if (e->gateway != NULL) {
        (void)bowie_gateway_stop(e->gateway);
        bowie_gateway_close(e->gateway);
        e->gateway = NULL;
    }

    if (e->session != NULL) { bowie_session_free(e->session); e->session = NULL; }

    if (e->nat != NULL) {
        if (e->nat_connected != 0) (void)bowie_nat_disconnect(e->nat);
        (void)bowie_nat_stop(e->nat);
        bowie_nat_free(e->nat);
        e->nat = NULL;
    }

    if (e->dht != NULL) {
        (void)bowie_dht_stop(e->dht);
        bowie_dht_shutdown(e->dht);
        free(e->dht);
        e->dht = NULL;
    }

    free(e->dht_hashes);      e->dht_hashes      = NULL;
    free(e->dht_peers);       e->dht_peers       = NULL;
    free(e->dht_rate_limits); e->dht_rate_limits = NULL;

    e->nat_connected = 0; e->pending_offer = 0; e->inbound_offer = 0; e->peer_signal_addr_valid = 0;
    e->state = BOWIE_ENGINE_STOPPED;
    e->tun   = NULL;

    pthread_mutex_unlock(&e->lock);
    ENGINE_LOG(BOWIE_LOG_INFO, "engine stopped");
    return BOWIE_OK;
}

/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 */

static bowie_error_t engine_search_hash(bowie_engine_t *e,
                                        const bowie_dht_info_hash_t *info_hash,
                                        bowie_dht_node_t *out_node,
                                        uint32_t timeout_ms,
                                        int exclude_self)
{
    bowie_dht_node_id_t target;
    bowie_dht_node_id_t queried[BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES];
    size_t queried_count = 0u;
    bowie_mtime_t deadline_ms;
    bowie_mtime_t last_query_ms = 0u;
    bowie_error_t rc = BOWIE_ERR_NOT_FOUND;

    if (e == NULL || info_hash == NULL || out_node == NULL) return BOWIE_ERR_NULL_ARG;

    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_STARTED && e->state != BOWIE_ENGINE_RUNNING) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_NOT_STARTED;
    }

    memcpy(target.bytes, info_hash->bytes, BOWIE_DHT_NODE_ID_LEN);
    if (timeout_ms == 0) timeout_ms = BOWIE_ENGINE_SEARCH_DEFAULT_TIMEOUT_MS;
    deadline_ms = bowie_time_monotonic_ms() + (bowie_mtime_t)timeout_ms;

    while (bowie_time_monotonic_ms() < deadline_ms &&
           queried_count < BOWIE_DHT_SEARCH_DEFAULT_MAX_QUERIES) {
        bowie_dht_peer_entry_t peers[16];
        bowie_dht_node_t candidates[BOWIE_DHT_K * 4];
        bowie_dht_node_t next;
        size_t peer_count = 0u, candidate_count = 0u;
        int found_next = 0;
        bowie_mtime_t now_ms = bowie_time_monotonic_ms();

        pthread_mutex_lock(&e->dht->state_lock);
        bowie_error_t peer_rc = bowie_dht_storage_find_peers(
            &e->dht->storage, info_hash, peers, NULL,
            sizeof(peers) / sizeof(peers[0]), &peer_count);
        if (peer_rc == BOWIE_OK && peer_count > 0u) {
            for (size_t i = 0u; i < peer_count; i++) {
                if (exclude_self && peers[i].addr.port == e->signal_port) continue;
                memset(out_node, 0, sizeof(*out_node));
                out_node->id = target;
                out_node->addr = peers[i].addr;
                out_node->last_seen_ms = peers[i].last_seen_ms;
                pthread_mutex_unlock(&e->dht->state_lock);
                pthread_mutex_unlock(&e->lock);
                return BOWIE_OK;
            }
        }

        (void)bowie_dht_routing_select_closest(&e->dht->routing, &target,
                                                now_ms, candidates,
                                                sizeof(candidates) / sizeof(candidates[0]),
                                                &candidate_count);
        pthread_mutex_unlock(&e->dht->state_lock);

        for (size_t i = 0u; i < candidate_count; i++) {
            int already_queried = 0;
            for (size_t j = 0u; j < queried_count; j++) {
                if (bowie_dht_node_id_equal(&candidates[i].id, &queried[j])) {
                    already_queried = 1;
                    break;
                }
            }
            if (!already_queried) {
                next = candidates[i];
                found_next = 1;
                break;
            }
        }

        if (found_next) {
            uint8_t tid[BOWIE_DHT_MSG_TID_MAX];
            bowie_dht_message_t query;
            rc = bowie_rand_secure_bytes(tid, sizeof(tid));
            if (rc == BOWIE_OK) {
                rc = bowie_dht_make_query(e->dht, BOWIE_DHT_QUERY_GET_PEERS,
                                          NULL, info_hash, tid, sizeof(tid),
                                          &query);
            }
            if (rc == BOWIE_OK) rc = bowie_dht_send_query(e->dht, &next.addr, &query);
            if (rc == BOWIE_OK) {
                queried[queried_count++] = next.id;
                last_query_ms = now_ms;
            }
        } else if (queried_count > 0u && now_ms - last_query_ms >= 1500u) {
            rc = BOWIE_ERR_NOT_FOUND;
            break;
        }

        struct timespec pause = { 0, 50000000L };
        nanosleep(&pause, NULL);
    }

    pthread_mutex_unlock(&e->lock);
    return BOWIE_ERR_NOT_FOUND;
}

static bowie_error_t engine_room_hash(const char *room,
                                      bowie_dht_info_hash_t *hash)
{
    bowie_hash_sha1_t digest;
    if (room == NULL || hash == NULL || room[0] == '\0' ||
        strnlen(room, 256u) >= 256u) return BOWIE_ERR_INVAL;
    bowie_error_t rc = bowie_hash_sha1(room, strlen(room), &digest);
    if (rc == BOWIE_OK) memcpy(hash->bytes, digest.bytes, sizeof(hash->bytes));
    return rc;
}

bowie_error_t bowie_engine_search_peer(bowie_engine_t *e,
                                       const bowie_peer_id_t *peer_id,
                                       bowie_dht_node_t *out_node,
                                       uint32_t timeout_ms)
{
    bowie_dht_info_hash_t hash;
    if (peer_id == NULL) return BOWIE_ERR_NULL_ARG;
    memcpy(hash.bytes, peer_id->bytes, sizeof(hash.bytes));
    return engine_search_hash(e, &hash, out_node, timeout_ms, 0);
}

bowie_error_t bowie_engine_announce_room(bowie_engine_t *e,
                                         const char *room)
{
    bowie_dht_info_hash_t hash;
    bowie_error_t rc;
    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    rc = engine_room_hash(room, &hash);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_dht_set_announce(e->dht, &hash, e->signal_port);
    if (rc == BOWIE_OK) {
        pthread_mutex_lock(&e->lock);
        e->announced_room_hash = hash;
        e->room_announced = 1;
        pthread_mutex_unlock(&e->lock);
    }
    return rc;
}

bowie_error_t bowie_engine_discover_room(bowie_engine_t *e,
                                         const char *room,
                                         bowie_dht_node_t *out_node,
                                         uint32_t timeout_ms)
{
    bowie_dht_info_hash_t hash;
    bowie_error_t rc = engine_room_hash(room, &hash);
    if (rc != BOWIE_OK) return rc;
    return engine_search_hash(e, &hash, out_node, timeout_ms, 1);
}

/*
 * ============================================================================
 * INTERNAL — CALLBACKS & HANDLERS
 * ============================================================================
 */

static bowie_error_t engine_on_nat_signal(void *ctx, const bowie_peer_id_t *peer, const uint8_t *data, size_t len)
{
    bowie_engine_t *e = (bowie_engine_t *)ctx;
    bowie_addr_t    to;
    (void)peer;

    if (e == NULL) return BOWIE_ERR_NULL_ARG;

    pthread_mutex_lock(&e->lock);
    if (!e->peer_signal_addr_valid) {
        pthread_mutex_unlock(&e->lock);
        bowie_engine_diag("BowieEngine", "cannot send NAT signaling: remote signaling endpoint is not known yet");
        return BOWIE_ERR_STATE;
    }
    memset(&to, 0, sizeof(to));
    to.family = BOWIE_AF_INET;
    memcpy(to.addr, &e->peer_signal_addr.sin_addr, 4);
    to.port = ntohs(e->peer_signal_addr.sin_port);
    pthread_mutex_unlock(&e->lock);

    if (e->cfg.prepare_underlay_address != NULL &&
        !e->cfg.prepare_underlay_address(e->cfg.underlay_context, AF_INET,
                                         to.addr, 4u))
        return BOWIE_ERR_NETWORK;

    bowie_error_t rc = bowie_engine_signal_send(e, &to, data, len);
    bowie_engine_diag("BowieEngine", "NAT signaling payload %zu bytes -> %u.%u.%u.%u:%u (rc=%d)",
                      len, to.addr[0], to.addr[1], to.addr[2], to.addr[3],
                      (unsigned)to.port, (int)rc);
    return rc;
}

static void engine_on_nat_state(void *ctx, bowie_nat_state_t state)
{
    bowie_engine_t *e = (bowie_engine_t *)ctx;
    if (e == NULL) return;
    bowie_engine_diag("BowieEngine", "ICE state callback: %d", (int)state);
    pthread_mutex_lock(&e->lock);
    if (state == BOWIE_NAT_STATE_CONNECTED || state == BOWIE_NAT_STATE_COMPLETED) {
        e->nat_connected = 1;
        pthread_cond_broadcast(&e->nat_cond);
    } else if (state == BOWIE_NAT_STATE_FAILED) {
        e->nat_connected = -1;
        pthread_cond_broadcast(&e->nat_cond);
    }
    pthread_mutex_unlock(&e->lock);
}

static bowie_error_t wait_for_nat(bowie_engine_t *e, bowie_mtime_t deadline_ms)
{
    bowie_engine_diag("BowieEngine", "waiting for ICE connection (state=%d)", e->nat_connected);
    while (e->nat_connected == 0) {
        struct timespec ts;
        bowie_mtime_t   now_ms = bowie_time_monotonic_ms();
        if (now_ms >= deadline_ms) {
            bowie_engine_diag("BowieEngine", "ICE connection timed out (state=%d)", e->nat_connected);
            {
                char details[64];
                (void)snprintf(details, sizeof(details),
                               "{\"state\":%d}", e->nat_connected);
                bowie_diag_json_emit("WARN", "ICE", "ICE_CONNECT_TIMEOUT", NULL, details);
            }
            return BOWIE_ERR_TIMEOUT;
        }
        bowie_mtime_t remain_ms = deadline_ms - now_ms;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(remain_ms / 1000u);
        ts.tv_nsec += (long)((remain_ms % 1000u) * 1000000L);
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        (void)pthread_cond_timedwait(&e->nat_cond, &e->lock, &ts);
    }
    bowie_engine_diag("BowieEngine", "ICE wait finished (state=%d)", e->nat_connected);
    return (e->nat_connected == 1) ? BOWIE_OK : BOWIE_ERR_NETWORK;
}

static int nat_ice_is_active(bowie_nat_state_t state)
{
    return state == BOWIE_NAT_STATE_GATHERING ||
           state == BOWIE_NAT_STATE_CONNECTING ||
           state == BOWIE_NAT_STATE_CONNECTED ||
           state == BOWIE_NAT_STATE_COMPLETED;
}

static const char *nat_ice_state_name(bowie_nat_state_t state)
{
    switch (state) {
    case BOWIE_NAT_STATE_DISCONNECTED: return "DISCONNECTED";
    case BOWIE_NAT_STATE_GATHERING: return "GATHERING";
    case BOWIE_NAT_STATE_CONNECTING: return "CONNECTING";
    case BOWIE_NAT_STATE_CONNECTED: return "CONNECTED";
    case BOWIE_NAT_STATE_COMPLETED: return "COMPLETED";
    case BOWIE_NAT_STATE_FAILED: return "FAILED";
    default: return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * CONNECT
 * ============================================================================
 */

static bowie_error_t engine_connect_node(bowie_engine_t *e,
                                         const bowie_peer_id_t *peer,
                                         const bowie_dht_node_t *node,
                                         uint32_t timeout_ms)
{
    bowie_mtime_t       deadline_ms;
    bowie_error_t       rc;
    const char         *stage = "validating connection state";
    bowie_peer_id_t     authenticated_peer;

    if (e == NULL || node == NULL) return BOWIE_ERR_NULL_ARG;
    if (timeout_ms == 0) timeout_ms = BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS;

    if (e->cfg.signal_backend == BOWIE_SIGNAL_BACKEND_METERED &&
        e->metered != NULL) {
        bowie_engine_diag("BowieEngine", "waiting for Metered ICE server setup");
        if (bowie_metered_wait_ice_servers(e->metered, 10000u) != 0) {
            bowie_engine_diag("BowieEngine", "Metered ICE server setup timed out");
            return BOWIE_ERR_TIMEOUT;
        }
        bowie_engine_diag("BowieEngine", "Metered ICE server setup ready");
    }

    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_STARTED) { pthread_mutex_unlock(&e->lock); return BOWIE_ERR_STATE; }
    rc = bowie_engine_state_set(e, BOWIE_ENGINE_CONNECTING);
    if (rc != BOWIE_OK) { pthread_mutex_unlock(&e->lock); return rc; }
    pthread_mutex_unlock(&e->lock);

    /* Setup signaling address and NAT */
    pthread_mutex_lock(&e->lock);
    memset(&e->peer_signal_addr, 0, sizeof(e->peer_signal_addr));
    e->peer_signal_addr.sin_family = AF_INET;
    memcpy(&e->peer_signal_addr.sin_addr, node->addr.addr, 4);
    e->peer_signal_addr.sin_port = htons(node->addr.port);
    e->peer_signal_addr_valid = 1;

    bowie_peer_clear(&e->peer);
    if (peer != NULL) bowie_peer_set_id(&e->peer, peer);
    bowie_peer_set_endpoint(&e->peer, &(bowie_endpoint_t){ .addr = node->addr, .transport = 0 });

    (void)bowie_nat_set_signal(e->nat, engine_on_nat_signal, e);
    (void)bowie_nat_set_state_cb(e->nat, engine_on_nat_state, e);
    e->nat_connected  = 0;
    e->pending_offer  = 1;
    deadline_ms = bowie_time_monotonic_ms() + timeout_ms;
    pthread_mutex_unlock(&e->lock);

    stage = "starting ICE and sending local signaling";
    bowie_engine_diag("BowieEngine", "connect target %u.%u.%u.%u:%u, timeout=%u ms",
                      node->addr.addr[0], node->addr.addr[1], node->addr.addr[2], node->addr.addr[3],
                      (unsigned)node->addr.port, (unsigned)timeout_ms);
    {
        bowie_addr_t peer_addr = node->addr;
        rc = bowie_nat_connect(e->nat, &peer_addr, timeout_ms);
    }
    if (rc != BOWIE_OK) goto fail_nat_connected;

    stage = "waiting for ICE connection";
    pthread_mutex_lock(&e->lock);
    rc = wait_for_nat(e, deadline_ms);
    e->pending_offer = 0;
    pthread_mutex_unlock(&e->lock);
    if (rc != BOWIE_OK) goto fail_nat_connected;

    /* Step 3 & 4: X25519 Exchange & Session Creation */
    {
        bowie_proto_stream_t stream;
        bowie_keypair_shared_t  shared;
        uint8_t                 key_material[BOWIE_SESSION_KEY_LEN * 2u];
        uint8_t                 transcript[ENGINE_HS_TRANSCRIPT_LEN];
        const uint8_t          *tx_key;
        const uint8_t          *rx_key;
        bowie_session_id_t      session_id;

        stage = "initializing authenticated handshake stream";
        bowie_engine_diag("BowieEngine", "ICE connected; starting authenticated handshake as initiator");
        rc = bowie_proto_stream_init(&stream, e->nat);
        if (rc != BOWIE_OK) goto fail_nat_connected;
        
        (void)bowie_nat_set_recv(e->nat, bowie_proto_stream_on_nat_data, &stream);

        stage = "exchanging and verifying peer identity";
        rc = exchange_authenticated(e, &stream, peer, 1, &shared, transcript,
                                    &authenticated_peer, NULL);
        if (rc != BOWIE_OK) { destroy_handshake_stream(e, &stream); goto fail_nat_connected; }

        stage = "deriving session keys";
        rc = bowie_security_kdf_hkdf_sha256(shared.bytes, BOWIE_KEYPAIR_SHARED_LEN,
                                            transcript, sizeof(transcript),
                                            kSessionInfo, sizeof(kSessionInfo) - 1,
                                            key_material, sizeof(key_material));
        if (rc != BOWIE_OK) { destroy_handshake_stream(e, &stream); goto fail_nat_connected; }

        tx_key = key_material;
        rx_key = key_material + BOWIE_SESSION_KEY_LEN;

        rc = bowie_rand_secure_bytes(session_id.bytes, BOWIE_SESSION_ID_LEN);
        if (rc == BOWIE_OK) {
            rc = bowie_session_new_from_keys(tx_key, rx_key, &session_id, &e->session);
        }
        memset(key_material, 0, sizeof(key_material));
        memset(transcript, 0, sizeof(transcript));
        memset(&shared, 0, sizeof(shared));
        destroy_handshake_stream(e, &stream);
        if (rc != BOWIE_OK) goto fail_nat_connected;
    }

    if (peer == NULL) {
        bowie_peer_clear(&e->peer);
        bowie_peer_set_id(&e->peer, &authenticated_peer);
    }

    /* The caller's peer ID is the explicit authorization pin for this session. */
    if (e->tun != NULL) {
        stage = "starting packet gateway";
        bowie_engine_diag("BowieEngine", "peer authenticated; starting packet gateway");
        bowie_gateway_config_t gw_cfg;
        bowie_gateway_default_config(&gw_cfg);
        gw_cfg.mtu = e->cfg.tunnel_mtu;
        e->gateway_source = 0;
        rc = bowie_gateway_open(&e->gateway, &gw_cfg, e->tun);
        if (rc != BOWIE_OK) goto fail_session;
        rc = bowie_gateway_start(e->gateway, e->session, e->nat);
        if (rc != BOWIE_OK) { bowie_gateway_close(e->gateway); e->gateway = NULL; goto fail_session; }
    }

    pthread_mutex_lock(&e->lock);
    e->state = BOWIE_ENGINE_RUNNING;
    pthread_mutex_unlock(&e->lock);
    ENGINE_LOG(BOWIE_LOG_INFO, "connected to peer");
    return BOWIE_OK;

fail_session:
    bowie_session_free(e->session); e->session = NULL;
fail_nat_connected:
    bowie_engine_diag("BowieEngine", "connect failed during %s (error %d)", stage, (int)rc);
    (void)bowie_nat_disconnect(e->nat);
    pthread_mutex_lock(&e->lock); e->pending_offer = 0; e->nat_connected = 0; pthread_mutex_unlock(&e->lock);
    pthread_mutex_lock(&e->lock); (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED); pthread_mutex_unlock(&e->lock);
    return rc;
}

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms)
{
    bowie_dht_node_t node;
    bowie_error_t rc;

    if (e == NULL || peer == NULL) return BOWIE_ERR_NULL_ARG;
    rc = bowie_engine_search_peer(e, peer, &node, timeout_ms);
    if (rc != BOWIE_OK) return rc;
    return engine_connect_node(e, peer, &node, timeout_ms);
}

bowie_error_t bowie_engine_connect_room(bowie_engine_t *e,
                                        const char *room,
                                        uint32_t timeout_ms)
{
    bowie_dht_node_t node;
    bowie_dht_info_hash_t room_hash;
    bowie_error_t rc;
    int has_grant;
    if (e == NULL || room == NULL) return BOWIE_ERR_NULL_ARG;
    pthread_mutex_lock(&e->lock);
    has_grant = e->has_presented_grant;
    pthread_mutex_unlock(&e->lock);
    if (!e->cfg.allow_ungranted_peers && !has_grant)
        return BOWIE_ERR_PERMISSION;
    rc = engine_room_hash(room, &room_hash);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_engine_discover_room(e, room, &node, timeout_ms);
    if (rc != BOWIE_OK) return rc;
    pthread_mutex_lock(&e->lock);
    e->active_room_hash = room_hash;
    e->active_room = 1;
    pthread_mutex_unlock(&e->lock);
    rc = engine_connect_node(e, NULL, &node, timeout_ms);
    pthread_mutex_lock(&e->lock);
    e->active_room = 0;
    memset(&e->active_room_hash, 0, sizeof(e->active_room_hash));
    pthread_mutex_unlock(&e->lock);
    return rc;
}

bowie_error_t bowie_engine_connect_direct(bowie_engine_t *e,
                                          const bowie_peer_id_t *peer,
                                          const bowie_addr_t *signal_addr,
                                          uint32_t timeout_ms)
{
    bowie_dht_node_t node;

    if (e == NULL || peer == NULL || signal_addr == NULL) return BOWIE_ERR_NULL_ARG;
    if (signal_addr->family != BOWIE_AF_INET || signal_addr->port == 0u) return BOWIE_ERR_INVAL;

    memset(&node, 0, sizeof(node));
    memcpy(node.id.bytes, peer->bytes, BOWIE_DHT_NODE_ID_LEN);
    node.addr = *signal_addr;
    node.last_seen_ms = bowie_time_monotonic_ms();
    return engine_connect_node(e, peer, &node, timeout_ms);
}

bowie_error_t bowie_engine_connect_relay(bowie_engine_t *e,
                                        const bowie_peer_id_t *peer,
                                        uint32_t timeout_ms)
{
    bowie_dht_node_t node;
    if (e == NULL || peer == NULL) return BOWIE_ERR_NULL_ARG;
    if (e->cfg.signal_backend != BOWIE_SIGNAL_BACKEND_METERED &&
        (e->cfg.signal_relay_host == NULL || e->cfg.signal_relay_port == 0u))
        return BOWIE_ERR_STATE;
    memset(&node, 0, sizeof(node));
    memcpy(node.id.bytes, peer->bytes, BOWIE_DHT_NODE_ID_LEN);
    node.addr.family = BOWIE_AF_INET;
    if (e->cfg.signal_backend == BOWIE_SIGNAL_BACKEND_METERED) {
        node.addr.addr[0] = 127u; node.addr.addr[3] = 1u;
        node.addr.port = 1u;
    } else {
        memcpy(node.addr.addr, &e->signal_relay_addr.sin_addr, sizeof(node.addr.addr));
        node.addr.port = ntohs(e->signal_relay_addr.sin_port);
    }
    node.last_seen_ms = bowie_time_monotonic_ms();
    return engine_connect_node(e, peer, &node, timeout_ms);
}

/*
 * ============================================================================
 * ACCEPT
 * ============================================================================
 */

static bowie_error_t engine_accept_expected(bowie_engine_t *e,
                                            const bowie_peer_id_t *expected_peer,
                                            uint32_t timeout_ms)
{
    bowie_mtime_t  deadline_ms;
    bowie_error_t  rc;
    const char    *stage = "validating accept state";
    bowie_peer_id_t authenticated_peer;
    bowie_grant_t owner_grant;
    int quota_slot = -1;
    bowie_grant_clear(&owner_grant);

    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    if (expected_peer != NULL && bowie_peer_id_is_zero(expected_peer)) return BOWIE_ERR_INVAL;
    if (timeout_ms == 0) timeout_ms = BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS;

    if (e->cfg.signal_backend == BOWIE_SIGNAL_BACKEND_METERED &&
        e->metered != NULL) {
        bowie_engine_diag("BowieEngine", "waiting for Metered ICE server setup");
        if (bowie_metered_wait_ice_servers(e->metered, 10000u) != 0) {
            bowie_engine_diag("BowieEngine", "Metered ICE server setup timed out");
            return BOWIE_ERR_TIMEOUT;
        }
        bowie_engine_diag("BowieEngine", "Metered ICE server setup ready");
    }

    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_STARTED) { pthread_mutex_unlock(&e->lock); return BOWIE_ERR_STATE; }
    rc = bowie_engine_state_set(e, BOWIE_ENGINE_CONNECTING);
    if (rc != BOWIE_OK) { pthread_mutex_unlock(&e->lock); return rc; }

    (void)bowie_nat_set_signal(e->nat, engine_on_nat_signal, e);
    (void)bowie_nat_set_state_cb(e->nat, engine_on_nat_state, e);
    e->nat_connected = 0;
    e->inbound_offer = 1;
    if (expected_peer != NULL) e->inbound_peer_id = *expected_peer;
    else memset(&e->inbound_peer_id, 0, sizeof(e->inbound_peer_id));
    bowie_peer_clear(&e->peer);
    if (expected_peer != NULL) bowie_peer_set_id(&e->peer, expected_peer);
    e->peer_signal_addr_valid = 0;
    deadline_ms = bowie_time_monotonic_ms() + timeout_ms;
    pthread_mutex_unlock(&e->lock);

    bowie_engine_diag("BowieEngine", "waiting for incoming authorized peer signal on UDP %u, timeout=%u ms",
                      (unsigned)e->signal_port, (unsigned)timeout_ms);
    {
        char details[80];
        (void)snprintf(details, sizeof(details),
                       "{\"signal_port\":%u,\"timeout_ms\":%u}",
                       (unsigned)e->signal_port, (unsigned)timeout_ms);
        bowie_diag_json_emit("INFO", "Engine", "ACCEPT_WAITING_FOR_SIGNAL", NULL, details);
    }
    stage = "waiting for incoming signaling datagram";
    rc = BOWIE_OK;
    pthread_mutex_lock(&e->lock);
    while (!e->peer_signal_addr_valid) {
        struct timespec ts;
        bowie_mtime_t now_ms = bowie_time_monotonic_ms();
        if (now_ms >= deadline_ms) {
            rc = BOWIE_ERR_TIMEOUT;
            break;
        }
        bowie_mtime_t remain_ms = deadline_ms - now_ms;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(remain_ms / 1000u);
        ts.tv_nsec += (long)((remain_ms % 1000u) * 1000000L);
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        (void)pthread_cond_timedwait(&e->nat_cond, &e->lock, &ts);
    }
    struct sockaddr_in remote_signal_addr = e->peer_signal_addr;
    if (rc == BOWIE_OK && e->peer_signal_addr_valid == 0) rc = BOWIE_ERR_TIMEOUT;
    pthread_mutex_unlock(&e->lock);
    if (rc != BOWIE_OK) goto fail_state;
    bowie_engine_diag("BowieEngine", "accepted signal from %u.%u.%u.%u:%u",
                      (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[0],
                      (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[1],
                      (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[2],
                      (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[3],
                      (unsigned)ntohs(remote_signal_addr.sin_port));
    {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"source_ip\":\"%u.%u.%u.%u\",\"source_port\":%u}",
                       (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[0],
                       (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[1],
                       (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[2],
                       (unsigned)((const uint8_t *)&remote_signal_addr.sin_addr)[3],
                       (unsigned)ntohs(remote_signal_addr.sin_port));
        bowie_diag_json_emit("INFO", "Engine", "SIGNAL_ACCEPTED", NULL, details);
    }

    /* Both libjuice peers gather local ICE candidates. The first
     * incoming description was queued on the initialized agent by
     * the signaling thread; this starts our local gathering. */
    bowie_addr_t remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.family = BOWIE_AF_INET;
    memcpy(remote_addr.addr, &remote_signal_addr.sin_addr, 4);
    remote_addr.port = ntohs(remote_signal_addr.sin_port);
    stage = "starting ICE from incoming peer signal";
    bowie_nat_state_t nat_state = bowie_nat_get_state(e->nat);
    if (nat_ice_is_active(nat_state)) {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"state\":\"%s\",\"state_code\":%d}",
                       nat_ice_state_name(nat_state), (int)nat_state);
        bowie_diag_json_emit("INFO", "Engine", "ACCEPT_ICE_ALREADY_ACTIVE",
                             NULL, details);
        rc = BOWIE_OK;
    } else {
        rc = bowie_nat_connect(e->nat, &remote_addr, timeout_ms);
        /* A remote-description callback can start ICE between the state
         * snapshot and connect(). Treat BUSY as success only when the NAT
         * backend now confirms an active ICE state. */
        if (rc == BOWIE_ERR_BUSY) {
            nat_state = bowie_nat_get_state(e->nat);
            if (nat_ice_is_active(nat_state)) {
                char details[96];
                (void)snprintf(details, sizeof(details),
                               "{\"state\":\"%s\",\"state_code\":%d}",
                               nat_ice_state_name(nat_state), (int)nat_state);
                bowie_diag_json_emit("INFO", "Engine", "ACCEPT_ICE_ALREADY_ACTIVE",
                                     NULL, details);
                rc = BOWIE_OK;
            }
        }
    }
    if (rc != BOWIE_OK) goto fail_nat_connected;

    stage = "waiting for ICE connection";
    pthread_mutex_lock(&e->lock);
    rc = wait_for_nat(e, deadline_ms);
    e->inbound_offer = 0;
    memset(&e->inbound_peer_id, 0, sizeof(e->inbound_peer_id));
    pthread_mutex_unlock(&e->lock);
    if (rc != BOWIE_OK) goto fail_nat_connected;

    /* X25519 Exchange & Session Creation */
    {
        bowie_proto_stream_t stream;
        bowie_keypair_shared_t  shared;
        uint8_t                 key_material[BOWIE_SESSION_KEY_LEN * 2u];
        uint8_t                 transcript[ENGINE_HS_TRANSCRIPT_LEN];
        const uint8_t          *tx_key;
        const uint8_t          *rx_key;
        bowie_session_id_t      session_id;

        stage = "initializing authenticated handshake stream";
        bowie_engine_diag("BowieEngine", "ICE connected; starting authenticated handshake as responder");
        rc = bowie_proto_stream_init(&stream, e->nat);
        if (rc != BOWIE_OK) goto fail_nat_connected;
        
        (void)bowie_nat_set_recv(e->nat, bowie_proto_stream_on_nat_data, &stream);

        stage = "exchanging and verifying peer identity";
        rc = exchange_authenticated(e, &stream, expected_peer, 0, &shared,
                                    transcript, &authenticated_peer, &owner_grant);
        if (rc != BOWIE_OK) { destroy_handshake_stream(e, &stream); goto fail_nat_connected; }

        stage = "deriving session keys";
        rc = bowie_security_kdf_hkdf_sha256(shared.bytes, BOWIE_KEYPAIR_SHARED_LEN,
                                            transcript, sizeof(transcript),
                                            kSessionInfo, sizeof(kSessionInfo) - 1,
                                            key_material, sizeof(key_material));
        if (rc != BOWIE_OK) { destroy_handshake_stream(e, &stream); goto fail_nat_connected; }

        tx_key = key_material + BOWIE_SESSION_KEY_LEN;
        rx_key = key_material;

        rc = bowie_rand_secure_bytes(session_id.bytes, BOWIE_SESSION_ID_LEN);
        if (rc == BOWIE_OK) {
            rc = bowie_session_new_from_keys(tx_key, rx_key, &session_id, &e->session);
        }
        memset(key_material, 0, sizeof(key_material));
        memset(transcript, 0, sizeof(transcript));
        memset(&shared, 0, sizeof(shared));
        destroy_handshake_stream(e, &stream);
        if (rc != BOWIE_OK) goto fail_nat_connected;
    }

    bowie_peer_clear(&e->peer);
    bowie_peer_set_id(&e->peer, expected_peer != NULL ? expected_peer : &authenticated_peer);

    if (e->tun != NULL) {
        stage = "starting packet gateway";
        bowie_engine_diag("BowieEngine", "peer authenticated; starting packet gateway");
        bowie_gateway_config_t gw_cfg;
        bowie_gateway_default_config(&gw_cfg);
        gw_cfg.mtu = e->cfg.tunnel_mtu;
        gw_cfg.source_gateway = 1;
        e->gateway_source = 1;
        if (!bowie_grant_id_is_zero(&owner_grant.grant_id) &&
            owner_grant.max_egress_bytes != 0u) {
            pthread_mutex_lock(&e->lock);
            quota_slot = engine_grant_usage_slot(e, &owner_grant);
            e->active_quota_slot = quota_slot;
            pthread_mutex_unlock(&e->lock);
            if (quota_slot < 0) { rc = BOWIE_ERR_QUOTA; goto fail_session; }
            gw_cfg.source_grant_quota_bytes = e->grant_usage[quota_slot].bytes_limit;
            gw_cfg.source_grant_quota_used = &e->grant_usage[quota_slot].bytes_used;
            gw_cfg.source_quota_save = e->cfg.grant_usage_save != NULL
                ? engine_grant_usage_save : NULL;
            gw_cfg.source_quota_save_context = e;
            gw_cfg.source_quota_exceeded = engine_quota_exceeded;
            gw_cfg.source_quota_context = e;
        } else {
            pthread_mutex_lock(&e->lock);
            e->active_quota_slot = -1;
            pthread_mutex_unlock(&e->lock);
        }
        gw_cfg.source_egress = e->cfg.source_egress;
        gw_cfg.source_egress_context = e->cfg.source_egress_context;
        rc = bowie_gateway_open(&e->gateway, &gw_cfg, e->tun);
        if (rc != BOWIE_OK) goto fail_session;
        rc = bowie_gateway_start(e->gateway, e->session, e->nat);
        if (rc != BOWIE_OK) { bowie_gateway_close(e->gateway); e->gateway = NULL; goto fail_session; }
    }

    pthread_mutex_lock(&e->lock);
    e->state = BOWIE_ENGINE_RUNNING;
    pthread_mutex_unlock(&e->lock);
    ENGINE_LOG(BOWIE_LOG_INFO, "accepted peer");
    return BOWIE_OK;

fail_session:
    bowie_session_free(e->session); e->session = NULL;
fail_nat_connected:
    bowie_engine_diag("BowieEngine", "accept failed during %s (error %d)", stage, (int)rc);
    (void)bowie_nat_disconnect(e->nat);
    pthread_mutex_lock(&e->lock); e->nat_connected = 0; pthread_mutex_unlock(&e->lock);
fail_state:
    bowie_engine_diag("BowieEngine", "accept failed during %s (error %d)", stage, (int)rc);
    {
        char details[128];
        (void)snprintf(details, sizeof(details),
                       "{\"stage\":\"%s\",\"error_code\":%d}", stage, (int)rc);
        bowie_diag_json_emit(rc == BOWIE_ERR_TIMEOUT ? "WARN" : "ERROR",
                             "Engine", "ACCEPT_FAILED", NULL, details);
    }
    pthread_mutex_lock(&e->lock);
    e->inbound_offer = 0;
    memset(&e->inbound_peer_id, 0, sizeof(e->inbound_peer_id));
    e->peer_signal_addr_valid = 0;
    e->nat_connected = 0;
    pthread_mutex_unlock(&e->lock);
    pthread_mutex_lock(&e->lock); (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED); pthread_mutex_unlock(&e->lock);
    return rc;
}

bowie_error_t bowie_engine_accept_from(bowie_engine_t *e,
                                       const bowie_peer_id_t *expected_peer,
                                       uint32_t timeout_ms)
{
    return engine_accept_expected(e, expected_peer, timeout_ms);
}

bowie_error_t bowie_engine_accept_discovered(bowie_engine_t *e,
                                             uint32_t timeout_ms)
{
    bowie_error_t rc;
    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    pthread_mutex_lock(&e->lock);
    if (!e->room_announced) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }
    e->active_room_hash = e->announced_room_hash;
    e->active_room = 1;
    pthread_mutex_unlock(&e->lock);
    rc = engine_accept_expected(e, NULL, timeout_ms);
    pthread_mutex_lock(&e->lock);
    e->active_room = 0;
    memset(&e->active_room_hash, 0, sizeof(e->active_room_hash));
    pthread_mutex_unlock(&e->lock);
    return rc;
}

bowie_error_t bowie_engine_accept(bowie_engine_t *e, uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    /* An unsigned/unpinned accept is deliberately disabled. */
    return BOWIE_ERR_PERMISSION;
}

/*
 * ============================================================================
 * DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e)
{
    if (e == NULL) return BOWIE_ERR_NULL_ARG;
    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_RUNNING) { pthread_mutex_unlock(&e->lock); return BOWIE_ERR_STATE; }

    if (e->nat != NULL && e->nat_connected != 0) (void)bowie_nat_disconnect(e->nat);
    if (e->gateway != NULL) { (void)bowie_gateway_stop(e->gateway); bowie_gateway_close(e->gateway); e->gateway = NULL; }
    if (e->session != NULL) { bowie_session_free(e->session); e->session = NULL; }

    e->nat_connected = 0; e->pending_offer = 0; e->inbound_offer = 0; e->peer_signal_addr_valid = 0;
    (void)bowie_engine_state_set(e, BOWIE_ENGINE_STARTED);
    pthread_mutex_unlock(&e->lock);
    ENGINE_LOG(BOWIE_LOG_INFO, "disconnected");
    return BOWIE_OK;
}

bowie_error_t bowie_engine_revoke_grant(bowie_engine_t *e,
                                        const bowie_grant_id_t *grant_id)
{
    if (e == NULL || grant_id == NULL) return BOWIE_ERR_NULL_ARG;
    pthread_mutex_lock(&e->lock);
    bowie_error_t rc = bowie_revoke_list_add(&e->revoke_list, grant_id);
    pthread_mutex_unlock(&e->lock);
    return rc;
}

bowie_error_t bowie_engine_replace_tun_fd(bowie_engine_t *e, int fd)
{
    bowie_gateway_t *old_gateway;
    bowie_gateway_t *new_gateway = NULL;
    bowie_gateway_config_t gw_cfg;
    bowie_tun_t *tun;
    int source_gateway;
    bowie_error_t rc;

    if (fd < 0) return BOWIE_ERR_INVAL;
    if (e == NULL) {
        close(fd);
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_RUNNING || e->gateway == NULL || e->tun == NULL) {
        pthread_mutex_unlock(&e->lock);
        close(fd);
        return BOWIE_ERR_STATE;
    }
    old_gateway = e->gateway;
    e->gateway = NULL;
    tun = e->tun;
    source_gateway = e->gateway_source;
    pthread_mutex_unlock(&e->lock);

    /* Stop the old packet pump before changing the descriptor it polls. */
    (void)bowie_gateway_stop(old_gateway);
    bowie_gateway_close(old_gateway);
    rc = bowie_tun_replace_fd(tun, fd);
    if (rc != BOWIE_OK) return rc;

    bowie_gateway_default_config(&gw_cfg);
    gw_cfg.mtu = e->cfg.tunnel_mtu;
    gw_cfg.source_gateway = source_gateway;
    if (source_gateway && e->active_quota_slot >= 0 &&
        (size_t)e->active_quota_slot < BOWIE_ENGINE_GRANT_USAGE_MAX) {
        bowie_engine_grant_usage_t *usage = &e->grant_usage[e->active_quota_slot];
        gw_cfg.source_grant_quota_bytes = usage->bytes_limit;
        gw_cfg.source_grant_quota_used = &usage->bytes_used;
        gw_cfg.source_quota_save = e->cfg.grant_usage_save != NULL
            ? engine_grant_usage_save : NULL;
        gw_cfg.source_quota_save_context = e;
        gw_cfg.source_quota_exceeded = engine_quota_exceeded;
        gw_cfg.source_quota_context = e;
    }
    gw_cfg.source_egress = e->cfg.source_egress;
    gw_cfg.source_egress_context = e->cfg.source_egress_context;
    rc = bowie_gateway_open(&new_gateway, &gw_cfg, tun);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_gateway_start(new_gateway, e->session, e->nat);
    if (rc != BOWIE_OK) {
        bowie_gateway_close(new_gateway);
        return rc;
    }

    pthread_mutex_lock(&e->lock);
    e->gateway = new_gateway;
    pthread_mutex_unlock(&e->lock);
    bowie_diag_json_emit("INFO", "Engine", "TUN_DESCRIPTOR_REPLACED", NULL,
                         "{\"peer_session_preserved\":true}");
    return BOWIE_OK;
}

/*
 * ============================================================================
 * IDENTITY & STATE
 * ============================================================================
 */

void bowie_engine_public_id(const bowie_engine_t *e, bowie_public_id_t *out)
{
    if (e == NULL || out == NULL) return;
    *out = e->own_public_id;
}

void bowie_engine_peer_id(const bowie_engine_t *e, bowie_peer_id_t *out)
{
    if (e == NULL || out == NULL) return;
    *out = e->own_peer_id;
}

bowie_error_t bowie_engine_connected_peer_id(const bowie_engine_t *e,
                                             bowie_peer_id_t *out)
{
    if (e == NULL || out == NULL) return BOWIE_ERR_NULL_ARG;
    pthread_mutex_lock((pthread_mutex_t *)&e->lock);
    if (e->nat_connected != 1 || bowie_peer_id_is_zero(&e->peer.peer_id)) {
        pthread_mutex_unlock((pthread_mutex_t *)&e->lock);
        return BOWIE_ERR_STATE;
    }
    *out = e->peer.peer_id;
    pthread_mutex_unlock((pthread_mutex_t *)&e->lock);
    return BOWIE_OK;
}

bowie_error_t bowie_engine_sign(bowie_engine_t *e, const void *msg, size_t msg_len, bowie_sign_signature_t *out)
{
    if (e == NULL || out == NULL) return BOWIE_ERR_NULL_ARG;
    if (msg == NULL && msg_len > 0) return BOWIE_ERR_NULL_ARG;
    return bowie_security_sign(&e->own_sign_priv, msg, msg_len, out);
}

bowie_error_t bowie_engine_issue_grant(bowie_engine_t *e,
                                       const bowie_peer_id_t *subject,
                                       uint32_t permissions,
                                       uint64_t ttl_ms,
                                       bowie_grant_t *out)
{
    return bowie_engine_issue_limited_grant(e, subject, permissions, ttl_ms,
                                            0u, out);
}

bowie_error_t bowie_engine_issue_limited_grant(bowie_engine_t *e,
                                               const bowie_peer_id_t *subject,
                                               uint32_t permissions,
                                               uint64_t ttl_ms,
                                               uint64_t max_egress_bytes,
                                               bowie_grant_t *out)
{
    bowie_wtime_t now;
    bowie_error_t rc;
    if (e == NULL || subject == NULL || out == NULL) return BOWIE_ERR_NULL_ARG;
    if (bowie_peer_id_is_zero(subject) || permissions == 0u || ttl_ms == 0u)
        return BOWIE_ERR_INVAL;
    now = bowie_time_wallclock_ms();
    if (UINT64_MAX - now < ttl_ms) return BOWIE_ERR_INVAL;
    bowie_grant_clear(out);
    out->subject = *subject;
    out->issuer = e->own_public_id;
    out->permissions = permissions;
    out->issued_at = now;
    out->expires_at = now + ttl_ms;
    out->max_egress_bytes = max_egress_bytes;
    rc = bowie_rand_secure_bytes(out->grant_id.bytes,
                                 sizeof(out->grant_id.bytes));
    if (rc != BOWIE_OK) return rc;
    if (bowie_grant_id_is_zero(&out->grant_id)) out->grant_id.bytes[0] = 1u;
    return bowie_grant_sign(out, &e->own_sign_priv);
}

bowie_error_t bowie_engine_set_grant(bowie_engine_t *e,
                                     const bowie_grant_t *grant)
{
    int subject_matches;
    int time_valid;
    int internet_use_allowed;
    bowie_error_t signature_rc;
    if (e == NULL || grant == NULL) return BOWIE_ERR_NULL_ARG;
    subject_matches = bowie_grant_matches_subject(grant, &e->own_peer_id);
    time_valid = bowie_grant_is_time_valid(grant, bowie_time_wallclock_ms());
    internet_use_allowed = bowie_grant_allows(grant, BOWIE_GRANT_INTERNET_USE);
    signature_rc = bowie_grant_verify(grant);
    if (!subject_matches || !time_valid || !internet_use_allowed ||
        signature_rc != BOWIE_OK) {
        char details[160];
        (void)snprintf(details, sizeof(details),
            "{\"subject_matches\":%s,\"time_valid\":%s,\"internet_use_allowed\":%s,\"signature_rc\":%d}",
            subject_matches ? "true" : "false",
            time_valid ? "true" : "false",
            internet_use_allowed ? "true" : "false", (int)signature_rc);
        bowie_diag_json_emit("WARN", "Security", "OWNER_GRANT_REJECTED",
                             NULL, details);
        return BOWIE_ERR_PERMISSION;
    }
    pthread_mutex_lock(&e->lock);
    e->presented_grant = *grant;
    e->has_presented_grant = 1;
    pthread_mutex_unlock(&e->lock);
    return BOWIE_OK;
}

void bowie_engine_clear_grant(bowie_engine_t *e)
{
    if (e == NULL) return;
    pthread_mutex_lock(&e->lock);
    memset(&e->presented_grant, 0, sizeof(e->presented_grant));
    e->has_presented_grant = 0;
    pthread_mutex_unlock(&e->lock);
}

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e)
{
    return (e == NULL) ? BOWIE_ENGINE_STOPPED : e->state;
}

const char *bowie_engine_state_name(bowie_engine_state_t state)
{
    return bowie_engine_state_name_internal(state);
}

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

uint16_t bowie_engine_dht_port(const bowie_engine_t *e)
{
    if (e == NULL || e->state == BOWIE_ENGINE_STOPPED) return 0;
    return e->dht_port;
}

uint16_t bowie_engine_signal_port(const bowie_engine_t *e)
{
    if (e == NULL || e->state == BOWIE_ENGINE_STOPPED) return 0;
    return e->signal_port;
}

size_t bowie_engine_dht_node_count(const bowie_engine_t *e)
{
    if (e == NULL) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&e->lock);
    if (e->dht == NULL) {
        pthread_mutex_unlock((pthread_mutex_t *)&e->lock);
        return 0;
    }
    pthread_mutex_lock(&e->dht->state_lock);
    size_t count = bowie_dht_node_count(e->dht);
    pthread_mutex_unlock(&e->dht->state_lock);
    pthread_mutex_unlock((pthread_mutex_t *)&e->lock);
    return count;
}

void bowie_engine_gateway_stats(const bowie_engine_t *e,
                                bowie_gateway_stats_t *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (e == NULL) return;

    pthread_mutex_lock((pthread_mutex_t *)&e->lock);
    if (e->gateway != NULL) bowie_gateway_stats(e->gateway, out);
    pthread_mutex_unlock((pthread_mutex_t *)&e->lock);
}

/*
 * ============================================================================
 * EVENTS (Implementation)
 * ============================================================================
 */

void bowie_engine_drain_events(bowie_engine_t *e)
{
    if (e == NULL) return;
    pthread_mutex_lock(&e->lock);
    bowie_engine_event_drain(&e->events, NULL, NULL);
    pthread_mutex_unlock(&e->lock);
}

int bowie_engine_poll_event(bowie_engine_t *e, bowie_event_record_t *out)
{
    if (e == NULL || out == NULL) return 0;
    pthread_mutex_lock(&e->lock);
    if (e->events.count == 0) {
        pthread_mutex_unlock(&e->lock);
        return 0;
    }
    *out = e->events.records[e->events.tail];
    e->events.tail = (e->events.tail + 1) % BOWIE_ENGINE_EVENT_QUEUE_CAP;
    e->events.count--;
    pthread_mutex_unlock(&e->lock);
    return 1;
}

/* Add a DHT bootstrap endpoint before the engine starts. */
bowie_error_t bowie_engine_add_bootstrap(bowie_engine_t *e, const char *host, uint16_t port)
{
    bowie_error_t rc;

    if (e == NULL || host == NULL) return BOWIE_ERR_NULL_ARG;

    pthread_mutex_lock(&e->lock);
    if (e->state != BOWIE_ENGINE_STOPPED) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_STATE;
    }
    if (e->cfg.bootstrap_count > BOWIE_DHT_BOOTSTRAP_MAX) {
        pthread_mutex_unlock(&e->lock);
        return BOWIE_ERR_TOO_LARGE;
    }

    bowie_dht_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bootstrap_count = e->cfg.bootstrap_count;
    memcpy(cfg.bootstrap, e->cfg.bootstrap,
           cfg.bootstrap_count * sizeof(cfg.bootstrap[0]));
    rc = bowie_dht_config_add_bootstrap(&cfg, host, port);
    if (rc == BOWIE_OK) {
        e->cfg.bootstrap_count = cfg.bootstrap_count;
        memcpy(e->cfg.bootstrap, cfg.bootstrap,
               cfg.bootstrap_count * sizeof(cfg.bootstrap[0]));
    }
    pthread_mutex_unlock(&e->lock);
    return rc;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
