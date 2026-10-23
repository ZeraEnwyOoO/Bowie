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
 * BOWIE — NAT (LIBJUICE BACKEND)
 * ============================================================================
 *
 * The libjuice backend for the NAT interface.
 *
 * This file implements the operations table declared in
 * nat/internal/nat.h using libjuice, an ICE library. The
 * backend is chosen at build time by the Makefile; the core
 * refers to the exported symbol by name.
 *
 * libjuice is an asynchronous, callback-based library. Every
 * callback runs on a thread owned by libjuice. The backend
 * synchronizes access to its own state with a mutex and a
 * condition variable, and blocks the caller of
 * bowie_nat_connect() until the connection is established or
 * the timeout elapses.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No ICE. libjuice does ICE. This file adapts libjuice's
 *     API to the NAT interface and nothing else.
 *   - No signaling transport. The backend produces and
 *     consumes signaling payloads, but it does not send them.
 *     It hands them to the core through
 *     bowie_nat_internal_signal(), which calls the caller's
 *     callback.
 *   - No session or permission. The backend does not check
 *     whether a peer is allowed to connect.
 *   - No TURN server. The backend can use a TURN server that
 *     the caller configured, but it does not run one.
 *   - No logging policy. The backend sets the libjuice log
 *     level but does not install a log handler.
 *   - No retry logic. A failed connection is reported as
 *     FAILED; a caller that wants to retry calls connect
 *     again.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * libjuice's concurrency model is selected at agent creation
 * time. This backend uses JUICE_CONCURRENCY_MODE_THREAD, which
 * gives every agent its own thread. The alternative,
 * JUICE_CONCURRENCY_MODE_POLL, would require the caller to
 * pump the agent; that does not fit a blocking connect API.
 *
 * Every callback receives the bowie_nat_t pointer as its
 * user_ptr. The callback then reaches the backend state
 * through nat->backend. This is the only way a libjuice
 * callback is allowed to touch backend state, and every touch
 * is protected by the backend mutex.
 *
 * The connect call blocks on a condition variable. The
 * state_changed callback signals the condition variable when
 * the state reaches CONNECTED, COMPLETED, or FAILED. The
 * connect call wakes up, reads the result, and returns.
 *
 * The local SDP is captured by the candidate callback as it
 * is produced, and by the gathering_done callback as a final
 * read. The candidate callback hands the SDP to the core
 * through bowie_nat_internal_signal() immediately, so the
 * peer can start connectivity checks as soon as possible.
 *
 * The remote SDP is fed in by bowie_nat_signal_recv(). The
 * backend does not distinguish between an offer and an
 * answer: libjuice's juice_set_remote_description() accepts
 * either, and the ICE agent figures out the rest. This keeps
 * the backend free of role negotiation, which is a Protocol
 * concern.
 *
 * The recv callback delivers data to the core through
 * bowie_nat_internal_deliver(). libjuice's callback contract
 * only guarantees the data pointer for the duration of the
 * call; the core's contract is the same, so no copy is made.
 *
 * The juice config is built by one helper,
 * lj_make_juice_config(). Both lj_create() and lj_start() and
 * lj_disconnect() need a config that reflects the caller's
 * STUN and TURN settings; building it in one place keeps the
 * three paths from drifting apart.
 *
 * stop() destroys the agent, but not the backend state. start()
 * recreates the agent if it was destroyed. This makes
 * start/stop/start work, and keeps connect() as the single
 * place that gathers candidates.
 *
 * Gathering is part of connect, not start. A start that
 * gathered would produce the first signaling payload before
 * the caller has installed a signal callback and before the
 * peer is ready to receive it. Keeping gather in connect
 * means the payload is produced exactly when the caller is
 * ready to route it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>             mutex, condition variable
 *   <stdlib.h>              calloc, free
 *   <string.h>              memset, memcpy, strlen
 *   <time.h>                clock_gettime
 *   <juice/juice.h>         libjuice API
 *   "bowie/types.h"         bowie_addr_t, bowie_peer_id_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "nat/nat.h"             public NAT contract
 *   "nat/internal/nat.h"    internal NAT contract
 * ============================================================================
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>

#include <juice/juice.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "nat/nat.h"
#include "nat/internal/nat.h"
#include "tunnel/mtu.h"
#include "core/internal/diag_json.h"

/* Keep Bowie's complete UDP payload below the conservative ICE ceiling.
 * The 1100-byte wire cap includes Bowie's fragment header; UDP/IP headers
 * are added below this layer by the network stack.
 * Large Bowie messages are carried as authenticated ciphertext slices.
 * Reassembly happens before delivery, so the session layer continues to
 * authenticate exactly the original ciphertext and IP packet. */
#define LJ_WIRE_MTU 1100u
#define LJ_FRAG_HEADER 16u
#define LJ_FRAG_PAYLOAD (LJ_WIRE_MTU - LJ_FRAG_HEADER)
#define LJ_REASSEMBLY_MAX (BOWIE_TUN_MTU_MAX + 64u)
#define LJ_REASSEMBLY_SLOTS 16u
#define LJ_FRAG_TTL_MS 30000u
#define LJ_DYNAMIC_TURN_MAX 4u
#define LJ_TURN_HOST_MAX 256u
#define LJ_TURN_CRED_MAX 512u

typedef struct lj_reassembly {
    uint32_t id;
    size_t total;
    size_t received;
    uint64_t touched_ms;
    uint8_t data[LJ_REASSEMBLY_MAX];
    uint8_t present[LJ_REASSEMBLY_MAX];
} lj_reassembly_t;

static uint32_t lj_read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void lj_write_be32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}

static uint64_t lj_now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/*
 * ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================
 *
 * The callbacks are referenced by lj_make_juice_config(), which
 * is defined before them. The forward declarations let the
 * helper name the callback pointers without reordering the
 * file.
 */

static void on_state_changed(juice_agent_t *agent,
                             juice_state_t  state,
                             void          *user_ptr);

static void on_candidate(juice_agent_t *agent,
                         const char    *sdp,
                         void          *user_ptr);

static void on_gathering_done(juice_agent_t *agent,
                              void          *user_ptr);

static void on_recv(juice_agent_t *agent,
                    const char    *data,
                    size_t         size,
                    void          *user_ptr);

/*
 * ============================================================================
 * BACKEND STATE
 * ============================================================================
 *
 * The private state of one libjuice backend instance.
 *
 * The state field mirrors the NAT state enum. It is updated by
 * the libjuice callbacks under the mutex, and read by the
 * connect loop under the mutex.
 *
 * The gathering_done flag is set by the gathering_done
 * callback. It is used to know when the local SDP is complete.
 *
 * The connect_done flag is set by the state_changed callback
 * when the state reaches a terminal value. The connect loop
 * waits on the condition variable until this flag is set or
 * the timeout elapses.
 *
 * The connect_result field is the outcome of the connect
 * call. It is written before connect_done is set, and read
 * after connect_done is observed.
 *
 * The local_sdp buffer holds the most recent local
 * description. It is written by the candidate callback and by
 * the gathering_done callback. It is reserved for a future
 * accessor; no accessor exists yet.
 */

typedef struct nat_libjuice {
    juice_agent_t    *agent;

    pthread_mutex_t   lock;
    pthread_cond_t    cond;

    bowie_nat_state_t state;
    int               gathering_done;
    int               connect_done;
    bowie_error_t     connect_result;

    char              local_sdp[JUICE_MAX_SDP_STRING_LEN];
    size_t            local_sdp_len;
    uint32_t          next_fragment_id;
    struct {
        char host[LJ_TURN_HOST_MAX];
        char username[LJ_TURN_CRED_MAX];
        char password[LJ_TURN_CRED_MAX];
        uint16_t port;
    } dynamic_turn[LJ_DYNAMIC_TURN_MAX];
    size_t dynamic_turn_count;
    lj_reassembly_t   reassembly[LJ_REASSEMBLY_SLOTS];
} nat_libjuice_t;

/*
 * ============================================================================
 * STATE MAPPING
 * ============================================================================
 */

static bowie_nat_state_t map_juice_state(juice_state_t state)
{
    switch (state) {
    case JUICE_STATE_DISCONNECTED:
        return BOWIE_NAT_STATE_DISCONNECTED;
    case JUICE_STATE_GATHERING:
        return BOWIE_NAT_STATE_GATHERING;
    case JUICE_STATE_CONNECTING:
        return BOWIE_NAT_STATE_CONNECTING;
    case JUICE_STATE_CONNECTED:
        return BOWIE_NAT_STATE_CONNECTED;
    case JUICE_STATE_COMPLETED:
        return BOWIE_NAT_STATE_COMPLETED;
    case JUICE_STATE_FAILED:
        return BOWIE_NAT_STATE_FAILED;
    default:
        return BOWIE_NAT_STATE_DISCONNECTED;
    }
}

static const char *nat_state_name(bowie_nat_state_t state)
{
    switch (state) {
    case BOWIE_NAT_STATE_GATHERING: return "GATHERING";
    case BOWIE_NAT_STATE_CONNECTING: return "CONNECTING";
    case BOWIE_NAT_STATE_CONNECTED: return "CONNECTED";
    case BOWIE_NAT_STATE_COMPLETED: return "COMPLETED";
    case BOWIE_NAT_STATE_FAILED: return "FAILED";
    default: return "DISCONNECTED";
    }
}

static bowie_error_t map_juice_error(int rc)
{
    switch (rc) {
    case JUICE_ERR_SUCCESS:
        return BOWIE_OK;
    case JUICE_ERR_INVALID:
        return BOWIE_ERR_INVAL;
    case JUICE_ERR_FAILED:
        return BOWIE_ERR_NETWORK;
    case JUICE_ERR_NOT_AVAIL:
        return BOWIE_ERR_STATE;
    case JUICE_ERR_IGNORED:
        return BOWIE_ERR_AGAIN;
    case JUICE_ERR_AGAIN:
        return BOWIE_ERR_AGAIN;
    case JUICE_ERR_TOO_LARGE:
        return BOWIE_ERR_TOO_LARGE;
    default:
        return BOWIE_ERR_NETWORK;
    }
}

/*
 * ============================================================================
 * JUICE CONFIG HELPER
 * ============================================================================
 *
 * Build a juice_config_t from the caller's bowie_nat_config_t.
 *
 * The helper fills jcfg and, if a TURN server is configured,
 * also fills the turn struct that jcfg points into. The turn
 * struct must outlive the juice_config_t; the caller keeps it
 * on its own stack.
 *
 * The helper always installs the four callbacks and the
 * user_ptr. The user_ptr is the bowie_nat_t pointer, which is
 * what every callback expects.
 *
 * The helper does not allocate.
 */

static void lj_make_juice_config(const bowie_nat_t   *nat,
                                 juice_config_t      *jcfg,
                                 juice_turn_server_t *turn)
{
    memset(jcfg, 0, sizeof(*jcfg));
    memset(turn, 0, sizeof(*turn));

    jcfg->concurrency_mode  = JUICE_CONCURRENCY_MODE_THREAD;
    jcfg->user_ptr          = (void *)nat;

    jcfg->cb_state_changed  = on_state_changed;
    jcfg->cb_candidate      = on_candidate;
    jcfg->cb_gathering_done = on_gathering_done;
    jcfg->cb_recv           = on_recv;
    jcfg->bind_address      = nat->cfg.bind_address;

    if (!nat->cfg.allow_server) {
        return;
    }

    jcfg->stun_server_host = nat->cfg.stun_server_host;
    jcfg->stun_server_port = nat->cfg.stun_server_port;

    if (nat->cfg.turn_server_host == NULL) {
        return;
    }

    turn->host     = nat->cfg.turn_server_host;
    turn->port     = nat->cfg.turn_server_port;
    turn->username = nat->cfg.turn_username;
    turn->password = nat->cfg.turn_password;

    jcfg->turn_servers       = turn;
    jcfg->turn_servers_count = 1;
}

/*
 * ============================================================================
 * LIJUICE CALLBACKS
 * ============================================================================
 *
 * Every callback receives the bowie_nat_t pointer as its
 * user_ptr. The callback locks the backend mutex, updates
 * state, and then calls a core helper (which does not take
 * the mutex).
 *
 * The core helpers are called with the mutex held. They do
 * not touch backend state, so this is safe. They may call
 * back into user code, which means user code runs with the
 * backend mutex held. That is acceptable here because the
 * user callbacks are expected to be short.
 */

static void on_state_changed(juice_agent_t *agent,
                             juice_state_t  state,
                             void          *user_ptr)
{
    bowie_nat_t      *nat = (bowie_nat_t *)user_ptr;
    nat_libjuice_t   *lj;
    bowie_nat_state_t mapped;

    (void)agent;

    if (nat == NULL || nat->backend == NULL) {
        return;
    }

    lj     = (nat_libjuice_t *)nat->backend;
    mapped = map_juice_state(state);

    {
        char details[96];
        (void)snprintf(details, sizeof(details), "{\"state\":\"%s\",\"state_code\":%d}",
                       nat_state_name(mapped), (int)mapped);
        bowie_diag_json_emit(mapped == BOWIE_NAT_STATE_FAILED ? "ERROR" : "INFO",
                             "ICE", "ICE_STATE_CHANGED", NULL, details);
    }

    pthread_mutex_lock(&lj->lock);

    lj->state = mapped;

    if (mapped == BOWIE_NAT_STATE_CONNECTED ||
        mapped == BOWIE_NAT_STATE_COMPLETED) {
        lj->connect_result = BOWIE_OK;
        lj->connect_done   = 1;
        pthread_cond_broadcast(&lj->cond);
    } else if (mapped == BOWIE_NAT_STATE_FAILED) {
        lj->connect_result = BOWIE_ERR_NETWORK;
        lj->connect_done   = 1;
        pthread_cond_broadcast(&lj->cond);
    }

    pthread_mutex_unlock(&lj->lock);

    bowie_nat_internal_set_state(nat, mapped);
}

static void on_candidate(juice_agent_t *agent,
                         const char    *sdp,
                         void          *user_ptr)
{
    (void)agent;
    (void)user_ptr;
    /* Candidates are logged here but relayed as part of the completed SDP. */
    if (sdp != NULL) {
        char details[128];
        (void)snprintf(details, sizeof(details),
                       "{\"candidate_bytes\":%zu,\"relayed_in_sdp\":true}",
                       strlen(sdp));
        bowie_diag_json_emit("DEBUG", "ICE", "ICE_CANDIDATE_GATHERED", NULL, details);
    }
}

static void on_gathering_done(juice_agent_t *agent, void *user_ptr)
{
    bowie_nat_t    *nat = (bowie_nat_t *)user_ptr;
    nat_libjuice_t *lj;
    char            buf[JUICE_MAX_SDP_STRING_LEN];
    int             rc;
    size_t          len;

    (void)agent;

    if (nat == NULL || nat->backend == NULL) {
        return;
    }

    lj = (nat_libjuice_t *)nat->backend;

    memset(buf, 0, sizeof(buf));

    rc = juice_get_local_description(lj->agent, buf, sizeof(buf));

    if (rc != JUICE_ERR_SUCCESS) {
        char details[80];
        (void)snprintf(details, sizeof(details), "{\"libjuice_rc\":%d}", rc);
        bowie_diag_json_emit("ERROR", "ICE", "LOCAL_DESCRIPTION_FAILED", NULL, details);
        return;
    }

    len = strlen(buf);

    pthread_mutex_lock(&lj->lock);

    if (len < sizeof(lj->local_sdp)) {
        memcpy(lj->local_sdp, buf, len);
        lj->local_sdp[len] = '\0';
        lj->local_sdp_len  = len;
    }

    lj->gathering_done = 1;

    pthread_mutex_unlock(&lj->lock);

    {
        char details[128];
        (void)snprintf(details, sizeof(details),
                       "{\"bytes\":%zu,\"candidate_count\":%zu}", len,
                       bowie_diag_candidate_count((const uint8_t *)buf, len));
        bowie_diag_json_emit("INFO", "ICE", "ICE_GATHERING_COMPLETE", NULL, details);
    }

    /* Signal the complete local description. Sending candidate callback
     * fragments here would make the peer parse a candidate as full SDP. */
    (void)bowie_nat_internal_signal(nat, NULL, (const uint8_t *)buf, len);
}

static void on_recv(juice_agent_t *agent,
                    const char    *data,
                    size_t         size,
                    void          *user_ptr)
{
    bowie_nat_t *nat = (bowie_nat_t *)user_ptr;
    nat_libjuice_t *lj;
    struct { uint32_t id; size_t total; size_t received; } expired[LJ_REASSEMBLY_SLOTS];
    size_t expired_count = 0u;

    (void)agent;

    if (nat == NULL || data == NULL || size == 0) {
        return;
    }
    {
        int fragment = size >= 4u && memcmp(data, "BWFG", 4u) == 0;
        char details[128];
        (void)snprintf(details, sizeof(details),
                       "{\"datagram_bytes\":%zu,\"fragment\":%s,\"datagram_limit\":%u}",
                       size, fragment ? "true" : "false", LJ_WIRE_MTU);
        bowie_diag_json_emit("DEBUG", "NAT", "NAT_DATA_DATAGRAM_RECEIVED", NULL, details);
    }
    if (size > LJ_WIRE_MTU) {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"datagram_bytes\":%zu,\"datagram_limit\":%u}",
                       size, LJ_WIRE_MTU);
        bowie_diag_json_emit("WARN", "NAT", "NAT_DATA_DATAGRAM_OVERSIZE", NULL, details);
        return;
    }
    lj = (nat_libjuice_t *)nat->backend;
    if (lj != NULL) {
        uint64_t now = lj_now_ms();
        pthread_mutex_lock(&lj->lock);
        for (size_t i = 0; i < LJ_REASSEMBLY_SLOTS; ++i) {
            lj_reassembly_t *slot = &lj->reassembly[i];
            if (slot->total != 0u && now - slot->touched_ms > LJ_FRAG_TTL_MS) {
                expired[expired_count].id = slot->id;
                expired[expired_count].total = slot->total;
                expired[expired_count].received = slot->received;
                expired_count++;
                memset(slot, 0, sizeof(*slot));
            }
        }
        pthread_mutex_unlock(&lj->lock);
        for (size_t i = 0; i < expired_count; ++i) {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"expected_bytes\":%zu,\"received_bytes\":%zu,\"missing_bytes\":%zu,\"timeout_ms\":%u}",
                           expired[i].id, expired[i].total, expired[i].received,
                           expired[i].total - expired[i].received, LJ_FRAG_TTL_MS);
            bowie_diag_json_emit("WARN", "NAT", "NAT_FRAGMENT_REASSEMBLY_TIMEOUT", NULL, details);
        }
    }
    if (size >= LJ_FRAG_HEADER && memcmp(data, "BWFG", 4u) == 0) {
        const uint8_t *wire = (const uint8_t *)data;
        uint32_t id = lj_read_be32(wire + 4u);
        size_t total = (size_t)lj_read_be32(wire + 8u);
        size_t offset = (size_t)lj_read_be32(wire + 12u);
        size_t part = size - LJ_FRAG_HEADER;
        uint8_t complete[LJ_REASSEMBLY_MAX];
        int deliver = 0;
        int pending = 0;
        size_t pending_received = 0u;
        {
            char details[192];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"offset\":%zu,\"fragment_payload_bytes\":%zu,\"message_bytes\":%zu,\"datagram_bytes\":%zu,\"datagram_limit\":%u}",
                           id, offset, part, total, size, LJ_WIRE_MTU);
            bowie_diag_json_emit("DEBUG", "NAT", "NAT_FRAGMENT_RECEIVED", NULL, details);
        }
        if (lj == NULL || total == 0u || total > LJ_REASSEMBLY_MAX ||
            part == 0u || offset > total || part > total - offset) {
            bowie_diag_json_emit("WARN", "NAT", "NAT_FRAGMENT_REJECTED", NULL,
                                 "{\"reason\":\"invalid_header_or_range\"}");
            return;
        }
        pthread_mutex_lock(&lj->lock);
        lj_reassembly_t *slot = NULL;
        for (size_t i = 0; i < LJ_REASSEMBLY_SLOTS; ++i) {
            lj_reassembly_t *candidate = &lj->reassembly[i];
            if (candidate->total != 0u && candidate->id == id) { slot = candidate; break; }
        }
        if (slot == NULL) {
            for (size_t i = 0; i < LJ_REASSEMBLY_SLOTS; ++i)
                if (lj->reassembly[i].total == 0u) { slot = &lj->reassembly[i]; break; }
            if (slot != NULL) { slot->id = id; slot->total = total; }
        }
        if (slot != NULL && slot->total == total) {
            slot->touched_ms = lj_now_ms();
            for (size_t i = 0; i < part; ++i) {
                size_t at = offset + i;
                if (!slot->present[at]) { slot->present[at] = 1u; slot->received++; }
                slot->data[at] = wire[LJ_FRAG_HEADER + i];
            }
            if (slot->received == slot->total) {
                memcpy(complete, slot->data, slot->total);
                size = slot->total;
                memset(slot, 0, sizeof(*slot));
                deliver = 1;
            } else {
                pending = 1;
                pending_received = slot->received;
            }
        } else {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"total_bytes\":%zu,\"reason\":\"%s\"}",
                           id, total, slot == NULL ? "reassembly_slots_full" : "size_mismatch");
            pthread_mutex_unlock(&lj->lock);
            bowie_diag_json_emit("WARN", "NAT", "NAT_FRAGMENT_REJECTED", NULL, details);
            return;
        }
        pthread_mutex_unlock(&lj->lock);
        if (pending) {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"expected_bytes\":%zu,\"received_bytes\":%zu,\"missing_bytes\":%zu}",
                           id, total, pending_received, total - pending_received);
            bowie_diag_json_emit("DEBUG", "NAT", "NAT_FRAGMENT_INCOMPLETE", NULL, details);
        }
        if (deliver) {
            char details[128];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"reassembled_bytes\":%zu}", id, size);
            bowie_diag_json_emit("DEBUG", "NAT", "NAT_FRAGMENT_REASSEMBLED", NULL, details);
            bowie_nat_internal_deliver(nat, complete, size);
        }
        return;
    }
    bowie_nat_internal_deliver(nat, (const uint8_t *)data, size);
}

/*
 * ============================================================================
 * OPS — CREATE
 * ============================================================================
 */

static bowie_error_t lj_create(bowie_nat_t              *nat,
                               const bowie_nat_config_t *cfg)
{
    nat_libjuice_t      *lj;
    juice_config_t       jcfg;
    juice_turn_server_t  turn;

    if (nat == NULL || cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)calloc(1, sizeof(*lj));

    if (lj == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    if (pthread_mutex_init(&lj->lock, NULL) != 0) {
        free(lj);
        return BOWIE_ERR_INTERNAL;
    }

    if (pthread_cond_init(&lj->cond, NULL) != 0) {
        pthread_mutex_destroy(&lj->lock);
        free(lj);
        return BOWIE_ERR_INTERNAL;
    }

    lj->state          = BOWIE_NAT_STATE_DISCONNECTED;
    lj->gathering_done = 0;
    lj->connect_done   = 0;
    lj->connect_result = BOWIE_OK;
    lj->local_sdp_len  = 0;
    lj->local_sdp[0]   = '\0';

    /*
     * Build the juice config from the caller's config. The
     * helper fills turn if a TURN server is configured; turn
     * stays on this stack frame until juice_create() returns.
     */

    lj_make_juice_config(nat, &jcfg, &turn);

    lj->agent = juice_create(&jcfg);

    if (lj->agent == NULL) {
        pthread_cond_destroy(&lj->cond);
        pthread_mutex_destroy(&lj->lock);
        free(lj);
        return BOWIE_ERR_INTERNAL;
    }

    nat->backend = lj;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS — START
 * ============================================================================
 *
 * Make the instance ready to connect.
 *
 * If stop destroyed the agent, recreate it from the same
 * config. If the agent is already there, reuse it. The agent
 * is never gathered here; gathering is part of connect, where
 * the caller has already installed a signal callback and is
 * ready to route the first payload.
 */

static bowie_error_t lj_start(bowie_nat_t *nat)
{
    nat_libjuice_t      *lj;
    juice_config_t       jcfg;
    juice_turn_server_t  turn;

    if (nat == NULL || nat->backend == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)nat->backend;

    if (lj->agent == NULL) {
        lj_make_juice_config(nat, &jcfg, &turn);

        lj->agent = juice_create(&jcfg);

        if (lj->agent == NULL) {
            return BOWIE_ERR_INTERNAL;
        }
        for (size_t i = 0u; i < lj->dynamic_turn_count; ++i) {
            juice_turn_server_t server = {
                .host = lj->dynamic_turn[i].host,
                .username = lj->dynamic_turn[i].username,
                .password = lj->dynamic_turn[i].password,
                .port = lj->dynamic_turn[i].port,
            };
            if (juice_add_turn_server(lj->agent, &server) != JUICE_ERR_SUCCESS)
                return BOWIE_ERR_NETWORK;
        }
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS — STOP
 * ============================================================================
 *
 * Destroy the agent. libjuice has no explicit stop; destroying
 * the agent tears down the connection and releases its thread
 * and its sockets. The backend struct stays alive so the
 * instance can be started again.
 */

static bowie_error_t lj_stop(bowie_nat_t *nat)
{
    nat_libjuice_t *lj;

    if (nat == NULL || nat->backend == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)nat->backend;

    if (lj->agent != NULL) {
        juice_destroy(lj->agent);
        lj->agent = NULL;
    }

    pthread_mutex_lock(&lj->lock);

    lj->state          = BOWIE_NAT_STATE_DISCONNECTED;
    lj->gathering_done = 0;
    lj->connect_done   = 0;
    lj->connect_result = BOWIE_OK;
    lj->local_sdp_len  = 0;
    lj->local_sdp[0]   = '\0';

    pthread_mutex_unlock(&lj->lock);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS — FREE
 * ============================================================================
 *
 * The agent has already been destroyed by stop() if the
 * instance was started. This function only has to destroy the
 * synchronization primitives and free the backend struct.
 */

static void lj_free(bowie_nat_t *nat)
{
    nat_libjuice_t *lj;

    if (nat == NULL || nat->backend == NULL) {
        return;
    }

    lj = (nat_libjuice_t *)nat->backend;

    if (lj->agent != NULL) {
        juice_destroy(lj->agent);
        lj->agent = NULL;
    }

    pthread_cond_destroy(&lj->cond);
    pthread_mutex_destroy(&lj->lock);

    free(lj);

    nat->backend = NULL;
}

/*
 * ============================================================================
 * OPS — CONNECT
 * ============================================================================
 *
 * Block until the connection reaches a terminal state, or
 * until the deadline passes.
 *
 * The peer address is not used directly. libjuice establishes
 * a connection through SDP signaling, not through a direct
 * address. The address is a hint; the signaling channel does
 * the real work.
 *
 * Gathering happens here, not in start. This is the point at
 * which the caller has installed a signal callback and is
 * ready to route the first payload.
 *
 * The deadline is computed from CLOCK_REALTIME because
 * pthread_cond_timedwait expects it by default.
 */

static bowie_error_t lj_connect(bowie_nat_t        *nat,
                                const bowie_addr_t *peer,
                                uint32_t            timeout_ms)
{
    nat_libjuice_t *lj;
    struct timespec deadline;
    bowie_error_t   result;
    int             rc;

    (void)peer;

    if (nat == NULL || nat->backend == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)nat->backend;

    clock_gettime(CLOCK_REALTIME, &deadline);

    deadline.tv_sec  += (time_t)(timeout_ms / 1000u);
    deadline.tv_nsec += (long)((timeout_ms % 1000u) * 1000000L);

    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec  += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&lj->lock);

    lj->connect_done   = 0;
    lj->connect_result = BOWIE_OK;
    pthread_mutex_unlock(&lj->lock);

    /*
     * Gather candidates. This produces the first signaling
     * payload through the candidate callback.
     */

    rc = juice_gather_candidates(lj->agent);

    if (rc != JUICE_ERR_SUCCESS) {
        return map_juice_error(rc);
    }

    /*
     * Wait for the connection to reach a terminal state, or
     * for the deadline to pass.
     */

    pthread_mutex_lock(&lj->lock);
    while (!lj->connect_done) {
        rc = pthread_cond_timedwait(&lj->cond, &lj->lock, &deadline);

        if (rc != 0) {
            break;
        }
    }

    if (!lj->connect_done) {
        result = BOWIE_ERR_TIMEOUT;
    } else {
        result = lj->connect_result;
    }

    pthread_mutex_unlock(&lj->lock);

    if (result == BOWIE_OK) {
        char local_address[128] = { 0 };
        char remote_address[128] = { 0 };
        int pair_rc = juice_get_selected_addresses(lj->agent,
                                                    local_address, sizeof(local_address),
                                                    remote_address, sizeof(remote_address));
        if (pair_rc == JUICE_ERR_SUCCESS) {
            char details[320];
            (void)snprintf(details, sizeof(details),
                           "{\"local_address\":\"%s\",\"remote_address\":\"%s\"}",
                           local_address, remote_address);
            bowie_diag_json_emit("INFO", "ICE", "ICE_SELECTED_ADDRESS_PAIR", NULL, details);
        } else {
            char details[80];
            (void)snprintf(details, sizeof(details), "{\"libjuice_rc\":%d}", pair_rc);
            bowie_diag_json_emit("WARN", "ICE", "ICE_SELECTED_ADDRESS_UNAVAILABLE", NULL, details);
        }
    }

    return result;
}

/*
 * ============================================================================
 * OPS — DISCONNECT
 * ============================================================================
 *
 * libjuice has no explicit disconnect. Destroy the agent and
 * recreate it from the same config, so the instance is ready
 * to connect again with the same STUN and TURN settings.
 *
 * The recreation path uses the same helper as create(), which
 * is what keeps the two paths from drifting apart.
 */

static bowie_error_t lj_disconnect(bowie_nat_t *nat)
{
    nat_libjuice_t      *lj;
    juice_config_t       jcfg;
    juice_turn_server_t  turn;

    if (nat == NULL || nat->backend == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)nat->backend;

    if (lj->agent != NULL) {
        juice_destroy(lj->agent);
        lj->agent = NULL;
    }

    lj_make_juice_config(nat, &jcfg, &turn);

    lj->agent = juice_create(&jcfg);

    if (lj->agent == NULL) {
        return BOWIE_ERR_INTERNAL;
    }

    for (size_t i = 0u; i < lj->dynamic_turn_count; ++i) {
        juice_turn_server_t server = {
            .host = lj->dynamic_turn[i].host,
            .username = lj->dynamic_turn[i].username,
            .password = lj->dynamic_turn[i].password,
            .port = lj->dynamic_turn[i].port,
        };
        if (juice_add_turn_server(lj->agent, &server) != JUICE_ERR_SUCCESS)
            return BOWIE_ERR_NETWORK;
    }

    pthread_mutex_lock(&lj->lock);

    lj->state          = BOWIE_NAT_STATE_DISCONNECTED;
    lj->gathering_done = 0;
    lj->connect_done   = 0;
    lj->connect_result = BOWIE_OK;
    lj->local_sdp_len  = 0;
    lj->local_sdp[0]   = '\0';

    pthread_mutex_unlock(&lj->lock);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS — SEND
 * ============================================================================
 */

static long lj_send(bowie_nat_t *nat,
                    const void  *buf,
                    size_t       len)
{
    nat_libjuice_t *lj;
    int             rc;

    if (nat == NULL || nat->backend == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    lj = (nat_libjuice_t *)nat->backend;

    if (len <= LJ_WIRE_MTU) {
        rc = juice_send(lj->agent, (const char *)buf, len);
        if (rc != JUICE_ERR_SUCCESS) return (long)map_juice_error(rc);
        return (long)len;
    }
    if (len > LJ_REASSEMBLY_MAX) return BOWIE_ERR_TOO_LARGE;
    uint32_t id;
    pthread_mutex_lock(&lj->lock);
    id = ++lj->next_fragment_id;
    if (id == 0u) id = ++lj->next_fragment_id;
    pthread_mutex_unlock(&lj->lock);
    uint8_t wire[LJ_WIRE_MTU];
    const uint8_t *bytes = (const uint8_t *)buf;
    size_t fragments = 0u;
    for (size_t offset = 0; offset < len; ) {
        size_t part = len - offset;
        if (part > LJ_FRAG_PAYLOAD) part = LJ_FRAG_PAYLOAD;
        memcpy(wire, "BWFG", 4u);
        lj_write_be32(wire + 4u, id);
        lj_write_be32(wire + 8u, (uint32_t)len);
        lj_write_be32(wire + 12u, (uint32_t)offset);
        memcpy(wire + LJ_FRAG_HEADER, bytes + offset, part);
        rc = juice_send(lj->agent, (const char *)wire, LJ_FRAG_HEADER + part);
        if (rc != JUICE_ERR_SUCCESS) {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"offset\":%zu,\"fragment_bytes\":%zu,\"message_bytes\":%zu,\"libjuice_error\":%d}",
                           id, offset, LJ_FRAG_HEADER + part, len, rc);
            bowie_diag_json_emit("WARN", "NAT", "NAT_FRAGMENT_SEND_FAILED", NULL, details);
            return (long)map_juice_error(rc);
        }
        {
            char details[192];
            (void)snprintf(details, sizeof(details),
                           "{\"fragment_id\":%u,\"offset\":%zu,\"fragment_payload_bytes\":%zu,\"message_bytes\":%zu,\"datagram_bytes\":%zu,\"datagram_limit\":%u}",
                           id, offset, part, len, LJ_FRAG_HEADER + part, LJ_WIRE_MTU);
            bowie_diag_json_emit("DEBUG", "NAT", "NAT_FRAGMENT_SENT", NULL, details);
        }
        fragments++;
        offset += part;
    }
    {
        char details[128];
        (void)snprintf(details, sizeof(details),
                       "{\"fragment_id\":%u,\"message_bytes\":%zu,\"fragment_count\":%zu,\"datagram_limit\":%u}",
                       id, len, fragments, LJ_WIRE_MTU);
        bowie_diag_json_emit("DEBUG", "NAT", "NAT_FRAGMENT_SEND_COMPLETE", NULL, details);
    }
    return (long)len;
}

/*
 * ============================================================================
 * OPS — RECV
 * ============================================================================
 *
 * libjuice is callback-based: data arrives through the recv
 * callback and is delivered to the core through
 * bowie_nat_internal_deliver(). There is no queue to drain
 * here. This function always returns 0.
 *
 * A caller that wants to receive data through the libjuice
 * backend installs a recv callback; see the header note on
 * pull recv.
 */

static long lj_recv(bowie_nat_t *nat,
                    void        *buf,
                    size_t       cap)
{
    (void)nat;
    (void)buf;
    (void)cap;

    return 0;
}

/*
 * ============================================================================
 * OPS — SIGNAL RECV
 * ============================================================================
 *
 * The payload is an SDP blob produced by the peer's ICE agent.
 * libjuice's juice_set_remote_description() accepts either an
 * offer or an answer; the ICE agent figures out the role. The
 * backend does not need to know which one it is.
 */

static bowie_error_t lj_signal_recv(bowie_nat_t   *nat,
                                    const uint8_t *data,
                                    size_t         len)
{
    nat_libjuice_t *lj;
    char            sdp[JUICE_MAX_SDP_STRING_LEN];
    int             rc;

    if (nat == NULL || nat->backend == NULL || data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (len == 0 || len >= sizeof(sdp)) {
        return BOWIE_ERR_TOO_LARGE;
    }

    lj = (nat_libjuice_t *)nat->backend;

    memcpy(sdp, data, len);
    sdp[len] = '\0';

    rc = juice_set_remote_description(lj->agent, sdp);

    if (rc != JUICE_ERR_SUCCESS) {
        return map_juice_error(rc);
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS — CAPABILITIES
 * ============================================================================
 */

static bowie_error_t lj_capabilities(const bowie_nat_t *nat,
                                     bowie_nat_caps_t  *out)
{
    if (nat == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    out->name                   = "libjuice";
    out->performs_nat_traversal = 1;
    out->uses_server            = nat->cfg.allow_server ? 1 : 0;
    out->can_relay              = nat->cfg.turn_server_host ? 1 : 0;

    return BOWIE_OK;
}

static bowie_error_t lj_add_turn_server(bowie_nat_t *nat, const char *host,
                                        uint16_t port, const char *username,
                                        const char *password)
{
    nat_libjuice_t *lj;
    juice_turn_server_t server;
    size_t host_len, user_len, pass_len;
    if (nat == NULL || nat->backend == NULL || host == NULL ||
        username == NULL || password == NULL) return BOWIE_ERR_NULL_ARG;
    host_len = strlen(host); user_len = strlen(username); pass_len = strlen(password);
    if (host_len == 0u || host_len >= LJ_TURN_HOST_MAX ||
        user_len >= LJ_TURN_CRED_MAX || pass_len >= LJ_TURN_CRED_MAX || port == 0u)
        return BOWIE_ERR_INVAL;
    lj = (nat_libjuice_t *)nat->backend;
    pthread_mutex_lock(&lj->lock);
    for (size_t i = 0u; i < lj->dynamic_turn_count; ++i) {
        if (lj->dynamic_turn[i].port == port &&
            strcmp(lj->dynamic_turn[i].host, host) == 0 &&
            strcmp(lj->dynamic_turn[i].username, username) == 0) {
            pthread_mutex_unlock(&lj->lock);
            return BOWIE_OK;
        }
    }
    if (lj->dynamic_turn_count >= LJ_DYNAMIC_TURN_MAX) {
        pthread_mutex_unlock(&lj->lock);
        return BOWIE_ERR_TOO_LARGE;
    }
    size_t index = lj->dynamic_turn_count++;
    memcpy(lj->dynamic_turn[index].host, host, host_len + 1u);
    memcpy(lj->dynamic_turn[index].username, username, user_len + 1u);
    memcpy(lj->dynamic_turn[index].password, password, pass_len + 1u);
    lj->dynamic_turn[index].port = port;
    if (lj->agent != NULL) {
        server.host = lj->dynamic_turn[index].host;
        server.username = lj->dynamic_turn[index].username;
        server.password = lj->dynamic_turn[index].password;
        server.port = port;
        if (juice_add_turn_server(lj->agent, &server) != JUICE_ERR_SUCCESS) {
            --lj->dynamic_turn_count;
            pthread_mutex_unlock(&lj->lock);
            return BOWIE_ERR_NETWORK;
        }
    }
    pthread_mutex_unlock(&lj->lock);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * OPS TABLE
 * ============================================================================
 *
 * The exported operations table. The core refers to it by
 * name. The Makefile selects the file that provides it.
 */

const bowie_nat_backend_ops_t bowie_nat_libjuice_ops = {
    .create       = lj_create,
    .start        = lj_start,
    .stop         = lj_stop,
    .free         = lj_free,
    .connect      = lj_connect,
    .disconnect   = lj_disconnect,
    .send         = lj_send,
    .recv         = lj_recv,
    .signal_recv  = lj_signal_recv,
    .capabilities = lj_capabilities,
    .add_turn_server = lj_add_turn_server,
};

/*
 * ============================================================================
 * END OF NAT LIBJUICE BACKEND
 * ============================================================================
 */
