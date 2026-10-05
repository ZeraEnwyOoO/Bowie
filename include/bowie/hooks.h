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
 * BOWIE — HOOKS
 * ============================================================================
 *
 * Integration points between the Bowie engine and the
 * application that embeds it.
 *
 * A hook is a caller-supplied function pointer plus an opaque
 * userdata pointer. The engine calls the hook at defined
 * moments; the hook does whatever the application needs.
 *
 * The engine never calls a NULL hook. A hook that the caller
 * does not set is treated as "no-op", not as an error.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No default implementations. A hook that the caller does
 *     not set is skipped; the engine does not substitute its own
 *     behavior.
 *   - No threading contract. Whether hooks are called from the
 *     caller's thread or a worker thread is an engine decision,
 *     documented per hook. This header does not impose one.
 *   - No allocation ownership. A hook that allocates must free
 *     through the same allocator it used; the engine does not
 *     track hook-allocated memory.
 *   - No security decisions. Hooks observe and report; they do
 *     not decide whether a peer is allowed. That decision lives
 *     in the permission layer.
 *   - No UI. Hooks carry data; rendering is the application's
 *     job.
 *   - No custom allocator. Memory management is a platform
 *     concern, not a hook. This is deliberate: a custom
 *     allocator is not required by any current Bowie
 *     requirement, and adding one to the public API without a
 *     requirement would lock a contract prematurely.
 *   - No custom clock. Time is a platform concern, not a hook.
 *     Testing may need time abstraction, but a testing
 *     requirement is not the same as a public time-hook
 *     requirement. If a time hook is ever needed, it will be
 *     added with evidence, not in advance.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Three hooks are provided:
 *
 *   1. Log hook. Receives formatted log lines. The engine
 *      formats; the hook writes.
 *
 *   2. Event hook. Receives structured events. The engine
 *      describes; the hook reacts.
 *
 *   3. Storage hook. Reads and writes opaque blobs. The engine
 *      owns the keys; the hook owns the medium.
 *
 * All three are optional. A caller that wants a minimal embed
 * sets none of them; the engine drops log and event output and
 * uses platform storage where storage is required.
 *
 * A hook must not call back into the engine. Re-entrancy is not
 * supported. A hook that needs to act on an event should queue
 * the action and perform it after the engine call returns.
 *
 * Hook lifetimes:
 *
 *   - A hook is valid from the moment it is set until the
 *     engine is shut down or the hook is replaced.
 *   - The userdata pointer is owned by the caller. The engine
 *     does not free it, even at shutdown.
 *   - A hook must not be replaced while the engine is calling
 *     it. Replacement is safe only between engine calls.
 *
 * ----------------------------------------------------------------------------
 * Status of API details
 * ----------------------------------------------------------------------------
 *
 * The hook set itself, and the three hook kinds, are required
 * by the current design:
 *
 *   - log     required by diagnostics and CLI/UI integration
 *   - event   required by event.c and by application UI updates
 *   - storage required by platform storage abstraction
 *
 * The concrete shape of some pieces is NOT yet locked. The
 * following are proposals that must be settled by research and
 * design before they are treated as facts:
 *
 *   - event type list (bowie_event_t)
 *   - event payload size (BOWIE_EVENT_PAYLOAD_MAX)
 *   - storage read/write semantics, including the meaning of a
 *     zero-length write
 *
 * These are marked PROPOSAL in the relevant sections below. Do
 * not depend on their exact values from outside this header
 * until the proposal is accepted.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"    shared types
 *   "bowie/err.h"      error codes
 *   "bowie/config.h"   log level
 * ============================================================================
 */

#ifndef BOWIE_HOOKS_H
#define BOWIE_HOOKS_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * EVENT TYPES
 * ============================================================================
 *
 * PROPOSAL — not locked.
 *
 * The event hook is required. The event type list below is a
 * proposal for the first implementation. It is expected to
 * change as the engine's event sources are implemented.
 *
 * Do not treat the numeric values or the exact set as stable
 * until this section is marked LOCKED.
 *
 * A structured event the engine reports. An event carries an
 * event code, a subject identifier where one applies, and a
 * short payload.
 */

typedef enum bowie_event {
    BOWIE_EVENT_NONE              = 0,

    /* Engine lifecycle. */
    BOWIE_EVENT_ENGINE_STARTING   = 1,
    BOWIE_EVENT_ENGINE_STARTED    = 2,
    BOWIE_EVENT_ENGINE_STOPPING   = 3,
    BOWIE_EVENT_ENGINE_STOPPED    = 4,

    /* Peer lifecycle. */
    BOWIE_EVENT_PEER_FOUND        = 10,
    BOWIE_EVENT_PEER_CONNECTED    = 11,
    BOWIE_EVENT_PEER_DISCONNECTED = 12,
    BOWIE_EVENT_PEER_FAILED       = 13,

    /* Session lifecycle. */
    BOWIE_EVENT_SESSION_OPENED    = 20,
    BOWIE_EVENT_SESSION_CLOSED    = 21,
    BOWIE_EVENT_SESSION_DENIED    = 22,

    /* Permission lifecycle. */
    BOWIE_EVENT_GRANT_CREATED     = 30,
    BOWIE_EVENT_GRANT_REVOKED     = 31,
    BOWIE_EVENT_GRANT_EXPIRED     = 32,

    /* Tunnel lifecycle. */
    BOWIE_EVENT_TUNNEL_UP         = 40,
    BOWIE_EVENT_TUNNEL_DOWN       = 41,
    BOWIE_EVENT_TUNNEL_ERROR      = 42,

    /* Gateway lifecycle. */
    BOWIE_EVENT_GATEWAY_UP        = 50,
    BOWIE_EVENT_GATEWAY_DOWN      = 51,
    BOWIE_EVENT_GATEWAY_ERROR     = 52,

    /* NAT traversal. */
    BOWIE_EVENT_NAT_STARTED       = 60,
    BOWIE_EVENT_NAT_SUCCEEDED     = 61,
    BOWIE_EVENT_NAT_FAILED        = 62,

    /* Generic. */
    BOWIE_EVENT_ERROR             = 90,
    BOWIE_EVENT_WARNING           = 91,
} bowie_event_t;

/*
 * Event payload size.
 *
 * PROPOSAL — not locked.
 *
 * Large enough for a short message, a peer ID hex string, or a
 * path. Not large enough for a full packet or a key.
 *
 * The value may change once real events are implemented.
 */
#define BOWIE_EVENT_PAYLOAD_MAX 128

typedef struct bowie_event_record {
    bowie_event_t event;
    bowie_mtime_t time_ms;
    uint32_t      code;          /* error code, if applicable */
    bowie_peer_id_t peer_id;     /* zero if not peer-related */
    char          payload[BOWIE_EVENT_PAYLOAD_MAX];
} bowie_event_record_t;

/*
 * ============================================================================
 * LOG HOOK
 * ============================================================================
 *
 * Called by the engine when a log line is emitted at or above
 * the configured log level.
 *
 * The line is NUL-terminated and valid only for the duration of
 * the call. The hook must copy anything it needs to keep.
 *
 * The engine does not call this hook when the configured log
 * level is BOWIE_LOG_NONE.
 */

typedef void (*bowie_log_hook_fn)(bowie_log_level_t level,
                                  const char *line,
                                  void *userdata);

/*
 * ============================================================================
 * EVENT HOOK
 * ============================================================================
 *
 * Called by the engine when a structured event occurs.
 *
 * The record is valid only for the duration of the call. The
 * hook must copy anything it needs to keep.
 *
 * Events are reported at most once per occurrence. The engine
 * does not retry a hook that returns normally; a hook that
 * fails to process an event is the hook's problem, not the
 * engine's.
 */

typedef void (*bowie_event_hook_fn)(const bowie_event_record_t *rec,
                                    void *userdata);

/*
 * ============================================================================
 * STORAGE HOOK
 * ============================================================================
 *
 * Read and write opaque blobs under string keys.
 *
 * The engine uses the storage hook for:
 *
 *   - persistent peer cache
 *   - DHT routing state
 *   - revocation list
 *   - optional session resumption state
 *
 * The hook does not see plaintext secrets. Secret storage is
 * the caller's responsibility and is not routed through this
 * hook.
 *
 * ----------------------------------------------------------------------------
 * Semantics — PROPOSAL, not locked
 * ----------------------------------------------------------------------------
 *
 * Read semantics (proposal):
 *   - The hook writes up to cap bytes into buf.
 *   - On success, the hook sets *out_len to the number of bytes
 *     written and returns BOWIE_OK.
 *   - If the key does not exist, the hook returns
 *     BOWIE_ERR_NOT_FOUND.
 *   - If the buffer is too small, the hook returns
 *     BOWIE_ERR_TOO_SMALL and sets *out_len to the required
 *     size.
 *
 * Write semantics (proposal):
 *   - The hook writes len bytes from buf under key.
 *   - On success, the hook returns BOWIE_OK.
 *   - A len of 0 deletes the key.
 *
 * The zero-length-write-as-delete rule is a proposal. It is
 * convenient, but it is not required by any current Bowie
 * requirement, and it should be confirmed or replaced before
 * the storage hook is treated as stable.
 *
 * The hook must be reentrant-safe against itself only for the
 * duration of one call. The engine does not call the storage
 * hook concurrently for the same key.
 */

typedef bowie_error_t (*bowie_storage_read_fn)(const char *key,
                                               uint8_t *buf,
                                               size_t cap,
                                               size_t *out_len,
                                               void *userdata);

typedef bowie_error_t (*bowie_storage_write_fn)(const char *key,
                                                const uint8_t *buf,
                                                size_t len,
                                                void *userdata);

/*
 * ============================================================================
 * HOOK SET
 * ============================================================================
 *
 * The set of hooks a caller can install. Each hook is optional.
 *
 * The set is passed to the engine by pointer; the engine copies
 * it at init time. The caller may free the set after
 * bowie_init() returns.
 */

typedef struct bowie_hooks {

    /*
     * Logging.
     */
    bowie_log_hook_fn      log;
    void                  *log_userdata;

    /*
     * Events.
     */
    bowie_event_hook_fn    event;
    void                  *event_userdata;

    /*
     * Storage.
     */
    bowie_storage_read_fn  storage_read;
    bowie_storage_write_fn storage_write;
    void                  *storage_userdata;

} bowie_hooks_t;

/*
 * ============================================================================
 * HOOK HELPERS
 * ============================================================================
 */

/*
 * Fill a hook set with all hooks cleared.
 *
 * A cleared hook set is valid. The engine will drop log and
 * event output and use platform storage where storage is
 * required.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_hooks_clear(bowie_hooks_t *hooks);

/*
 * Check whether a hook set is internally consistent.
 *
 * Returns BOWIE_OK when the set can be used as-is. Returns an
 * ARGUMENT-class error when userdata is set without the
 * corresponding function.
 *
 * This function does not modify the set.
 */
bowie_error_t bowie_hooks_validate(const bowie_hooks_t *hooks);

/*
 * ============================================================================
 * EVENT HELPERS
 * ============================================================================
 */

/*
 * Return a stable, human-readable name for an event code.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 *
 * PROPOSAL — the names returned for proposal event codes are
 * not yet locked.
 */
const char *bowie_event_name(bowie_event_t event);

/*
 * ============================================================================
 * END OF PUBLIC HOOKS
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_HOOKS_H */
