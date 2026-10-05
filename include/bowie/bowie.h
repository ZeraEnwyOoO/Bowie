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
 * BOWIE — MAIN PUBLIC HEADER
 * ============================================================================
 *
 * The single include a consumer needs to embed the Bowie engine.
 *
 * This header pulls in the foundational Bowie headers and
 * declares the engine lifecycle API.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No module-specific API. Functions for DHT, tunnel,
 *     gateway, permission, and crypto are declared in the
 *     headers that own those capabilities, not here. This
 *     header is the entry point, not a grab-bag.
 *   - No policy. This header does not decide what the engine
 *     should do; it exposes how to create, start, stop, and
 *     destroy it.
 *   - No platform detection. Platform selection is a build-time
 *     concern and is handled by the build system.
 *   - No implementation details. The engine handle is opaque.
 *     Its layout is private to the engine source, not part of
 *     the public contract.
 *
 * ----------------------------------------------------------------------------
 * Status of API details
 * ----------------------------------------------------------------------------
 *
 * LOCKED (DESIGN DECISION, approved):
 *
 *   - Engine ownership is HANDLE-BASED, matching Xury's style.
 *     There is no process-wide singleton. A consumer creates one
 *     or more engines with bowie_create() and owns each handle.
 *
 *   - Lifecycle signatures:
 *       bowie_engine_t *bowie_create(const bowie_config_t *config);
 *       bowie_error_t   bowie_start(bowie_engine_t *e);
 *       bowie_error_t   bowie_stop(bowie_engine_t *e);
 *       void            bowie_destroy(bowie_engine_t *e);
 *
 *   - bowie_grant_t is a transparent struct. See its definition
 *     below. The definition matches the grant fields documented
 *     for PoO v1.
 *
 *   - NULL semantics:
 *       config == NULL  -> use library defaults
 *       hooks  == NULL  -> no hooks
 *
 * UNKNOWN (not designed yet, do not invent):
 *
 *   - The engine lifecycle state machine. Which calls are valid
 *     in which order, and what error is returned for an
 *     out-of-order call, is not decided.
 *
 *   - The exact list of subsystems bowie_start() brings up.
 *     DHT, NAT, tunnel, and gateway are named in the design
 *     document, but the start order, the failure handling, and
 *     the relationship between them are not settled.
 *
 *   - Socket API semantics. bowie_get_socket_fd() and
 *     bowie_detach_socket() appear in the design document, but
 *     their behavior, ownership, and relationship to the tunnel
 *     and to Xury are not decided.
 *
 *   - Connection and peer API semantics. bowie_connect(),
 *     bowie_disconnect(), bowie_add_peer(), and
 *     bowie_remove_peer() appear in the design document, but
 *     their behavior is not settled.
 *
 *   - Owner and permission API semantics. bowie_owner_init(),
 *     bowie_owner_get_public_id(), bowie_grant_new(),
 *     bowie_grant_sign(), and bowie_grant_verify() appear in
 *     the design document, but their behavior is not settled.
 *
 * Nothing in this header is a promise about the behavior of a
 * function whose semantics are listed as UNKNOWN. The signatures
 * may change when those semantics are designed.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The public API is intentionally small. Every function here
 * has one job and one return value. Functions that could be
 * expressed in terms of other functions are not included.
 *
 * The engine handle is opaque. A consumer never dereferences
 * it; it is passed back to the library. This keeps the engine's
 * internal layout free to change without breaking the public
 * contract.
 *
 * A consumer that needs multiple engines can create multiple
 * handles. There is no global engine state. This matches the
 * design principle already applied to Xury: no god-struct, no
 * implicit process-wide state.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/version.h"   version constants
 *   "bowie/err.h"       error codes
 *   "bowie/types.h"     shared types
 *   "bowie/config.h"    configuration
 *   "bowie/hooks.h"     integration hooks
 * ============================================================================
 */

#ifndef BOWIE_BOWIE_H
#define BOWIE_BOWIE_H

#include "bowie/version.h"
#include "bowie/err.h"
#include "bowie/types.h"
#include "bowie/config.h"
#include "bowie/hooks.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * GRANT
 * ============================================================================
 *
 * LOCKED (DESIGN DECISION, approved).
 *
 * A permission grant, as defined by the PoO v1 security model.
 *
 * The struct is transparent: a consumer may read its fields.
 * The fields are fixed-size value types so that a grant can be
 * copied, stored, and serialized without allocation.
 *
 * The signature field holds an Ed25519 signature over the
 * canonical encoding of the other fields. The exact canonical
 * encoding is a protocol concern and is not defined here.
 *
 * A grant with an all-zero subject or issuer is unset.
 * An all-zero grant_id is unset.
 * An all-zero signature is unset.
 *
 * The permissions field is a bitmask. The meaning of each bit
 * is a permission-layer concern and is not defined here.
 */

typedef struct bowie_grant {
    bowie_public_id_t subject;      /* peer's Ed25519 public key */
    bowie_public_id_t issuer;       /* owner's Ed25519 public key */
    bowie_grant_id_t  grant_id;     /* nonce chosen by the owner */
    uint32_t          permissions;  /* bitmask; meaning is layer-defined */
    bowie_wtime_t     issued_at;    /* wall-clock time, ms since epoch */
    bowie_wtime_t     expires_at;   /* wall-clock time, ms since epoch */
    uint8_t           signature[64];/* Ed25519 signature */
} bowie_grant_t;

/*
 * ============================================================================
 * ENGINE LIFECYCLE
 * ============================================================================
 *
 * LOCKED (DESIGN DECISION, approved): handle-based.
 *
 * The engine is an opaque handle. A consumer creates one with
 * bowie_create() and destroys it with bowie_destroy(). Multiple
 * engines may coexist in one process; there is no global engine
 * state.
 *
 * ----------------------------------------------------------------------------
 * UNKNOWN: lifecycle state machine
 * ----------------------------------------------------------------------------
 *
 * The order in which create/start/stop/destroy may be called,
 * and the error returned for an out-of-order call, is NOT
 * decided. The following is the intended shape, not a locked
 * contract:
 *
 *   created
 *       |
 *       | bowie_start()
 *       v
 *   running
 *       |
 *       | bowie_stop()
 *       v
 *   stopped
 *       |
 *       | bowie_destroy()
 *       v
 *   destroyed
 *
 * A consumer must not assume this shape until the state machine
 * is designed. A call that is valid in one implementation may
 * be rejected in another.
 */

/*
 * ----------------------------------------------------------------------------
 * bowie_create
 * ----------------------------------------------------------------------------
 *
 * Create an engine handle.
 *
 * config == NULL means "use library defaults".
 * hooks  == NULL means "no hooks".
 *
 * The engine copies the configuration and the hook set. The
 * caller may free either after this call returns.
 *
 * On success, returns a non-NULL handle owned by the caller.
 * The caller must eventually call bowie_destroy() on it.
 *
 * On failure, returns NULL. The reason for failure is not
 * reported through this call; a consumer that needs a reason
 * should validate its configuration and hooks before calling
 * bowie_create().
 *
 * UNKNOWN: whether a NULL return is the only failure mode, or
 * whether a diagnostic hook is called before returning NULL.
 */
bowie_engine_t *bowie_create(const bowie_config_t *config,
                             const bowie_hooks_t *hooks);

/*
 * ----------------------------------------------------------------------------
 * bowie_start
 * ----------------------------------------------------------------------------
 *
 * Start the engine.
 *
 * UNKNOWN: the exact list of subsystems this brings up, the
 * order, and the failure handling. The design document names
 * DHT, NAT, tunnel, and gateway as subsystems the engine may
 * use, but the start sequence and the relationship between them
 * are not settled. Do not assume a specific start order or a
 * specific failure atomicity until this is designed.
 *
 * Returns:
 *   BOWIE_OK          if the engine started.
 *   BOWIE_ERR_INVAL   if the handle is NULL.
 *   other errors      as reported by the failing subsystem.
 *                     The class of the error identifies which
 *                     subsystem reported the failure.
 *
 * UNKNOWN: whether a failed start leaves the engine in a
 * partially started state, a cleanly stopped state, or an
 * undefined state. Do not assume.
 */
bowie_error_t bowie_start(bowie_engine_t *e);

/*
 * ----------------------------------------------------------------------------
 * bowie_stop
 * ----------------------------------------------------------------------------
 *
 * Stop the engine.
 *
 * UNKNOWN: whether stop releases all resources acquired by
 * start, whether it leaves any subsystem in a resumable state,
 * and whether stop is idempotent. Do not assume.
 *
 * Returns:
 *   BOWIE_OK          if the engine stopped.
 *   BOWIE_ERR_INVAL   if the handle is NULL.
 *   other errors      as reported by a subsystem during
 *                     shutdown.
 *
 * UNKNOWN: whether a subsystem failure during stop leaves the
 * engine partially stopped, and what the consumer is expected
 * to do in that case.
 */
bowie_error_t bowie_stop(bowie_engine_t *e);

/*
 * ----------------------------------------------------------------------------
 * bowie_destroy
 * ----------------------------------------------------------------------------
 *
 * Destroy an engine handle.
 *
 * The engine must not be running when this is called. Whether
 * calling destroy on a running engine is an error, a forced
 * stop, or undefined behavior is part of the UNKNOWN state
 * machine above.
 *
 * This function does not fail. It returns nothing.
 *
 * Passing NULL is a no-op.
 *
 * UNKNOWN: whether any process-wide resource (for example an
 * OpenSSL global) is cleaned up here or elsewhere. If a
 * process-wide cleanup is ever required, it will be added as a
 * separate function with its own contract, not folded into
 * destroy.
 */
void bowie_destroy(bowie_engine_t *e);

/*
 * ============================================================================
 * FUTURE API — NOT LOCKED
 * ============================================================================
 *
 * The following function groups appear in the design document
 * and will be added to this header when the modules they depend
 * on are designed:
 *
 *   Connection:
 *     bowie_connect()
 *     bowie_disconnect()
 *
 *   Peer management:
 *     bowie_add_peer()
 *     bowie_remove_peer()
 *
 *   Owner and permission:
 *     bowie_owner_init()
 *     bowie_owner_get_public_id()
 *     bowie_grant_new()
 *     bowie_grant_sign()
 *     bowie_grant_verify()
 *
 *   Socket access:
 *     bowie_get_socket_fd()
 *     bowie_detach_socket()
 *
 * They are not declared here because their semantics depend on
 * the engine state machine and on layers that are not designed
 * yet. Declaring them early would lock a contract before the
 * evidence exists.
 * ============================================================================
 */

/*
 * ============================================================================
 * END OF PUBLIC API
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_BOWIE_H */
