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
 * BOWIE — SECURITY: PERMISSION (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the permission check declared in
 * security/permission.h.
 *
 * The check is a sequence of conditions. Each condition is
 * checked in order and the first failure stops the check.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key agreement. The session is created by the caller
 *     after the check succeeds.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every failure is logged with bowie_log_warn(). A success is
 * not logged here; a caller that wants an audit trail logs
 * it itself. This keeps the log from filling with one line
 * per connection on a busy gateway.
 *
 * The log message includes the first two bytes of the
 * subject ID. It does not include the full ID, the grant ID,
 * or any key material. This is enough to correlate a log
 * line with a peer without leaking a secret.
 *
 * The session bind is a no-op when the session is NULL. This
 * lets the unit tests run the check without creating a
 * session.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"           types
 *   "bowie/err.h"             errors
 *   "core/log.h"              bowie_log_warn
 *   "security/grant.h"        grant fields and helpers
 *   "security/ownership.h"    proof of ownership
 *   "security/revoke.h"       revocation list
 *   "security/permission.h"   declarations
 * ============================================================================
 */

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/log.h"
#include "security/grant.h"
#include "security/ownership.h"
#include "security/revoke.h"
#include "security/permission.h"

/*
 * ============================================================================
 * INTERNAL — LOG
 * ============================================================================
 *
 * Log a failed check with the first two bytes of the subject
 * ID. The subject ID is not logged in full; the first two
 * bytes are enough to correlate the line with a peer without
 * making the log a list of every peer that tried to connect.
 */

static void log_failure(const char *reason,
                        const bowie_peer_id_t *subject)
{
    if (subject == NULL) {
        bowie_log_warn("permission: %s (subject unknown)", reason);
        return;
    }

    bowie_log_warn("permission: %s (subject %02x%02x)",
                   reason,
                   subject->bytes[0],
                   subject->bytes[1]);
}

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

bowie_error_t bowie_permission_check_list(
    const bowie_grant_t       *grant,
    const bowie_public_id_t   *owner,
    const bowie_revoke_list_t *revoke_list,
    uint32_t                   capability,
    const bowie_peer_id_t     *subject_id,
    bowie_span_t               challenge,
    bowie_span_t               signature,
    bowie_wtime_t              now)
{
    if (grant == NULL || owner == NULL ||
        revoke_list == NULL || subject_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!bowie_grant_matches_issuer(grant, owner)) {
        log_failure("owner mismatch", subject_id);
        return BOWIE_ERR_OWNER_MISMATCH;
    }

    if (!bowie_grant_is_time_valid(grant, now)) {
        log_failure("grant expired", subject_id);
        return BOWIE_ERR_GRANT_EXPIRED;
    }

    if (bowie_revoke_list_contains(revoke_list, &grant->grant_id)) {
        log_failure("grant revoked", subject_id);
        return BOWIE_ERR_GRANT_REVOKED;
    }

    if (!bowie_grant_allows(grant, capability)) {
        log_failure("capability not allowed", subject_id);
        return BOWIE_ERR_PERMISSION;
    }

    if (!bowie_grant_matches_subject(grant, subject_id)) {
        log_failure("subject mismatch", subject_id);
        return BOWIE_ERR_SUBJECT_MISMATCH;
    }

    if (bowie_ownership_verify(owner, challenge, signature) != BOWIE_OK) {
        log_failure("proof of ownership invalid", subject_id);
        return BOWIE_ERR_SIGN_INVALID;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * SESSION BINDING
 * ============================================================================
 *
 * The bind step is a no-op in this version. The session
 * layer records its own authorization; the permission layer
 * only decides. A future version can add a callback or a
 * session-side flag.
 */

bowie_error_t bowie_permission_check_and_bind(
    const bowie_grant_t       *grant,
    const bowie_public_id_t   *owner,
    const bowie_revoke_list_t *revoke_list,
    uint32_t                   capability,
    const bowie_peer_id_t     *subject_id,
    bowie_span_t               challenge,
    bowie_span_t               signature,
    bowie_wtime_t              now,
    bowie_session_t           *session)
{
    (void)session;

    return bowie_permission_check_list(grant, owner, revoke_list,
                                        capability, subject_id,
                                        challenge, signature, now);
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

const char *bowie_permission_error_string(bowie_error_t rc)
{
    switch (rc) {
    case BOWIE_OK:
        return "ok";
    case BOWIE_ERR_NULL_ARG:
        return "null argument";
    case BOWIE_ERR_OWNER_MISMATCH:
        return "grant issuer does not match owner";
    case BOWIE_ERR_GRANT_EXPIRED:
        return "grant expired";
    case BOWIE_ERR_GRANT_REVOKED:
        return "grant revoked";
    case BOWIE_ERR_PERMISSION:
        return "capability not allowed";
    case BOWIE_ERR_SUBJECT_MISMATCH:
        return "subject does not match grant";
    case BOWIE_ERR_SIGN_INVALID:
        return "proof of ownership invalid";
    default:
        return "unknown permission error";
    }
}

/*
 * ============================================================================
 * END OF SECURITY PERMISSION IMPLEMENTATION
 * ============================================================================
 */
