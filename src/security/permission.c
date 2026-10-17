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
 * The order is chosen so that the cheapest checks come first
 * and the most informative error is produced.
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
 * The subject check is the most important one. A grant names
 * a subject; a peer that proves a different key is rejected
 * even if the grant is valid and not revoked. This is what
 * makes a stolen grant useless to an attacker who does not
 * also hold the corresponding private key.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"           types
 *   "bowie/err.h"             errors
 *   "security/grant.h"        grant fields and helpers
 *   "security/ownership.h"    proof of ownership
 *   "security/revoke.h"       revocation list
 *   "security/permission.h"   declarations
 * ============================================================================
 */

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/grant.h"
#include "security/ownership.h"
#include "security/revoke.h"
#include "security/permission.h"

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

    /*
     * 1. The grant must name the expected owner.
     */
    if (!bowie_grant_matches_issuer(grant, owner)) {
        return BOWIE_ERR_OWNER_MISMATCH;
    }

    /*
     * 2. The grant must not have expired.
     */
    if (!bowie_grant_is_time_valid(grant, now)) {
        return BOWIE_ERR_GRANT_EXPIRED;
    }

    /*
     * 3. The grant must not be revoked.
     */
    if (bowie_revoke_list_contains(revoke_list, &grant->grant_id)) {
        return BOWIE_ERR_GRANT_REVOKED;
    }

    /*
     * 4. The grant must allow the requested capability.
     */
    if (!bowie_grant_allows(grant, capability)) {
        return BOWIE_ERR_PERMISSION;
    }

    /*
     * 5. The grant must name the peer as its subject, and the
     *    peer must prove it holds the corresponding key.
     */
    if (!bowie_grant_matches_subject(grant, subject_id)) {
        return BOWIE_ERR_SUBJECT_MISMATCH;
    }

    if (bowie_ownership_verify(owner, challenge, signature)
            != BOWIE_OK) {
        return BOWIE_ERR_SIGN_INVALID;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF SECURITY PERMISSION IMPLEMENTATION
 * ============================================================================
 */
