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
 * BOWIE — SECURITY: PERMISSION
 * ============================================================================
 *
 * Permission check for a connection.
 *
 * This is the top of the security stack. It combines the
 * grant, the proof of ownership, the revocation list, and the
 * session into a single decision: may this peer connect?
 *
 * The decision is made once, at session establishment. Once
 * the connection is authorized, the gateway and tunnel trust
 * it; they do not re-check per packet.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key generation.
 *   - No I/O.
 *   - No session key derivation. That is done by
 *     bowie_session_new(), which the caller runs after the
 *     permission check succeeds.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The check is a sequence of independent conditions. Each
 * condition is a separate function so that a caller can
 * report which one failed. The combined check runs them in
 * order and stops at the first failure.
 *
 * The order is:
 *
 *   1. The grant is not NULL and the issuer matches the
 *      expected owner.
 *   2. The grant has not expired.
 *   3. The grant has not been revoked.
 *   4. The grant allows the requested capability.
 *   5. The peer's proof of ownership is valid.
 *
 * A failure at any step produces a specific error code. The
 * caller can map the code to a user-facing message.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_grant_t, bowie_public_id_t,
 *                           bowie_peer_id_t, bowie_wtime_t,
 *                           bowie_span_t
 *   "bowie/err.h"           bowie_error_t
 *   "security/revoke.h"     bowie_revoke_list_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_PERMISSION_H
#define BOWIE_SECURITY_PERMISSION_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/revoke.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

/*
 * Check whether a peer is allowed to connect.
 *
 * The check runs the five conditions described in the design
 * notes. It stops at the first failure and returns a specific
 * error code for that failure.
 *
 * The `now` argument is the current wall-clock time. A caller
 * that has a trusted clock uses it; a caller that does not can
 * use a value from time.h.
 *
 * The `challenge` and `signature` arguments are the peer's
 * proof of ownership. The proof is checked against the
 * grant's subject: a peer that proves a different key is
 * rejected even if the grant is valid.
 *
 * Returns BOWIE_OK when every condition passes.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_OWNER_MISMATCH if the grant's issuer does
 *   not match the expected owner.
 * Returns BOWIE_ERR_GRANT_EXPIRED if the grant has expired.
 * Returns BOWIE_ERR_GRANT_REVOKED if the grant is in the
 *   revocation list.
 * Returns BOWIE_ERR_PERMISSION if the grant does not allow
 *   the requested capability.
 * Returns BOWIE_ERR_SUBJECT_MISMATCH if the proof of
 *   ownership does not match the grant's subject.
 * Returns BOWIE_ERR_SIGN_INVALID if the proof of ownership is
 *   not a valid signature.
 */
bowie_error_t bowie_permission_check_list(
    const bowie_grant_t       *grant,
    const bowie_public_id_t   *owner,
    const bowie_revoke_list_t *revoke_list,
    uint32_t                   capability,
    const bowie_peer_id_t     *subject_id,
    bowie_span_t               challenge,
    bowie_span_t               signature,
    bowie_wtime_t              now);

/*
 * ============================================================================
 * END OF SECURITY PERMISSION
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_PERMISSION_H */
