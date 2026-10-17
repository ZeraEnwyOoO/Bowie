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
 * BOWIE — SECURITY: REVOCATION
 * ============================================================================
 *
 * Grant revocation list management.
 *
 * A grant can be revoked by its issuer before it expires. The
 * revocation is a signed statement that the grant is no
 * longer valid. A peer that holds a revoked grant must not be
 * allowed to connect, even if the grant has not yet expired.
 *
 * There is no central revocation service. Each owner
 * maintains their own revocation list, and a verifier checks
 * the grant against the issuer's list.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No storage. The list is a value type supplied by the
 *     caller.
 *   - No signature verification of the list itself.
 *   - No network I/O.
 *   - No automatic expiry. A revocation is permanent.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The list is a fixed-capacity array. The capacity is a
 * compile-time constant. A list that is full cannot accept
 * more entries; the caller must choose a capacity large
 * enough for its needs.
 *
 * The list is a value type. It can be copied and compared
 * without allocation.
 *
 * A revocation entry is a grant ID. Nothing else is needed:
 * the grant ID is a nonce that is unique to the grant, and
 * the issuer is implied by the list itself.
 *
 * The lookup is linear. For a list of a few hundred entries,
 * linear search is faster than any indexed structure because
 * it fits in cache and has no setup cost.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t, uint8_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_grant_id_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_REVOKE_H
#define BOWIE_SECURITY_REVOKE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The capacity of a revocation list, in entries.
 *
 * 256 entries is enough for a single owner to revoke a few
 * hundred grants, which is well above the expected lifetime
 * of a list before it is pruned.
 */
#define BOWIE_REVOKE_CAP 256

/*
 * ============================================================================
 * REVOCATION LIST
 * ============================================================================
 *
 * The list is a fixed-capacity array of grant IDs. The count
 * field is the number of entries currently in use.
 */

typedef struct bowie_revoke_list {
    bowie_grant_id_t entries[BOWIE_REVOKE_CAP];
    size_t           count;
} bowie_revoke_list_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a revocation list to empty.
 *
 * The count becomes zero. The entries are not cleared.
 *
 * Passing NULL is a no-op.
 */
void bowie_revoke_list_clear(bowie_revoke_list_t *list);

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

/*
 * Add a grant ID to the revocation list.
 *
 * If the grant ID is already in the list, the call succeeds
 * and the list is unchanged. This makes the operation
 * idempotent.
 *
 * If the list is full, the call fails with BOWIE_ERR_TOO_LARGE.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if list or id is NULL.
 * Returns BOWIE_ERR_INVAL if id is the all-zero value.
 * Returns BOWIE_ERR_TOO_LARGE if the list is full.
 */
bowie_error_t bowie_revoke_list_add(bowie_revoke_list_t *list,
                                    const bowie_grant_id_t *id);

/*
 * Remove a grant ID from the revocation list.
 *
 * If the grant ID is not in the list, the call is a no-op
 * and returns BOWIE_OK. This makes the operation idempotent.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if list or id is NULL.
 */
bowie_error_t bowie_revoke_list_remove(bowie_revoke_list_t *list,
                                       const bowie_grant_id_t *id);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * True when the grant ID is in the revocation list.
 *
 * Passing NULL for either argument returns 0.
 */
int bowie_revoke_list_contains(const bowie_revoke_list_t *list,
                               const bowie_grant_id_t *id);

/*
 * Return the number of entries in the list.
 *
 * Passing NULL returns 0.
 */
size_t bowie_revoke_list_count(const bowie_revoke_list_t *list);

/*
 * ============================================================================
 * END OF SECURITY REVOKE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_REVOKE_H */
