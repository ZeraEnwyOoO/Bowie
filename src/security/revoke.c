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
 * BOWIE — SECURITY: REVOCATION (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the revocation list helpers declared in
 * security/revoke.h.
 *
 * The list is a fixed-capacity array. Operations are O(n) in
 * the number of entries; for the expected size (a few
 * hundred) this is faster than any indexed structure.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No persistence. The list lives in the caller's memory.
 *   - No signature verification.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The add and remove operations are idempotent: adding an
 * entry that is already present succeeds without changing the
 * list, and removing an entry that is not present succeeds
 * without changing the list. This makes the two operations
 * safe to retry.
 *
 * The lookup is a linear scan. A grant ID is 16 bytes and the
 * list is small; the scan touches a few kilobytes of memory
 * and is well within the cache.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>              memmove
 *   "bowie/types.h"         bowie_grant_id_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "security/revoke.h"     declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/revoke.h"

/*
 * ============================================================================
 * INTERNAL — FIND
 * ============================================================================
 *
 * Return the index of the grant ID in the list, or
 * BOWIE_REVOKE_CAP if it is not present.
 */

static size_t find_entry(const bowie_revoke_list_t *list,
                         const bowie_grant_id_t *id)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (bowie_grant_id_equal(&list->entries[i], id)) {
            return i;
        }
    }

    return BOWIE_REVOKE_CAP;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_revoke_list_clear(bowie_revoke_list_t *list)
{
    if (list == NULL) {
        return;
    }

    list->count = 0;
}

/*
 * ============================================================================
 * MUTATION
 * ============================================================================
 */

bowie_error_t bowie_revoke_list_add(bowie_revoke_list_t *list,
                                    const bowie_grant_id_t *id)
{
    size_t idx;

    if (list == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (bowie_grant_id_is_zero(id)) {
        return BOWIE_ERR_INVAL;
    }

    idx = find_entry(list, id);

    if (idx != BOWIE_REVOKE_CAP) {
        /*
         * Already present. The operation is idempotent.
         */
        return BOWIE_OK;
    }

    if (list->count >= BOWIE_REVOKE_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    list->entries[list->count] = *id;
    list->count += 1;

    return BOWIE_OK;
}

bowie_error_t bowie_revoke_list_remove(bowie_revoke_list_t *list,
                                       const bowie_grant_id_t *id)
{
    size_t idx;

    if (list == NULL || id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = find_entry(list, id);

    if (idx == BOWIE_REVOKE_CAP) {
        /*
         * Not present. The operation is idempotent.
         */
        return BOWIE_OK;
    }

    /*
     * Shift the remaining entries down by one. The moved
     * region may overlap with the destination, so memmove is
     * used rather than memcpy.
     */
    if (idx + 1u < list->count) {
        memmove(&list->entries[idx],
                &list->entries[idx + 1u],
                (list->count - idx - 1u) * sizeof(list->entries[0]));
    }

    list->count -= 1;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

int bowie_revoke_list_contains(const bowie_revoke_list_t *list,
                               const bowie_grant_id_t *id)
{
    if (list == NULL || id == NULL) {
        return 0;
    }

    return (find_entry(list, id) != BOWIE_REVOKE_CAP) ? 1 : 0;
}

size_t bowie_revoke_list_count(const bowie_revoke_list_t *list)
{
    if (list == NULL) {
        return 0;
    }

    return list->count;
}

/*
 * ============================================================================
 * END OF SECURITY REVOCATION IMPLEMENTATION
 * ============================================================================
 */
