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
 * BOWIE — GATEWAY: LIMIT (IMPLEMENTATION)
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/limit.h"

static size_t find_peer(const bowie_limit_t *l,
                        const bowie_peer_id_t *peer)
{
    size_t i;

    for (i = 0; i < l->count; i++) {
        if (bowie_peer_id_equal(&l->peer[i], peer)) {
            return i;
        }
    }

    return BOWIE_LIMIT_CAP;
}

void bowie_limit_clear(bowie_limit_t *l)
{
    if (l == NULL) {
        return;
    }

    memset(l, 0, sizeof(*l));
}

bowie_error_t bowie_limit_set(bowie_limit_t *l,
                              const bowie_peer_id_t *peer,
                              uint32_t max_connections)
{
    size_t idx;

    if (l == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (bowie_peer_id_is_zero(peer)) {
        return BOWIE_ERR_INVAL;
    }

    idx = find_peer(l, peer);

    if (idx != BOWIE_LIMIT_CAP) {
        l->max_conn[idx] = max_connections;
        return BOWIE_OK;
    }

    if (l->count >= BOWIE_LIMIT_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    l->peer[l->count]     = *peer;
    l->max_conn[l->count] = max_connections;
    l->cur_conn[l->count] = 0;
    l->count++;

    return BOWIE_OK;
}

bowie_error_t bowie_limit_acquire(bowie_limit_t *l,
                                  const bowie_peer_id_t *peer)
{
    size_t idx;

    if (l == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = find_peer(l, peer);

    if (idx == BOWIE_LIMIT_CAP) {
        /* No limit for this peer. */
        return BOWIE_OK;
    }

    if (l->max_conn[idx] != 0 &&
        l->cur_conn[idx] >= l->max_conn[idx]) {
        return BOWIE_ERR_QUOTA;
    }

    l->cur_conn[idx]++;
    return BOWIE_OK;
}

bowie_error_t bowie_limit_release(bowie_limit_t *l,
                                  const bowie_peer_id_t *peer)
{
    size_t idx;

    if (l == NULL || peer == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    idx = find_peer(l, peer);

    if (idx == BOWIE_LIMIT_CAP) {
        return BOWIE_OK;
    }

    if (l->cur_conn[idx] > 0) {
        l->cur_conn[idx]--;
    }

    return BOWIE_OK;
}
