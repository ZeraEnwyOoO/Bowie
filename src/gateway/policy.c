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
 * BOWIE — GATEWAY: POLICY (IMPLEMENTATION)
 * ============================================================================
 */

#include <string.h>

#include "bowie/err.h"
#include "gateway/policy.h"

static int entry_matches(const bowie_policy_entry_t *e,
                         const uint8_t addr[4])
{
    uint8_t prefix = e->prefix_len;

    if (prefix > 32) {
        return 0;
    }

    uint8_t full_bytes = (uint8_t)(prefix / 8u);
    if (memcmp(e->addr, addr, full_bytes) != 0) {
        return 0;
    }

    uint8_t rem = (uint8_t)(prefix % 8u);
    if (rem == 0) {
        return 1;
    }

    uint8_t mask = (uint8_t)(0xFFu << (8u - rem));
    if ((e->addr[full_bytes] & mask) != (addr[full_bytes] & mask)) {
        return 0;
    }

    return 1;
}

void bowie_policy_clear(bowie_policy_t *p)
{
    if (p == NULL) {
        return;
    }

    memset(p, 0, sizeof(*p));
}

bowie_error_t bowie_policy_allow(bowie_policy_t *p,
                                 const uint8_t addr[4],
                                 uint8_t prefix_len)
{
    if (p == NULL || addr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (prefix_len > 32) {
        return BOWIE_ERR_INVAL;
    }

    if (p->allow_count >= BOWIE_POLICY_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    memcpy(p->allow[p->allow_count].addr, addr, 4);
    p->allow[p->allow_count].prefix_len = prefix_len;
    p->allow_count++;

    return BOWIE_OK;
}

bowie_error_t bowie_policy_block(bowie_policy_t *p,
                                 const uint8_t addr[4],
                                 uint8_t prefix_len)
{
    if (p == NULL || addr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (prefix_len > 32) {
        return BOWIE_ERR_INVAL;
    }

    if (p->block_count >= BOWIE_POLICY_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    memcpy(p->block[p->block_count].addr, addr, 4);
    p->block[p->block_count].prefix_len = prefix_len;
    p->block_count++;

    return BOWIE_OK;
}

int bowie_policy_is_allowed(const bowie_policy_t *p,
                            const uint8_t addr[4])
{
    size_t i;

    if (p == NULL || addr == NULL) {
        return 0;
    }

    /* Blocklist first. */
    for (i = 0; i < p->block_count; i++) {
        if (entry_matches(&p->block[i], addr)) {
            return 0;
        }
    }

    /* Empty allowlist means "allow everything else". */
    if (p->allow_count == 0) {
        return 1;
    }

    for (i = 0; i < p->allow_count; i++) {
        if (entry_matches(&p->allow[i], addr)) {
            return 1;
        }
    }

    return 0;
}
