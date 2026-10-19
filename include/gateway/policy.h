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
 * BOWIE — GATEWAY: POLICY
 * ============================================================================
 *
 * Allowlist and blocklist for the gateway.
 *
 * The owner can restrict which destinations a peer is allowed
 * to reach. The policy is a small list of CIDR ranges; a
 * destination is allowed or blocked based on which list it
 * matches first.
 *
 * The policy is a value type. The caller creates one,
 * configures it, and passes it to the gateway.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No enforcement. The gateway reads the policy and decides
 *     whether to forward a packet.
 *   - No DNS. The policy works on IP addresses, not names.
 *   - No port filtering. The policy matches on destination
 *     address only.
 *   - No persistence. The policy lives in memory.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A policy has two lists: an allowlist and a blocklist. A
 * destination is allowed when the blocklist does not contain
 * it and, if the allowlist is non-empty, the allowlist
 * contains it.
 *
 * The order is: blocklist first, then allowlist. A
 * destination that is on both lists is blocked.
 *
 * Each entry is a CIDR range. The range is stored as a base
 * address and a prefix length.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_GATEWAY_POLICY_H
#define BOWIE_GATEWAY_POLICY_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOWIE_POLICY_CAP 64

typedef struct bowie_policy_entry {
    uint8_t  addr[4];
    uint8_t  prefix_len;
} bowie_policy_entry_t;

typedef struct bowie_policy {
    bowie_policy_entry_t allow[BOWIE_POLICY_CAP];
    size_t               allow_count;

    bowie_policy_entry_t block[BOWIE_POLICY_CAP];
    size_t               block_count;
} bowie_policy_t;

void bowie_policy_clear(bowie_policy_t *p);

bowie_error_t bowie_policy_allow(bowie_policy_t *p,
                                 const uint8_t addr[4],
                                 uint8_t prefix_len);

bowie_error_t bowie_policy_block(bowie_policy_t *p,
                                 const uint8_t addr[4],
                                 uint8_t prefix_len);

int bowie_policy_is_allowed(const bowie_policy_t *p,
                            const uint8_t addr[4]);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_POLICY_H */
