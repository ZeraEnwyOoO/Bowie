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
 * BOWIE — TUNNEL MTU (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the MTU helpers declared in tunnel/mtu.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No configuration of a device.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The suggestion function subtracts the tunnel overhead from
 * the underlying MTU. The overhead covers the tunnel's own
 * headers and the encryption tag.
 *
 * The result is clamped to the accepted range. If the
 * underlying MTU is too small to carry the minimum supported
 * overlay packet after the overhead is subtracted, the
 * conservative tunnel default is returned
 * instead. A caller that wants to force a smaller MTU must
 * set it explicitly.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "tunnel/mtu.h"      constants and declarations
 * ============================================================================
 */

#include "tunnel/mtu.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The fixed overhead of the tunnel, in bytes.
 *
 * The value covers:
 *
 *   - an IPv4 header (20 bytes)
 *   - a UDP header (8 bytes)
 *   - a session framing header (4 bytes)
 *   - an AEAD tag (16 bytes)
 *   - a safety margin for future headers and path MTU
 *     variation (52 bytes)
 *
 * The total is 100 bytes. This helper estimates a conservative
 * interface MTU from a known underlying path MTU. The normal
 * tunnel default is 1500; the NAT backend fragments encrypted
 * messages to fit its datagram limit.
 */
#define BOWIE_MTU_OVERHEAD  100u

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

int bowie_mtu_is_valid(size_t mtu)
{
    if (mtu < BOWIE_TUN_MTU_MIN) {
        return 0;
    }
    if (mtu > BOWIE_TUN_MTU_MAX) {
        return 0;
    }
    return 1;
}

size_t bowie_mtu_suggest(size_t underlying_mtu)
{
    size_t suggested;

    /*
     * If the underlying MTU is too small to even subtract the
     * overhead, return the conservative interface default.
     */
    if (underlying_mtu <= BOWIE_MTU_OVERHEAD) {
        return BOWIE_TUN_MTU_TUNNEL;
    }

    suggested = underlying_mtu - BOWIE_MTU_OVERHEAD;

    /*
     * The result must fit the accepted range. A value below
     * the minimum supported overlay MTU is raised to the
     * conservative default; a value
     * above the maximum is lowered to the maximum.
     */
    if (suggested < BOWIE_TUN_MTU_MIN) {
        return BOWIE_TUN_MTU_TUNNEL;
    }

    if (suggested > BOWIE_TUN_MTU_MAX) {
        return BOWIE_TUN_MTU_MAX;
    }

    return suggested;
}

/*
 * ============================================================================
 * END OF TUNNEL MTU IMPLEMENTATION
 * ============================================================================
 */
