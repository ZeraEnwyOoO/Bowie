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
 * The helpers are pure value functions: they take a number and
 * return a number. They do not touch the network, the
 * filesystem, or any global state.
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
 * The suggestion function subtracts a fixed overhead from the
 * underlying MTU. The overhead covers an IPv4 header, a UDP
 * header, and a small encryption margin. It is deliberately
 * generous: an MTU that is a little too small only costs a
 * little throughput, while an MTU that is too large causes
 * fragmentation and a much larger performance hit.
 *
 * The result is clamped to the accepted range. A caller that
 * passes an underlying MTU below the minimum gets the default
 * tunnel MTU, not an error: the caller asked for a
 * suggestion, and the default is the safest suggestion.
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
 * The fixed overhead subtracted from the underlying MTU when
 * suggesting a tunnel MTU.
 *
 * The value covers:
 *
 *   - an IPv4 header (20 bytes)
 *   - a UDP header (8 bytes)
 *   - a small encryption and framing margin (72 bytes)
 *
 * The total is 100 bytes, which matches the difference
 * between BOWIE_TUN_MTU_DEFAULT and BOWIE_TUN_MTU_TUNNEL.
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

    if (underlying_mtu <= BOWIE_MTU_OVERHEAD) {
        return BOWIE_TUN_MTU_TUNNEL;
    }

    suggested = underlying_mtu - BOWIE_MTU_OVERHEAD;

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
