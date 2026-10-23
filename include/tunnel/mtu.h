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
 * BOWIE — TUNNEL MTU
 * ============================================================================
 *
 * MTU helpers for the Bowie tunnel.
 *
 * The tunnel encapsulates IP packets inside its own transport.
 * The MTU of the tunnel device must be small enough that the
 * encapsulated packet still fits the underlying path MTU. This
 * header declares the helpers that pick a safe value.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No device configuration.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The accepted range is [BOWIE_TUN_MTU_MIN, BOWIE_TUN_MTU_MAX].
 * The minimum accepted interface MTU is 1100 bytes. The
 * transport fragments larger encrypted messages, so the normal
 * Ethernet MTU (1500) does not need to be reduced.
 *
 * The tunnel default is 1500 bytes. bowie_mtu_suggest() remains
 * available to calculate a conservative value for a specified
 * underlying path MTU.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stddef.h>          size_t
 * ============================================================================
 */

#ifndef BOWIE_TUNNEL_MTU_H
#define BOWIE_TUNNEL_MTU_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The minimum accepted MTU, in bytes.
 *
 * The current overlay carries IPv4 packets and uses 1100 bytes
 * as its minimum supported interface MTU.
 */
#define BOWIE_TUN_MTU_MIN  1100u

/*
 * The maximum accepted MTU, in bytes.
 *
 * 9000 is the common jumbo frame ceiling.
 */
#define BOWIE_TUN_MTU_MAX  9000u

/*
 * The default underlying MTU, in bytes.
 *
 * 1500 is the Ethernet MTU.
 */
#define BOWIE_TUN_MTU_DEFAULT  1500u

/*
 * The default tunnel MTU, in bytes. Bowie packet fragmentation
 * keeps the encrypted transport datagrams under 1200 bytes.
 */
#define BOWIE_TUN_MTU_TUNNEL  1500u

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True when the MTU is within the accepted range.
 *
 * Returns 1 when BOWIE_TUN_MTU_MIN <= mtu <= BOWIE_TUN_MTU_MAX,
 * 0 otherwise.
 */
int bowie_mtu_is_valid(size_t mtu);

/*
 * Suggest a tunnel MTU for the given underlying MTU.
 *
 * The tunnel overhead is subtracted from the underlying MTU.
 * The result is clamped to the accepted range. If the
 * underlying MTU is too small to carry the minimum supported
 * overlay packet after the overhead is subtracted, the safe default
 * (BOWIE_TUN_MTU_TUNNEL) is returned instead.
 *
 * A caller that wants to force a smaller MTU must set it
 * explicitly; this function only suggests a safe value.
 */
size_t bowie_mtu_suggest(size_t underlying_mtu);

/*
 * ============================================================================
 * END OF TUNNEL MTU
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_TUNNEL_MTU_H */
