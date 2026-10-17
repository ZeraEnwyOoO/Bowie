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
 * The minimum is the IPv6 minimum link MTU (1280); a tunnel
 * smaller than that cannot carry IPv6 at all. The maximum is
 * the jumbo frame ceiling (9000).
 *
 * The default is 1500, the Ethernet MTU. The tunnel default
 * is the default minus the tunnel overhead.
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
 * 1280 is the IPv6 minimum link MTU (RFC 8200). A tunnel
 * smaller than this cannot carry IPv6.
 */
#define BOWIE_TUN_MTU_MIN  1280u

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
 * The default tunnel MTU, in bytes.
 *
 * This is the default underlying MTU minus the tunnel
 * overhead (100 bytes).
 */
#define BOWIE_TUN_MTU_TUNNEL  1400u

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
 * underlying MTU is too small to carry an IPv6 packet after
 * the overhead is subtracted, the safe default
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
