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
 * Maximum Transmission Unit (MTU) constants and helpers for
 * the Bowie tunnel.
 *
 * The MTU is the largest packet that can be sent over an
 * interface without fragmentation. The tunnel reduces the
 * usable MTU because it adds its own headers and encryption
 * overhead to every packet.
 *
 * This header defines the constants and a small validation
 * function. It does not configure the TUN device; that is a
 * platform concern handled in tun.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O. Nothing here opens a device or sends a packet.
 *   - No configuration. The MTU is set on the TUN device by
 *     the platform backend, not by this header.
 *   - No fragmentation. Fragmentation, if needed, is a
 *     platform or protocol concern. This header only defines
 *     the values.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The default Ethernet MTU is 1500 bytes. The tunnel must
 * subtract the overhead of its own headers and encryption so
 * that the resulting packet still fits in the underlying
 * transport's MTU.
 *
 * The overhead depends on the layers above the tunnel:
 *
 *   - IPv4 or IPv6 header (20 or 40 bytes)
 *   - UDP header (8 bytes)
 *   - ICE/Session framing and encryption (variable)
 *
 * To avoid fragmentation on the most common path, the tunnel
 * MTU is set to 1400 bytes. This leaves 100 bytes of headroom
 * for headers and encryption, which is enough for IPv4 and
 * most encryption schemes.
 *
 * The absolute minimum MTU for IPv6 is 1280 bytes. Any
 * interface with an MTU below that cannot carry IPv6 traffic
 * without fragmentation. The tunnel MTU must never be set
 * below this value if IPv6 is to be supported.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stddef.h>      size_t
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
 * The default MTU of an Ethernet interface.
 *
 * This is the value the operating system assigns to a new
 * TUN or TAP device unless the caller overrides it.
 */
#define BOWIE_TUN_MTU_DEFAULT  1500

/*
 * The MTU the tunnel sets on its TUN device.
 *
 * It is 100 bytes smaller than the Ethernet default, which
 * leaves room for the tunnel's own headers and encryption
 * without forcing fragmentation on the underlying link.
 */
#define BOWIE_TUN_MTU_TUNNEL   1400

/*
 * The minimum MTU an IPv6-capable interface must support.
 *
 * Any interface with an MTU below this value cannot carry
 * IPv6 packets without fragmentation. The tunnel must not be
 * configured below this value if IPv6 is to work.
 */
#define BOWIE_TUN_MTU_MIN_IPV6 1280

/*
 * The minimum MTU the tunnel accepts.
 *
 * It matches the IPv6 minimum. A caller that wants to use an
 * even smaller MTU must know that IPv6 will not work through
 * the tunnel.
 */
#define BOWIE_TUN_MTU_MIN      BOWIE_TUN_MTU_MIN_IPV6

/*
 * The maximum MTU the tunnel accepts.
 *
 * It is the jumbo frame maximum minus a small margin. A caller
 * that wants to use an even larger MTU must know that the
 * underlying link may not support it.
 */
#define BOWIE_TUN_MTU_MAX      9000

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True when the MTU is within the range the tunnel accepts.
 *
 * The range is BOWIE_TUN_MTU_MIN to BOWIE_TUN_MTU_MAX,
 * inclusive. A value outside the range is rejected.
 */
int bowie_mtu_is_valid(size_t mtu);

/*
 * Suggest an MTU for the tunnel given the underlying MTU.
 *
 * The suggestion is the underlying MTU minus the tunnel
 * overhead, clamped to the accepted range. A caller that
 * knows the underlying link's MTU can use this to pick a
 * tunnel MTU that avoids fragmentation.
 *
 * Passing zero or a value below the tunnel minimum returns
 * BOWIE_TUN_MTU_TUNNEL, which is the safe default.
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
