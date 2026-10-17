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
 * BOWIE — GATEWAY: IP FORWARDING
 * ============================================================================
 *
 * Enable and disable IP forwarding on the host.
 *
 * The gateway needs the kernel to forward packets between the
 * tunnel interface and the Internet interface. On Linux this
 * is controlled by the net.ipv4.ip_forward sysctl and, for
 * IPv6, net.ipv6.conf.all.forwarding.
 *
 * This module provides a small wrapper around the sysctl so
 * that the gateway does not need to know how the sysctl is
 * written.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing. Forwarding is not routing. The host routing
 *     table and the iptables rules are still the caller's
 *     responsibility.
 *   - No firewall. The gateway does not add or remove
 *     iptables rules.
 *   - No persistence. The sysctl is set for the current boot.
 *     A caller that wants it to survive a reboot must write
 *     /etc/sysctl.d/ itself.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The check functions read the current sysctl value. The set
 * functions write it. The "enable" and "disable" functions
 * are convenience wrappers that set both IPv4 and IPv6 to the
 * same value.
 *
 * The path to the sysctl is a compile-time constant. A caller
 * that runs on a system with a different path must patch the
 * constant. The path is /proc/sys/net/ipv4/ip_forward for
 * IPv4 and /proc/sys/net/ipv6/conf/all/forwarding for IPv6.
 *
 * A read of a sysctl file that does not exist is reported as
 * BOWIE_ERR_NOT_SUPPORTED. A write to a file the caller
 * cannot open is reported as BOWIE_ERR_PERMISSION.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_GATEWAY_IP_FORWARD_H
#define BOWIE_GATEWAY_IP_FORWARD_H

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

/*
 * True when IPv4 forwarding is enabled.
 *
 * Returns 1 when the sysctl is 1, 0 when it is 0, and a
 * negative bowie_error_t when the sysctl cannot be read.
 */
int bowie_ip_forward_is_enabled(void);

/*
 * True when IPv6 forwarding is enabled.
 *
 * Same return shape as bowie_ip_forward_is_enabled().
 */
int bowie_ip_forward_is_enabled_v6(void);

/*
 * ============================================================================
 * SET
 * ============================================================================
 */

/*
 * Enable or disable IPv4 forwarding.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_PERMISSION if the caller lacks the
 *   privilege to write the sysctl.
 * Returns BOWIE_ERR_NETWORK if the write fails for another
 *   reason.
 */
bowie_error_t bowie_ip_forward_set(int enabled);

/*
 * Enable or disable IPv6 forwarding.
 *
 * Same return values as bowie_ip_forward_set().
 * Returns BOWIE_ERR_NOT_SUPPORTED if the host has no IPv6
 *   sysctl.
 */
bowie_error_t bowie_ip_forward_set_v6(int enabled);

/*
 * ============================================================================
 * CONVENIENCE
 * ============================================================================
 */

/*
 * Enable both IPv4 and IPv6 forwarding.
 *
 * Returns BOWIE_OK on success.
 * Returns the first error if either set fails. IPv4 is set
 * first; if it fails, IPv6 is not touched.
 */
bowie_error_t bowie_ip_forward_enable(void);

/*
 * Disable both IPv4 and IPv6 forwarding.
 *
 * Same return shape as bowie_ip_forward_enable().
 */
bowie_error_t bowie_ip_forward_disable(void);

/*
 * ============================================================================
 * END OF GATEWAY IP FORWARDING
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_IP_FORWARD_H */
