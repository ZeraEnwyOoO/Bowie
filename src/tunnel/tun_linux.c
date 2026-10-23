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
 * BOWIE — TUNNEL TUN (LINUX IMPLEMENTATION)
 * ============================================================================
 *
 * Linux implementation of the TUN device interface declared
 * in tunnel/tun_linux.h.
 *
 * This file uses the standard Linux TUN/TAP driver. A TUN
 * device is opened by opening /dev/net/tun and issuing the
 * TUNSETIFF ioctl with the IFF_TUN flag. The resulting file
 * descriptor is used for both reading and writing raw IP
 * packets.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing configuration. Creating a TUN device does
 *     not add routes.
 *   - No NAT. The TUN device is a plain packet pipe.
 *   - No Android.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The handle is a small struct that holds the file descriptor
 * and the interface name.
 *
 * The interface name is copied into the handle so that the
 * caller can log it or display it without calling back into
 * the kernel.
 *
 * The MTU is set with an ioctl on an AF_INET socket.
 *
 * Reading from a TUN device returns exactly one packet. The
 * kernel never splits a packet across two reads, and never
 * combines two packets into one read. The read buffer is
 * sized by the caller; if it is too small, the packet is
 * truncated. This is the documented TUN behavior.
 *
 * Writing to a TUN device injects one packet. The kernel
 * routes it as if it had arrived from the interface.
 *
 * The handle is not thread-safe. A caller that shares a TUN
 * device between threads must serialize access to it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>               errno
 *   <fcntl.h>               open, O_RDWR
 *   <linux/if_tun.h>        TUNSETIFF
 *   <net/if.h>              ifreq, IFNAMSIZ, IFF_TUN, IFF_NO_PI
 *   <stdlib.h>              calloc, free
 *   <string.h>              memset, strncpy
 *   <sys/ioctl.h>           ioctl, SIOCSIFMTU
 *   <sys/socket.h>          socket, AF_INET, SOCK_DGRAM
 *   <unistd.h>              close, read, write
 *   "bowie/types.h"         bowie_tun_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "tunnel/tun_linux.h"    public contract
 *   "tunnel/mtu.h"          MTU defaults and validation
 * ============================================================================
 */

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/tun_linux.h"
#include "tunnel/tun_internal.h"
#include "tunnel/mtu.h"

/*
 * ============================================================================
 * MTU
 * ============================================================================
 */

static bowie_error_t set_mtu(const char *name, size_t mtu)
{
    struct ifreq ifr;
    int          sock;
    int          rc;

    if (mtu > 0xFFFFu) {
        return BOWIE_ERR_TOO_LARGE;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        return BOWIE_ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_mtu = (int)mtu;

    rc = ioctl(sock, SIOCSIFMTU, &ifr);

    close(sock);

    if (rc < 0) {
        return BOWIE_ERR_NETWORK;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_tun_open(bowie_tun_t **out,
                             const char *name,
                             size_t mtu)
{
    struct ifreq     ifr;
    size_t           effective_mtu;
    int              fd;

    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (mtu == 0) {
        effective_mtu = BOWIE_TUN_MTU_TUNNEL;
    } else if (bowie_mtu_is_valid(mtu)) {
        effective_mtu = mtu;
    } else {
        return BOWIE_ERR_INVAL;
    }

    fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            return BOWIE_ERR_PERMISSION;
        }

        return BOWIE_ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (name != NULL && name[0] != '\0') {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return BOWIE_ERR_SOCKET;
    }

    bowie_error_t rc = bowie_tun_wrap_fd(out, fd, 1);
    if (rc != BOWIE_OK) {
        close(fd);
        return rc;
    }
    bowie_tun_t *tun = *out;
    bowie_tun_set_name(tun, ifr.ifr_name);

    rc = set_mtu(tun->name, effective_mtu);
    if (rc != BOWIE_OK) {
        bowie_tun_close(tun);
        *out = NULL;
        return rc;
    }
    return BOWIE_OK;
}

bowie_error_t bowie_tun_configure_ipv4(bowie_tun_t *tun,
                                       const char *address,
                                       uint8_t prefix_len)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct in_addr addr;
    struct in_addr mask;
    int sock;

    if (tun == NULL || address == NULL) return BOWIE_ERR_NULL_ARG;
    if (prefix_len > 32u || inet_pton(AF_INET, address, &addr) != 1)
        return BOWIE_ERR_INVAL;

    uint32_t mask_host = prefix_len == 0u ? 0u : (UINT32_MAX << (32u - prefix_len));
    mask.s_addr = htonl(mask_host);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return BOWIE_ERR_SOCKET;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1u);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = addr;
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) goto fail;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1u);
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    sin->sin_addr = mask;
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) goto fail;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1u);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) goto fail;
    ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) goto fail;

    close(sock);
    return BOWIE_OK;

fail:
    close(sock);
    return (errno == EPERM || errno == EACCES) ? BOWIE_ERR_PERMISSION : BOWIE_ERR_NETWORK;
}

/*
 * ============================================================================
 * END OF TUNNEL TUN (LINUX)
 * ============================================================================
 */
