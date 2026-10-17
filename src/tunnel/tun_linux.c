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
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/tun_linux.h"
#include "tunnel/mtu.h"

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 */

struct bowie_tun {
    int  fd;
    char name[IFNAMSIZ];
};

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
    bowie_tun_t     *tun;
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

    tun = (bowie_tun_t *)calloc(1, sizeof(*tun));

    if (tun == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    tun->fd = -1;

    fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        free(tun);

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
        free(tun);
        return BOWIE_ERR_SOCKET;
    }

    tun->fd = fd;

    strncpy(tun->name, ifr.ifr_name, IFNAMSIZ - 1);
    tun->name[IFNAMSIZ - 1] = '\0';

    {
        bowie_error_t rc = set_mtu(tun->name, effective_mtu);

        if (rc != BOWIE_OK) {
            close(tun->fd);
            free(tun);
            return rc;
        }
    }

    *out = tun;

    return BOWIE_OK;
}

void bowie_tun_close(bowie_tun_t *tun)
{
    if (tun == NULL) {
        return;
    }

    if (tun->fd >= 0) {
        close(tun->fd);
        tun->fd = -1;
    }

    free(tun);
}

int bowie_tun_fd(const bowie_tun_t *tun)
{
    if (tun == NULL) {
        return -1;
    }

    return tun->fd;
}

/*
 * ============================================================================
 * I/O
 * ============================================================================
 */

long bowie_tun_read(bowie_tun_t *tun, void *buf, size_t cap)
{
    ssize_t n;

    if (tun == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cap == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * read() returns exactly one packet. If cap is smaller
     * than the packet, the kernel truncates the packet. The
     * caller is responsible for sizing the buffer.
     */
    n = read(tun->fd, buf, cap);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return BOWIE_ERR_AGAIN;
        }

        return BOWIE_ERR_NETWORK;
    }

    return (long)n;
}

long bowie_tun_write(bowie_tun_t *tun, const void *buf, size_t len)
{
    ssize_t n;

    if (tun == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (len == 0) {
        return BOWIE_ERR_INVAL;
    }

    n = write(tun->fd, buf, len);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return BOWIE_ERR_AGAIN;
        }

        return BOWIE_ERR_NETWORK;
    }

    return (long)n;
}

/*
 * ============================================================================
 * END OF TUNNEL TUN (LINUX)
 * ============================================================================
 */
