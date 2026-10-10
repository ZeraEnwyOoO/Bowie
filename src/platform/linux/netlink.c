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
 * BOWIE — LINUX NETLINK INTERFACE ENUMERATION
 * ============================================================================
 *
 * Network interface enumeration for Linux.
 *
 * The implementation uses the rtnetlink interface (NETLINK_ROUTE)
 * to enumerate local network interfaces and their addresses.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No interface configuration. This file only reads.
 *   - No route enumeration. Only interfaces and their addresses.
 *   - No allocation. Every function writes to a caller-supplied
 *     buffer.
 *   - No persistent state. Each call opens a fresh netlink
 *     socket and closes it before returning.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The rtnetlink interface is a datagram protocol over a
 * netlink socket. To enumerate interfaces, the function:
 *
 *   1. Opens a NETLINK_ROUTE socket.
 *   2. Sends an RTM_GETADDR request with NLM_F_DUMP.
 *   3. Reads the response messages.
 *   4. Parses each RTM_NEWADDR message.
 *   5. Stores the address in the output list.
 *   6. Closes the socket.
 *
 * The RTM_GETADDR request returns one message per address,
 * not per interface. An interface with both an IPv4 and an
 * IPv6 address produces two messages. The function groups
 * them by interface index.
 *
 * The function does not request RTM_GETLINK, because the
 * address messages carry the interface index and name. The
 * "is up" and "is loopback" flags come from the interface
 * flags, which are not in the address message. The function
 * reads them from a separate RTM_GETLINK request if it needs
 * them. For the first version, the flags are set to their
 * default values (up = 1, loopback = 0) and left for a
 * future version to fill in.
 *
 * The function reads at most BOWIE_PLATFORM_IF_MAX entries.
 * An interface with more addresses than that is truncated.
 *
 * The function returns BOWIE_ERR_NOT_IMPLEMENTED on a
 * platform that does not have netlink. The build system
 * selects this file only for Linux.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <sys/socket.h>                socket, send, recv, close
 *   <linux/netlink.h>             struct nlmsghdr, struct
 *                                 sockaddr_nl, NETLINK_ROUTE
 *   <linux/rtnetlink.h>           struct ifaddrmsg,
 *                                 RTM_GETADDR, RTM_NEWADDR
 *   <linux/if_addr.h>             IFA_ADDRESS, IFA_LOCAL
 *   <unistd.h>                    close
 *   <string.h>                    memset, memcpy, strncpy
 *   <errno.h>                     errno
 *   "bowie/err.h"                 error codes
 *   "platform/platform.h"         the declarations
 * ============================================================================
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "bowie/err.h"
#include "platform/platform.h"

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 */

static bowie_error_t errno_to_bowie(int e)
{
    switch (e) {
    case 0:              return BOWIE_OK;
    case EINVAL:         return BOWIE_ERR_INVAL;
    case ENOMEM:         return BOWIE_ERR_NOMEM;
    case EPERM:          return BOWIE_ERR_PERMISSION;
    case EACCES:         return BOWIE_ERR_PERMISSION;
    case ENOBUFS:        return BOWIE_ERR_NOMEM;
    default:             return BOWIE_ERR_INTERNAL;
    }
}

/*
 * ============================================================================
 * INTERNAL — PARSE ONE ADDRESS MESSAGE
 * ============================================================================
 *
 * Parse an RTM_NEWADDR message and, if the address is usable,
 * append it to the output list.
 *
 * The address message has a fixed header followed by a list
 * of attributes. The attributes of interest are IFA_LOCAL
 * (the local address, which is what we want) and IFA_ADDRESS
 * (the peer address on a point-to-point link, which we do not
 * want).
 *
 * For a normal interface, IFA_LOCAL is the address we want.
 * For a point-to-point interface, IFA_LOCAL is the local end
 * and IFA_ADDRESS is the remote end. The function uses
 * IFA_LOCAL when it is present, and falls back to IFA_ADDRESS
 * when it is not.
 */

static void parse_addr_msg(struct nlmsghdr *nlh,
                            bowie_platform_if_list_t *out)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

    /*
     * Only IPv4 and IPv6 addresses are interesting.
     */
    if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6) {
        return;
    }

    /*
     * The list is bounded. A list that is already full is not
     * extended.
     */
    if (out->count >= BOWIE_PLATFORM_IF_MAX) {
        return;
    }

    /*
     * Walk the attributes to find IFA_LOCAL or IFA_ADDRESS.
     */
    int attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
    struct rtattr *rta = IFA_RTA(ifa);
    const void *addr_data = NULL;
    size_t addr_len = 0;

    for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
        if (rta->rta_type == IFA_LOCAL) {
            addr_data = RTA_DATA(rta);
            addr_len  = RTA_PAYLOAD(rta);
            break;
        }
        if (rta->rta_type == IFA_ADDRESS) {
            /*
             * Remember the address, but keep looking for
             * IFA_LOCAL.
             */
            addr_data = RTA_DATA(rta);
            addr_len  = RTA_PAYLOAD(rta);
        }
    }

    if (addr_data == NULL || addr_len == 0u) {
        return;
    }

    bowie_platform_if_t *entry = &out->ifs[out->count];
    memset(entry, 0, sizeof(*entry));

    if (ifa->ifa_family == AF_INET && addr_len == 4u) {
        entry->addr.family = BOWIE_AF_INET;
        memcpy(entry->addr.addr, addr_data, 4u);
    } else if (ifa->ifa_family == AF_INET6 && addr_len == 16u) {
        entry->addr.family = BOWIE_AF_INET6;
        memcpy(entry->addr.addr, addr_data, 16u);
    } else {
        return;
    }

    entry->addr.port = 0u;
    entry->index     = ifa->ifa_index;

    /*
     * The interface name and flags are not in the address
     * message. They are in the link message, which this
     * function does not request. The name is left empty and
     * the flags are set to their default values.
     *
     * A future version that needs the name must send a
     * separate RTM_GETLINK request. For now, the index is
     * the identifier.
     */
    entry->name[0]    = '\0';
    entry->is_up      = 1;
    entry->is_loopback = 0;

    out->count++;
}

/*
 * ============================================================================
 * INTERFACE ENUMERATION
 * ============================================================================
 */

bowie_error_t bowie_platform_if_list(bowie_platform_if_list_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(out, 0, sizeof(*out));

    /*
     * Open a netlink socket.
     */
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        return errno_to_bowie(errno);
    }

    /*
     * Bind the socket to the current process.
     */
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        bowie_error_t err = errno_to_bowie(errno);
        close(fd);
        return err;
    }

    /*
     * Send an RTM_GETADDR request with NLM_F_DUMP. The
     * request has no attributes.
     */
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type  = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = 0;

    req.ifa.ifa_family = AF_UNSPEC;

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        bowie_error_t err = errno_to_bowie(errno);
        close(fd);
        return err;
    }

    /*
     * Read the response. The response may span multiple
     * messages; the loop reads until NLMSG_DONE or an error.
     */
    char buf[8192];
    int  done = 0;

    while (!done) {
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            bowie_error_t err = errno_to_bowie(errno);
            close(fd);
            return err;
        }
        if (got == 0) {
            break;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        int remaining = (int)got;

        for (; NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err =
                    (struct nlmsgerr *)NLMSG_DATA(nlh);
                close(fd);
                return errno_to_bowie(-err->error);
            }
            if (nlh->nlmsg_type == RTM_NEWADDR) {
                parse_addr_msg(nlh, out);
            }
        }
    }

    close(fd);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
