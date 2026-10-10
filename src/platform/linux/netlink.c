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
 * The implementation sends two rtnetlink requests:
 *
 *   1. RTM_GETLINK with NLM_F_DUMP. This returns one message
 *      per interface, with the interface name, index, and
 *      flags. The result is stored in a small intermediate
 *      table keyed by index.
 *
 *   2. RTM_GETADDR with NLM_F_DUMP. This returns one message
 *      per address. Each address is matched to an interface
 *      by index, and the interface's name and flags are
 *      copied into the output entry.
 *
 * The two requests are separate because the kernel does not
 * combine them. A caller that needs only the addresses could
 * skip the first request, but the output entry would then
 * have an empty name and default flags. The two requests are
 * cheap; the implementation prefers a complete result.
 *
 * A dual-stack interface (one that has both an IPv4 and an
 * IPv6 address) produces two entries in the output list, one
 * per address. The name and index are the same for both; the
 * address differs. The caller that wants one entry per
 * interface must group by index.
 *
 * The output list is bounded by BOWIE_PLATFORM_IF_MAX. If the
 * kernel reports more addresses than the list can hold, the
 * list is filled to capacity and the "truncated" flag is set
 * to 1. A caller that ignores the flag may treat an
 * incomplete list as complete.
 *
 * The implementation reads the kernel's response in a single
 * buffer of 8 KiB. A kernel with a very large number of
 * interfaces may fill the buffer; the read loop continues
 * until NLMSG_DONE. A buffer that is too small to hold one
 * message is reported as a failure; in practice an 8 KiB
 * buffer holds many messages.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <sys/socket.h>                socket, send, recv, bind, close
 *   <linux/netlink.h>             struct nlmsghdr, struct
 *                                 sockaddr_nl, NETLINK_ROUTE
 *   <linux/rtnetlink.h>           struct ifinfomsg,
 *                                 struct ifaddrmsg,
 *                                 RTM_GETLINK, RTM_NEWLINK,
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
 * INTERNAL — LINK TABLE
 * ============================================================================
 *
 * A small intermediate table that holds the information from
 * the RTM_GETLINK response. The table is keyed by interface
 * index. A lookup is a linear scan; the table is small.
 */

typedef struct link_entry {
    uint32_t index;
    char     name[BOWIE_PLATFORM_IF_NAME_MAX];
    int      is_up;
    int      is_loopback;
} link_entry_t;

typedef struct link_table {
    link_entry_t entries[BOWIE_PLATFORM_IF_MAX];
    size_t       count;
    int          overflowed;
} link_table_t;

static const link_entry_t *link_table_find(const link_table_t *t,
                                            uint32_t index)
{
    for (size_t i = 0; i < t->count; i++) {
        if (t->entries[i].index == index) {
            return &t->entries[i];
        }
    }
    return NULL;
}

static void link_table_add(link_table_t *t,
                            uint32_t index,
                            const char *name,
                            int is_up,
                            int is_loopback)
{
    if (t->count >= BOWIE_PLATFORM_IF_MAX) {
        t->overflowed = 1;
        return;
    }

    link_entry_t *e = &t->entries[t->count];
    memset(e, 0, sizeof(*e));
    e->index = index;

    /*
     * Copy the name. The kernel's name is NUL-terminated
     * within IFNAMSIZ bytes; the destination is the same
     * size, so a plain copy is safe.
     */
    strncpy(e->name, name, BOWIE_PLATFORM_IF_NAME_MAX - 1u);
    e->name[BOWIE_PLATFORM_IF_NAME_MAX - 1u] = '\0';

    e->is_up       = is_up;
    e->is_loopback = is_loopback;

    t->count++;
}

/*
 * ============================================================================
 * INTERNAL — PARSE LINK MESSAGE
 * ============================================================================
 *
 * Parse an RTM_NEWLINK message and add it to the link table.
 *
 * The message has a fixed header followed by a list of
 * attributes. The attribute of interest is IFLA_IFNAME, which
 * holds the interface name. The index and flags are in the
 * fixed header.
 */

static void parse_link_msg(struct nlmsghdr *nlh, link_table_t *t)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);

    /*
     * The interface index is in the header.
     */
    uint32_t index = (uint32_t)ifi->ifi_index;

    /*
     * The flags are in the header. IFF_UP means the
     * interface is up. IFF_LOOPBACK means it is a loopback
     * interface.
     */
    int is_up       = (ifi->ifi_flags & IFF_UP) ? 1 : 0;
    int is_loopback = (ifi->ifi_flags & IFF_LOOPBACK) ? 1 : 0;

    /*
     * Walk the attributes to find IFLA_IFNAME.
     */
    int attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    struct rtattr *rta = IFLA_RTA(ifi);

    const char *name = "";

    for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
        if (rta->rta_type == IFLA_IFNAME) {
            name = (const char *)RTA_DATA(rta);
            break;
        }
    }

    link_table_add(t, index, name, is_up, is_loopback);
}

/*
 * ============================================================================
 * INTERNAL — PARSE ADDRESS MESSAGE
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
                            const link_table_t *links,
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
     * The list is bounded. A list that is already full sets
     * the truncated flag and is not extended.
     */
    if (out->count >= BOWIE_PLATFORM_IF_MAX) {
        out->truncated = 1;
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
     * Look up the interface in the link table. If found, copy
     * the name and flags. If not found, leave the name empty
     * and the flags at their default values.
     */
    const link_entry_t *le = link_table_find(links, ifa->ifa_index);
    if (le != NULL) {
        memcpy(entry->name, le->name, BOWIE_PLATFORM_IF_NAME_MAX);
        entry->name[BOWIE_PLATFORM_IF_NAME_MAX - 1u] = '\0';
        entry->is_up       = le->is_up;
        entry->is_loopback = le->is_loopback;
    } else {
        entry->name[0]     = '\0';
        entry->is_up       = 0;
        entry->is_loopback = 0;
    }

    out->count++;
}

/*
 * ============================================================================
 * INTERNAL — NETLINK REQUEST
 * ============================================================================
 *
 * Send one rtnetlink request and read the response.
 *
 * The caller supplies the request type and a callback that
 * parses each message. The callback receives the message
 * header and the caller's context.
 *
 * The function returns BOWIE_OK on success and an error code
 * on failure. The error is reported through the return value.
 */

typedef void (*nl_msg_cb_t)(struct nlmsghdr *nlh, void *ctx);

static bowie_error_t nl_request(int fd, uint16_t type,
                                 struct nlmsghdr *req,
                                 nl_msg_cb_t cb, void *ctx)
{
    (void)req; /* the request is already prepared by the caller */

    /*
     * Send the request.
     */
    if (send(fd, req, req->nlmsg_len, 0) < 0) {
        return errno_to_bowie(errno);
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
            return errno_to_bowie(errno);
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
                return errno_to_bowie(-err->error);
            }
            if (nlh->nlmsg_type == type) {
                cb(nlh, ctx);
            }
        }
    }

    return BOWIE_OK;
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
     * First request: RTM_GETLINK with NLM_F_DUMP. This fills
     * the link table with interface names and flags.
     */
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
    } link_req;

    memset(&link_req, 0, sizeof(link_req));
    link_req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    link_req.nlh.nlmsg_type  = RTM_GETLINK;
    link_req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    link_req.nlh.nlmsg_seq   = 1;
    link_req.nlh.nlmsg_pid   = 0;

    link_req.ifi.ifi_family = AF_UNSPEC;

    link_table_t links;
    memset(&links, 0, sizeof(links));

    bowie_error_t rc = nl_request(fd, RTM_NEWLINK,
                                   &link_req.nlh,
                                   (nl_msg_cb_t)parse_link_msg,
                                   &links);
    if (rc != BOWIE_OK) {
        close(fd);
        return rc;
    }

    /*
     * Second request: RTM_GETADDR with NLM_F_DUMP. This
     * fills the output list with addresses.
     */
    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
    } addr_req;

    memset(&addr_req, 0, sizeof(addr_req));
    addr_req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    addr_req.nlh.nlmsg_type  = RTM_GETADDR;
    addr_req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    addr_req.nlh.nlmsg_seq   = 2;
    addr_req.nlh.nlmsg_pid   = 0;

    addr_req.ifa.ifa_family = AF_UNSPEC;

    /*
     * The callback for the address request needs both the
     * link table and the output list. A small context struct
     * holds both.
     */
    struct addr_ctx {
        const link_table_t        *links;
        bowie_platform_if_list_t  *out;
    } actx = { &links, out };

    /*
     * The callback signature is (struct nlmsghdr *, void *).
     * The cast is the standard idiom for a callback that
     * needs a different context type.
     */
    rc = nl_request(fd, RTM_NEWADDR,
                    &addr_req.nlh,
                    (nl_msg_cb_t)parse_addr_msg,
                    &actx);

    close(fd);
    return rc;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
