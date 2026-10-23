#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>

#include "platform/platform.h"

bowie_error_t bowie_platform_if_list(bowie_platform_if_list_t *out)
{
    struct ifaddrs *interfaces = NULL;
    if (out == NULL) return BOWIE_ERR_NULL_ARG;
    memset(out, 0, sizeof(*out));
    if (getifaddrs(&interfaces) != 0) return BOWIE_ERR_INTERNAL;

    for (struct ifaddrs *it = interfaces; it != NULL; it = it->ifa_next) {
        if (it->ifa_name == NULL || it->ifa_addr == NULL) continue;
        int family = it->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        if (out->count == BOWIE_PLATFORM_IF_MAX) {
            out->truncated = 1;
            break;
        }

        bowie_platform_if_t *entry = &out->ifs[out->count++];
        strncpy(entry->name, it->ifa_name, sizeof(entry->name) - 1u);
        entry->is_up = (it->ifa_flags & IFF_UP) != 0;
        entry->is_loopback = (it->ifa_flags & IFF_LOOPBACK) != 0;
        entry->index = if_nametoindex(it->ifa_name);
        if (family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)it->ifa_addr;
            entry->addr.family = BOWIE_AF_INET;
            memcpy(entry->addr.addr, &sin->sin_addr, 4u);
        } else {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)it->ifa_addr;
            entry->addr.family = BOWIE_AF_INET6;
            memcpy(entry->addr.addr, &sin6->sin6_addr, 16u);
        }
    }

    freeifaddrs(interfaces);
    return BOWIE_OK;
}
