#ifndef BOWIE_LINUX_EGRESS_H
#define BOWIE_LINUX_EGRESS_H

#include <stddef.h>
#include <net/if.h>
#include <pthread.h>

typedef struct bowie_linux_egress {
    char table[IFNAMSIZ + 32];
    int forwarding_was_enabled;
    int forwarding_changed;
    int table_created;
    int active;
} bowie_linux_egress_t;

#define BOWIE_LINUX_ROUTE_HOST_MAX 80u
typedef struct bowie_linux_client_routes {
    char tun_name[IFNAMSIZ];
    char hosts4[BOWIE_LINUX_ROUTE_HOST_MAX][16];
    char hosts6[BOWIE_LINUX_ROUTE_HOST_MAX][46];
    unsigned host4_count;
    unsigned host6_count;
    unsigned host4_rules_added;
    unsigned host6_rules_added;
    pthread_mutex_t lock;
    int lock_initialized;
    int ipv4_table_added;
    int ipv4_guard_added;
    int ipv6_table_added;
    int ipv4_catchall_added;
    int ipv6_catchall_added;
    int dns_configured;
    unsigned table_id;
    char dns_server[16];
} bowie_linux_client_routes_t;

int bowie_linux_egress_start(bowie_linux_egress_t *state,
                             const char *tun_name,
                             const char *overlay_ip,
                             unsigned prefix_len);
void bowie_linux_egress_stop(bowie_linux_egress_t *state);

int bowie_linux_client_routes_start(bowie_linux_client_routes_t *state,
                                    const char *tun_name,
                                    const char *const *underlay_hosts,
                                    size_t host_count,
                                    const char *dns_server);
void bowie_linux_client_routes_stop(bowie_linux_client_routes_t *state);
int bowie_linux_client_routes_add(bowie_linux_client_routes_t *state,
                                  int family, const uint8_t *address,
                                  size_t address_len);

#endif
