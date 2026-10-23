#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gateway/ip_forward.h"
#include "egress.h"

static int run_nft(char *const args[])
{
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        execvp("nft", args);
        _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int default_uplink(char out[IFNAMSIZ])
{
    FILE *routes = fopen("/proc/net/route", "r");
    char line[256];
    if (routes == NULL) return 0;
    (void)fgets(line, sizeof(line), routes);
    int found = 0;
    unsigned long best_metric = ~0ul;
    while (fgets(line, sizeof(line), routes) != NULL) {
        char name[IFNAMSIZ];
        unsigned long destination, gateway, metric;
        unsigned flags, refcnt, use, mtu, window, irtt;
        int fields = sscanf(line, "%15s %lx %lx %x %u %u %lu %u %u %u",
                            name, &destination, &gateway, &flags, &refcnt,
                            &use, &metric, &mtu, &window, &irtt);
        if (fields == 10 && destination == 0ul && (flags & 1u) != 0u &&
            metric < best_metric) {
            (void)snprintf(out, IFNAMSIZ, "%s", name);
            best_metric = metric;
            found = 1;
        }
    }
    fclose(routes);
    return found;
}

static int valid_interface(const char *name)
{
    return name != NULL && name[0] != '\0' && strnlen(name, IFNAMSIZ) < IFNAMSIZ &&
           strchr(name, '/') == NULL;
}

int bowie_linux_egress_start(bowie_linux_egress_t *state,
                             const char *tun_name,
                             const char *overlay_ip,
                             unsigned prefix_len)
{
    char uplink[IFNAMSIZ];
    struct in_addr address;
    if (state == NULL || !valid_interface(tun_name) || overlay_ip == NULL ||
        prefix_len > 32u || inet_pton(AF_INET, overlay_ip, &address) != 1) return 0;
    memset(state, 0, sizeof(*state));
    if (!default_uplink(uplink)) return 2;
    if (strcmp(uplink, tun_name) == 0) return 0;

    uint32_t host = ntohl(address.s_addr);
    uint32_t mask = prefix_len == 0u ? 0u : UINT32_MAX << (32u - prefix_len);
    struct in_addr network = { .s_addr = htonl(host & mask) };
    char subnet[INET_ADDRSTRLEN + 5];
    if (snprintf(subnet, sizeof(subnet), "%s/%u", inet_ntoa(network), prefix_len) >=
        (int)sizeof(subnet)) return 0;
    (void)snprintf(state->table, sizeof(state->table), "bowie_%ld", (long)getpid());

    int forwarding = bowie_ip_forward_is_enabled();
    if (forwarding < 0) return 0;
    state->forwarding_was_enabled = forwarding != 0;
    if (!state->forwarding_was_enabled) {
        if (bowie_ip_forward_set(1) != BOWIE_OK) return 0;
        state->forwarding_changed = 1;
    }

    char *new_table[] = { "nft", "add", "table", "inet", state->table, NULL };
    char *forward_chain[] = { "nft", "add", "chain", "inet", state->table,
        "forward", "{", "type", "filter", "hook", "forward", "priority",
        "-50", ";", "policy", "accept", ";", "}", NULL };
    char *nat_chain[] = { "nft", "add", "chain", "inet", state->table,
        "postrouting", "{", "type", "nat", "hook", "postrouting", "priority",
        "srcnat", ";", "policy", "accept", ";", "}", NULL };
    if (!run_nft(new_table)) goto fail;
    state->table_created = 1;
    if (!run_nft(forward_chain) || !run_nft(nat_chain)) goto fail;
    char *outbound[] = { "nft", "add", "rule", "inet", state->table, "forward",
        "iifname", (char *)tun_name, "oifname", uplink, "accept", NULL };
    char *inbound[] = { "nft", "add", "rule", "inet", state->table, "forward",
        "iifname", uplink, "oifname", (char *)tun_name, "ct", "state",
        "established,related", "accept", NULL };
    char *masquerade[] = { "nft", "add", "rule", "inet", state->table,
        "postrouting", "oifname", uplink, "ip", "saddr", subnet, "masquerade", NULL };
    char *block_v6[] = { "nft", "add", "rule", "inet", state->table, "forward",
        "iifname", (char *)tun_name, "meta", "nfproto", "ipv6", "drop", NULL };
    static const char *const blocked_v4[] = {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"
    };
    if (!run_nft(block_v6)) goto fail;
    for (size_t i = 0; i < sizeof(blocked_v4) / sizeof(blocked_v4[0]); ++i) {
        char *block_v4[] = { "nft", "add", "rule", "inet", state->table, "forward",
            "iifname", (char *)tun_name, "ip", "daddr", (char *)blocked_v4[i],
            "drop", NULL };
        if (!run_nft(block_v4)) goto fail;
    }
    if (!run_nft(outbound) || !run_nft(inbound) || !run_nft(masquerade)) goto fail;
    state->active = 1;
    return 1;

fail:
    bowie_linux_egress_stop(state);
    return 0;
}

void bowie_linux_egress_stop(bowie_linux_egress_t *state)
{
    if (state == NULL) return;
    if (state->table_created && state->table[0] != '\0') {
        char *delete_table[] = { "nft", "delete", "table", "inet", state->table, NULL };
        (void)run_nft(delete_table);
    }
    if (state->forwarding_changed)
        (void)bowie_ip_forward_set(0);
    memset(state, 0, sizeof(*state));
}

static int run_ip(char *const args[])
{
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        execvp("ip", args);
        _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_resolvectl(char *const args[])
{
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        execvp("resolvectl", args);
        _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int ip_output(char *const args[], char *buffer, size_t capacity)
{
    int descriptors[2];
    pid_t child;
    size_t used = 0u;
    int status;
    if (buffer == NULL || capacity < 2u || pipe(descriptors) != 0) return 0;
    child = fork();
    if (child < 0) {
        close(descriptors[0]); close(descriptors[1]);
        return 0;
    }
    if (child == 0) {
        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0) _exit(127);
        close(descriptors[1]);
        execvp("ip", args);
        _exit(127);
    }
    close(descriptors[1]);
    while (used + 1u < capacity) {
        ssize_t got = read(descriptors[0], buffer + used, capacity - used - 1u);
        if (got > 0) used += (size_t)got;
        else if (got == 0) break;
        else if (errno != EINTR) { close(descriptors[0]); return 0; }
    }
    close(descriptors[0]);
    buffer[used] = '\0';
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 && used + 1u < capacity;
}

static int route_table_empty(unsigned table_id, int ipv6)
{
    char table[16];
    char *args4[] = { "ip", "-4", "route", "show", "table", "all", NULL };
    char *args6[] = { "ip", "-6", "route", "show", "table", "all", NULL };
    char output[65536];
    (void)snprintf(table, sizeof(table), "%u", table_id);
    if (!ip_output(ipv6 ? args6 : args4, output, sizeof(output))) return 0;
    char needle[32];
    (void)snprintf(needle, sizeof(needle), "table %s", table);
    return strstr(output, needle) == NULL;
}

static int policy_rules_compatible(int ipv6)
{
    char output[4096];
    char *args4[] = { "ip", "-4", "rule", "show", NULL };
    char *args6[] = { "ip", "-6", "rule", "show", NULL };
    char *line;
    if (!ip_output(ipv6 ? args6 : args4, output, sizeof(output))) return 0;
    for (line = strtok(output, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        char *end = NULL;
        unsigned long priority = strtoul(line, &end, 10);
        if (end == line || *end != ':' || priority == 0ul) continue;
        /* Do not override another VPN or custom routing policy. */
        if (priority != 32766ul && priority != 32767ul) return 0;
    }
    return 1;
}

int bowie_linux_client_routes_start(bowie_linux_client_routes_t *state,
                                    const char *tun_name,
                                    const char *const *underlay_hosts,
                                    size_t host_count,
                                    const char *dns_server)
{
    static const unsigned table_id = 51827u;
    char table[16];
    char priority[16];
    char host[INET_ADDRSTRLEN + 4];
    struct in_addr dns_address;
    char *route4[10];
    char *route6[9];
    char *rule4[12];
    char *rule6[10];
    if (state == NULL || !valid_interface(tun_name) || underlay_hosts == NULL ||
        host_count > BOWIE_LINUX_ROUTE_HOST_MAX ||
        dns_server == NULL || inet_pton(AF_INET, dns_server, &dns_address) != 1) return 0;
    memset(state, 0, sizeof(*state));
    state->table_id = table_id;
    (void)snprintf(state->tun_name, sizeof(state->tun_name), "%s", tun_name);
    (void)snprintf(state->dns_server, sizeof(state->dns_server), "%s", dns_server);
    for (size_t i = 0u; i < host_count; ++i) {
        struct in_addr parsed;
        if (underlay_hosts[i] == NULL ||
            inet_pton(AF_INET, underlay_hosts[i], &parsed) != 1) return 0;
        (void)snprintf(state->hosts4[i], sizeof(state->hosts4[i]), "%s", underlay_hosts[i]);
        for (size_t j = 0u; j < i; ++j) {
            if (strcmp(state->hosts4[i], state->hosts4[j]) == 0) {
                memmove(&state->hosts4[i], &state->hosts4[i + 1u],
                        (host_count - i - 1u) * sizeof(state->hosts4[0]));
                --i;
                --host_count;
                break;
            }
        }
    }
    state->host4_count = (unsigned)host_count;
    if (pthread_mutex_init(&state->lock, NULL) != 0) return 0;
    state->lock_initialized = 1;
    if (!policy_rules_compatible(0) || !policy_rules_compatible(1) ||
        !route_table_empty(table_id, 0) || !route_table_empty(table_id, 1)) return 0;

    (void)snprintf(table, sizeof(table), "%u", table_id);
    route4[0] = "ip"; route4[1] = "-4"; route4[2] = "route";
    route4[3] = "add"; route4[4] = "default"; route4[5] = "dev";
    route4[6] = (char *)tun_name; route4[7] = NULL;
    if (!run_ip(route4)) goto fail;
    state->ipv4_table_added = 1;
    {
        char *guard4[] = { "ip", "-4", "route", "add", "unreachable",
                           "default", "metric", "42760", "table", table, NULL };
        if (!run_ip(guard4)) goto fail;
        state->ipv4_guard_added = 1;
    }
    route6[0] = "ip"; route6[1] = "-6"; route6[2] = "route";
    route6[3] = "add"; route6[4] = "blackhole"; route6[5] = "default";
    route6[6] = "table"; route6[7] = table; route6[8] = NULL;
    if (!run_ip(route6)) goto fail;
    state->ipv6_table_added = 1;

    for (unsigned i = 0u; i < state->host4_count; ++i) {
        (void)snprintf(host, sizeof(host), "%s/32", state->hosts4[i]);
        (void)snprintf(priority, sizeof(priority), "%u", 10u + i);
        rule4[0] = "ip"; rule4[1] = "-4"; rule4[2] = "rule";
        rule4[3] = "add"; rule4[4] = "priority"; rule4[5] = priority;
        rule4[6] = "to"; rule4[7] = host; rule4[8] = "lookup";
        rule4[9] = "main"; rule4[10] = NULL;
        if (!run_ip(rule4)) goto fail;
        ++state->host4_rules_added;
    }
    (void)snprintf(priority, sizeof(priority), "%u", 100u);
    rule4[0] = "ip"; rule4[1] = "-4"; rule4[2] = "rule";
    rule4[3] = "add"; rule4[4] = "priority"; rule4[5] = priority;
    rule4[6] = "lookup"; rule4[7] = table; rule4[8] = NULL;
    if (!run_ip(rule4)) goto fail;
    state->ipv4_catchall_added = 1;
    rule6[0] = "ip"; rule6[1] = "-6"; rule6[2] = "rule";
    rule6[3] = "add"; rule6[4] = "priority"; rule6[5] = priority;
    rule6[6] = "lookup"; rule6[7] = table; rule6[8] = NULL;
    if (!run_ip(rule6)) goto fail;
    state->ipv6_catchall_added = 1;
    {
        char *dns_args[] = { "resolvectl", "dns", state->tun_name,
                             state->dns_server, NULL };
        char *domain_args[] = { "resolvectl", "domain", state->tun_name,
                                "~.", NULL };
        if (!run_resolvectl(dns_args)) goto fail;
        state->dns_configured = 1;
        if (!run_resolvectl(domain_args)) goto fail;
    }
    return 1;

fail:
    bowie_linux_client_routes_stop(state);
    return 0;
}

void bowie_linux_client_routes_stop(bowie_linux_client_routes_t *state)
{
    char table[16];
    char priority[16];
    char host[INET_ADDRSTRLEN + 4];
    char *rule4[12];
    char *rule6[10];
    char *route4[10];
    char *route6[9];
    if (state == NULL) return;
    if (state->dns_configured) {
        char *dns_revert[] = { "resolvectl", "revert", state->tun_name, NULL };
        (void)run_resolvectl(dns_revert);
    }
    (void)snprintf(table, sizeof(table), "%u", state->table_id);
    (void)snprintf(priority, sizeof(priority), "%u", 100u);
    if (state->ipv6_catchall_added) {
        rule6[0] = "ip"; rule6[1] = "-6"; rule6[2] = "rule";
        rule6[3] = "del"; rule6[4] = "priority"; rule6[5] = priority;
        rule6[6] = "lookup"; rule6[7] = table; rule6[8] = NULL;
        (void)run_ip(rule6);
    }
    if (state->ipv4_catchall_added) {
        rule4[0] = "ip"; rule4[1] = "-4"; rule4[2] = "rule";
        rule4[3] = "del"; rule4[4] = "priority"; rule4[5] = priority;
        rule4[6] = "lookup"; rule4[7] = table; rule4[8] = NULL;
        (void)run_ip(rule4);
    }
    for (unsigned i = state->host4_rules_added; i > 0u; --i) {
        unsigned index = i - 1u;
        (void)snprintf(host, sizeof(host), "%s/32", state->hosts4[index]);
        (void)snprintf(priority, sizeof(priority), "%u", 10u + index);
        rule4[0] = "ip"; rule4[1] = "-4"; rule4[2] = "rule";
        rule4[3] = "del"; rule4[4] = "priority"; rule4[5] = priority;
        rule4[6] = "to"; rule4[7] = host; rule4[8] = "lookup";
        rule4[9] = "main"; rule4[10] = NULL;
        (void)run_ip(rule4);
    }
    for (unsigned i = state->host6_rules_added; i > 0u; --i) {
        unsigned index = i - 1u;
        char host6[INET6_ADDRSTRLEN + 4];
        (void)snprintf(host6, sizeof(host6), "%s/128", state->hosts6[index]);
        (void)snprintf(priority, sizeof(priority), "%u", 10u + index);
        rule6[0] = "ip"; rule6[1] = "-6"; rule6[2] = "rule";
        rule6[3] = "del"; rule6[4] = "priority"; rule6[5] = priority;
        rule6[6] = "to"; rule6[7] = host6; rule6[8] = "lookup";
        rule6[9] = "main"; rule6[10] = NULL;
        (void)run_ip(rule6);
    }
    (void)snprintf(priority, sizeof(priority), "%u", 100u);
    if (state->ipv6_table_added) {
        route6[0] = "ip"; route6[1] = "-6"; route6[2] = "route";
        route6[3] = "del"; route6[4] = "blackhole"; route6[5] = "default";
        route6[6] = "table"; route6[7] = table; route6[8] = NULL;
        (void)run_ip(route6);
    }
    if (state->ipv4_table_added) {
        route4[0] = "ip"; route4[1] = "-4"; route4[2] = "route";
        route4[3] = "del"; route4[4] = "default"; route4[5] = "dev";
        /* Delete only the route this instance installed in its private table. */
        route4[6] = state->tun_name;
        route4[7] = "table";
        route4[8] = table;
        route4[9] = NULL;
        (void)run_ip(route4);
    }
    if (state->ipv4_guard_added) {
        char *guard4[] = { "ip", "-4", "route", "del", "unreachable",
                           "default", "metric", "42760", "table", table, NULL };
        (void)run_ip(guard4);
    }
    if (state->lock_initialized) pthread_mutex_destroy(&state->lock);
    memset(state, 0, sizeof(*state));
}

int bowie_linux_client_routes_add(bowie_linux_client_routes_t *state,
                                  int family, const uint8_t *address,
                                  size_t address_len)
{
    char text[INET6_ADDRSTRLEN];
    char prefix[INET6_ADDRSTRLEN + 4];
    char priority[16];
    char *rule[12];
    char *host_slot;
    unsigned *count;
    unsigned *added;
    size_t required;
    const char *family_arg;
    if (state == NULL || !state->lock_initialized || address == NULL) return 0;
    if (family == AF_INET) {
        required = 4u;
        count = &state->host4_count; added = &state->host4_rules_added;
        family_arg = "-4";
    } else if (family == AF_INET6) {
        required = 16u;
        count = &state->host6_count; added = &state->host6_rules_added;
        family_arg = "-6";
    } else return 0;
    if (address_len != required || inet_ntop(family, address, text, sizeof(text)) == NULL)
        return 0;
    pthread_mutex_lock(&state->lock);
    for (unsigned i = 0u; i < *count; ++i) {
        const char *existing = family == AF_INET ? state->hosts4[i] : state->hosts6[i];
        if (strcmp(existing, text) == 0) { pthread_mutex_unlock(&state->lock); return 1; }
    }
    if (*count >= BOWIE_LINUX_ROUTE_HOST_MAX) {
        pthread_mutex_unlock(&state->lock); return 0;
    }
    (void)snprintf(prefix, sizeof(prefix), "%s/%u", text, family == AF_INET ? 32u : 128u);
    (void)snprintf(priority, sizeof(priority), "%u", 10u + *count);
    rule[0] = "ip"; rule[1] = (char *)family_arg; rule[2] = "rule";
    rule[3] = "add"; rule[4] = "priority"; rule[5] = priority;
    rule[6] = "to"; rule[7] = prefix; rule[8] = "lookup";
    rule[9] = "main"; rule[10] = NULL;
    if (!run_ip(rule)) { pthread_mutex_unlock(&state->lock); return 0; }
    host_slot = family == AF_INET ? state->hosts4[*count] : state->hosts6[*count];
    (void)snprintf(host_slot, family == AF_INET ? 16u : 46u, "%s", text);
    ++*count; ++*added;
    pthread_mutex_unlock(&state->lock);
    return 1;
}
