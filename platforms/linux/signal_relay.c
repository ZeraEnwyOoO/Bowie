#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/internal/diag_json.h"
#include "engine/internal/signal_relay.h"

#define RELAY_PEER_CAP 4096u
#define RELAY_TTL_SECONDS 60
#define RELAY_PACKET_MAX 65507u

typedef struct relay_peer {
    uint8_t id[BOWIE_PEER_ID_LEN];
    struct sockaddr_in address;
    time_t updated_at;
    int used;
} relay_peer_t;

static volatile sig_atomic_t relay_running = 1;

static void stop_relay(int signal_number)
{
    (void)signal_number;
    relay_running = 0;
}

static int same_address(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_family == b->sin_family && a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static relay_peer_t *find_peer(relay_peer_t *peers, const uint8_t *id)
{
    for (size_t i = 0u; i < RELAY_PEER_CAP; ++i)
        if (peers[i].used && memcmp(peers[i].id, id, BOWIE_PEER_ID_LEN) == 0)
            return &peers[i];
    return NULL;
}

static relay_peer_t *find_or_allocate_peer(relay_peer_t *peers, const uint8_t *id,
                                            time_t now)
{
    relay_peer_t *available = NULL;
    for (size_t i = 0u; i < RELAY_PEER_CAP; ++i) {
        if (peers[i].used && memcmp(peers[i].id, id, BOWIE_PEER_ID_LEN) == 0)
            return &peers[i];
        if (!peers[i].used || now - peers[i].updated_at > RELAY_TTL_SECONDS)
            available = &peers[i];
    }
    return available;
}

static void log_peer_event(const char *event, const uint8_t *peer,
                           const struct sockaddr_in *address,
                           const char *result)
{
    char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
    char details[128];
    bowie_diag_hex(peer, BOWIE_PEER_ID_LEN, peer_hex, sizeof(peer_hex));
    (void)snprintf(details, sizeof(details),
        "{\"ip\":\"%u.%u.%u.%u\",\"port\":%u,\"result\":\"%s\"}",
        (unsigned)((const uint8_t *)&address->sin_addr)[0],
        (unsigned)((const uint8_t *)&address->sin_addr)[1],
        (unsigned)((const uint8_t *)&address->sin_addr)[2],
        (unsigned)((const uint8_t *)&address->sin_addr)[3],
        (unsigned)ntohs(address->sin_port), result);
    bowie_diag_json_emit("INFO", "SignalRelay", event, peer_hex, details);
}

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_in bind_address;
    relay_peer_t *peers;
    uint8_t input[RELAY_PACKET_MAX], output[RELAY_PACKET_MAX];
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <bind-ip|0.0.0.0> <udp-port>\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || port == 0u || port > 65535u) {
        fprintf(stderr, "Invalid UDP port.\n");
        return EXIT_FAILURE;
    }
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, argv[1], &bind_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid bind IPv4 address.\n");
        return EXIT_FAILURE;
    }
    peers = (relay_peer_t *)calloc(RELAY_PEER_CAP, sizeof(*peers));
    if (peers == NULL) return EXIT_FAILURE;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) != 0) {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        free(peers);
        fprintf(stderr, "Signal relay bind failed: errno=%d\n", saved_errno);
        return EXIT_FAILURE;
    }
    signal(SIGINT, stop_relay);
    signal(SIGTERM, stop_relay);
    {
        char details[96];
        (void)snprintf(details, sizeof(details),
            "{\"bind_ip\":\"%s\",\"port\":%lu}", argv[1], port);
        bowie_diag_json_emit("INFO", "SignalRelay", "RELAY_STARTED", NULL, details);
    }

    while (relay_running) {
        struct sockaddr_in source_address;
        socklen_t source_len = sizeof(source_address);
        ssize_t got = recvfrom(fd, input, sizeof(input), 0,
                               (struct sockaddr *)&source_address, &source_len);
        if (got < 0) {
            if (errno == EINTR) continue;
            break;
        }
        bowie_signal_relay_packet_t packet;
        if (!bowie_signal_relay_decode(input, (size_t)got, &packet)) continue;
        time_t now = time(NULL);
        if (packet.type == BOWIE_SIGNAL_RELAY_REGISTER && packet.payload_len == 0u) {
            relay_peer_t *entry = find_or_allocate_peer(peers, packet.source, now);
            if (entry == NULL) continue;
            memcpy(entry->id, packet.source, BOWIE_PEER_ID_LEN);
            entry->address = source_address;
            entry->updated_at = now;
            entry->used = 1;
            log_peer_event("PEER_REGISTERED", packet.source, &source_address, "ok");
            continue;
        }
        if (packet.type != BOWIE_SIGNAL_RELAY_DATA || packet.payload_len == 0u) continue;
        relay_peer_t *sender = find_peer(peers, packet.source);
        relay_peer_t *target = find_peer(peers, packet.target);
        if (sender == NULL || !same_address(&sender->address, &source_address) ||
            now - sender->updated_at > RELAY_TTL_SECONDS) {
            log_peer_event("DATA_REJECTED", packet.source, &source_address,
                           "sender_not_registered");
            continue;
        }
        if (target == NULL || now - target->updated_at > RELAY_TTL_SECONDS) {
            log_peer_event("TARGET_UNAVAILABLE", packet.target, &source_address,
                           "target_not_registered");
            continue;
        }
        size_t output_len = 0u;
        if (!bowie_signal_relay_encode(output, sizeof(output),
                BOWIE_SIGNAL_RELAY_FORWARD, packet.source, packet.target,
                packet.payload, packet.payload_len, &output_len)) continue;
        ssize_t sent = sendto(fd, output, output_len, 0,
                              (struct sockaddr *)&target->address,
                              sizeof(target->address));
        log_peer_event(sent == (ssize_t)output_len ? "SIGNAL_FORWARDED" : "FORWARD_FAILED",
                       packet.source, &target->address,
                       sent == (ssize_t)output_len ? "ok" : "send_failed");
        sender->updated_at = now;
    }

    bowie_diag_json_emit("INFO", "SignalRelay", "RELAY_STOPPED", NULL, "{}");
    close(fd);
    free(peers);
    return EXIT_SUCCESS;
}
