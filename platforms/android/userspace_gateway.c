/* Rootless IPv4 packet-to-socket forwarding for Android source sessions.
 * TCP is terminated locally and bridged to a protected stream socket. */
#include "userspace_gateway.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define USG_FLOW_COUNT 64u
#define USG_PACKET_MAX 1500u
#define USG_TCP_MSS 1200u

typedef struct usg_tcp_flow {
    int active;
    int fd;
    uint8_t client_ip[4];
    uint8_t server_ip[4];
    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_next;
    uint32_t server_next;
    int client_fin;
} usg_tcp_flow_t;

struct bowie_android_userspace_gateway {
    pthread_mutex_t lock;
    usg_tcp_flow_t flows[USG_FLOW_COUNT];
    uint32_t next_isn;
};

static uint16_t checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0u;
    while (len >= 2u) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2u;
        len -= 2u;
    }
    if (len != 0u) sum += (uint32_t)data[0] << 8;
    while ((sum >> 16) != 0u) sum = (sum & 0xffffu) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static uint16_t transport_checksum(const uint8_t src[4], const uint8_t dst[4],
                                   uint8_t proto, const uint8_t *segment,
                                   size_t segment_len)
{
    uint8_t pseudo[12u + USG_PACKET_MAX];
    if (segment_len > USG_PACKET_MAX) return 0u;
    memcpy(pseudo, src, 4u);
    memcpy(pseudo + 4u, dst, 4u);
    pseudo[8] = 0u;
    pseudo[9] = proto;
    pseudo[10] = (uint8_t)(segment_len >> 8);
    pseudo[11] = (uint8_t)segment_len;
    memcpy(pseudo + 12u, segment, segment_len);
    return checksum(pseudo, 12u + segment_len);
}

static size_t make_ipv4(uint8_t *out, const uint8_t src[4],
                        const uint8_t dst[4], uint8_t protocol,
                        const uint8_t *payload, size_t payload_len)
{
    size_t total = 20u + payload_len;
    if (total > USG_PACKET_MAX) return 0u;
    memset(out, 0, 20u);
    out[0] = 0x45u;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64u;
    out[9] = protocol;
    memcpy(out + 12u, src, 4u);
    memcpy(out + 16u, dst, 4u);
    if (payload_len != 0u) memcpy(out + 20u, payload, payload_len);
    uint16_t check = checksum(out, 20u);
    memcpy(out + 10u, &check, sizeof(check));
    return total;
}

static int emit_udp_reply(const uint8_t *packet, size_t ip_len,
                          const uint8_t *payload, size_t payload_len,
                          bowie_gateway_emit_fn emit, void *emit_context)
{
    uint8_t reply[USG_PACKET_MAX];
    uint8_t udp[USG_PACKET_MAX - 20u];
    size_t ip_header = (size_t)(packet[0] & 0x0fu) * 4u;
    size_t udp_len = 8u + payload_len;
    size_t total;
    if (ip_header < 20u || ip_header > ip_len || udp_len > sizeof(udp)) return 0;
    memcpy(udp, packet + ip_header + 2u, 2u);
    memcpy(udp + 2u, packet + ip_header, 2u);
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)udp_len;
    udp[6] = udp[7] = 0u;
    if (payload_len != 0u) memcpy(udp + 8u, payload, payload_len);
    memcpy(reply, packet + 16u, 4u);
    memcpy(reply + 4u, packet + 12u, 4u);
    uint16_t check = transport_checksum(reply, reply + 4u, 17u, udp, udp_len);
    memcpy(udp + 6u, &check, sizeof(check));
    total = make_ipv4(reply, packet + 16u, packet + 12u, 17u, udp, udp_len);
    return total != 0u && emit(emit_context, reply, total);
}

static int send_tcp_packet(usg_tcp_flow_t *flow, uint32_t seq, uint32_t ack,
                           uint8_t flags, const uint8_t *payload,
                           size_t payload_len, bowie_gateway_emit_fn emit,
                           void *emit_context)
{
    uint8_t tcp[USG_PACKET_MAX - 20u];
    uint8_t packet[USG_PACKET_MAX];
    size_t tcp_len = 20u + payload_len;
    size_t total;
    uint16_t check;
    if (tcp_len > sizeof(tcp)) return 0;
    memset(tcp, 0, 20u);
    memcpy(tcp, &flow->server_port, 2u);
    memcpy(tcp + 2u, &flow->client_port, 2u);
    seq = htonl(seq); ack = htonl(ack);
    memcpy(tcp + 4u, &seq, 4u);
    memcpy(tcp + 8u, &ack, 4u);
    tcp[12] = 5u << 4;
    tcp[13] = flags;
    tcp[14] = 0xffu; tcp[15] = 0xffu;
    if (payload_len != 0u) memcpy(tcp + 20u, payload, payload_len);
    check = transport_checksum(flow->server_ip, flow->client_ip, 6u,
                               tcp, tcp_len);
    memcpy(tcp + 16u, &check, 2u);
    total = make_ipv4(packet, flow->server_ip, flow->client_ip, 6u, tcp, tcp_len);
    return total != 0u && emit(emit_context, packet, total);
}

static int tuple_matches(const usg_tcp_flow_t *flow, const uint8_t *packet,
                         size_t ip_header)
{
    return flow->active && memcmp(flow->client_ip, packet + 12u, 4u) == 0 &&
        memcmp(flow->server_ip, packet + 16u, 4u) == 0 &&
        memcmp(&flow->client_port, packet + ip_header, 2u) == 0 &&
        memcmp(&flow->server_port, packet + ip_header + 2u, 2u) == 0;
}

static void close_flow(usg_tcp_flow_t *flow)
{
    if (flow->fd >= 0) close(flow->fd);
    memset(flow, 0, sizeof(*flow));
    flow->fd = -1;
}

static int connect_tcp(const uint8_t address[4], uint16_t port)
{
    struct sockaddr_in endpoint;
    struct pollfd pollfd;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int flags, error = 0;
    socklen_t error_len = sizeof(error);
    if (fd < 0) return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd); return -1;
    }
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = port;
    memcpy(&endpoint.sin_addr.s_addr, address, 4u);
    if (connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) != 0 && errno != EINPROGRESS) {
        close(fd); return -1;
    }
    pollfd.fd = fd; pollfd.events = POLLOUT; pollfd.revents = 0;
    if (poll(&pollfd, 1, 5000) <= 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
        close(fd); return -1;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    return fd;
}

static int process_tcp(bowie_android_userspace_gateway_t *gateway,
                       const uint8_t *packet, size_t ip_len,
                       size_t ip_header, bowie_gateway_emit_fn emit,
                       void *emit_context)
{
    size_t tcp_header, payload_len;
    const uint8_t *tcp = packet + ip_header;
    const uint8_t *payload;
    uint8_t flags;
    uint32_t sequence, acknowledgment;
    usg_tcp_flow_t *flow = NULL, *free_flow = NULL;
    size_t i;
    int result = 0;
    if (ip_len < ip_header + 20u) return 0;
    tcp_header = (size_t)(tcp[12] >> 4) * 4u;
    if (tcp_header < 20u || ip_len < ip_header + tcp_header) return 0;
    payload = tcp + tcp_header;
    payload_len = ip_len - ip_header - tcp_header;
    flags = tcp[13];
    memcpy(&sequence, tcp + 4u, 4u); sequence = ntohl(sequence);
    memcpy(&acknowledgment, tcp + 8u, 4u); acknowledgment = ntohl(acknowledgment);

    pthread_mutex_lock(&gateway->lock);
    for (i = 0u; i < USG_FLOW_COUNT; ++i) {
        if (tuple_matches(&gateway->flows[i], packet, ip_header)) {
            flow = &gateway->flows[i]; break;
        }
        if (!gateway->flows[i].active && free_flow == NULL) free_flow = &gateway->flows[i];
    }
    if ((flags & 0x04u) != 0u) {
        if (flow != NULL) close_flow(flow);
        pthread_mutex_unlock(&gateway->lock);
        return 1;
    }
    if ((flags & 0x02u) != 0u && (flags & 0x10u) == 0u) {
        if (flow == NULL) {
            if (free_flow == NULL) { pthread_mutex_unlock(&gateway->lock); return 0; }
            int fd = connect_tcp(packet + 16u, *(const uint16_t *)(const void *)(tcp + 2u));
            if (fd < 0) { pthread_mutex_unlock(&gateway->lock); return 0; }
            flow = free_flow;
            memset(flow, 0, sizeof(*flow));
            flow->active = 1; flow->fd = fd;
            memcpy(flow->client_ip, packet + 12u, 4u);
            memcpy(flow->server_ip, packet + 16u, 4u);
            memcpy(&flow->client_port, tcp, 2u);
            memcpy(&flow->server_port, tcp + 2u, 2u);
            flow->client_next = sequence + 1u;
            gateway->next_isn += 0x101u;
            flow->server_next = gateway->next_isn + 1u;
        }
        result = send_tcp_packet(flow, flow->server_next - 1u,
                                 flow->client_next, 0x12u, NULL, 0u,
                                 emit, emit_context);
        pthread_mutex_unlock(&gateway->lock);
        return result;
    }
    if (flow == NULL) { pthread_mutex_unlock(&gateway->lock); return 0; }
    if ((flags & 0x10u) != 0u && acknowledgment > flow->server_next)
        flow->server_next = acknowledgment;
    if (payload_len != 0u && sequence == flow->client_next) {
        size_t sent = 0u;
        while (sent < payload_len) {
            ssize_t n = send(flow->fd, payload + sent, payload_len - sent, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            sent += (size_t)n;
        }
        if (sent != payload_len) { close_flow(flow); pthread_mutex_unlock(&gateway->lock); return 0; }
        flow->client_next += (uint32_t)payload_len;
    }
    if ((flags & 0x01u) != 0u && sequence + (uint32_t)payload_len == flow->client_next) {
        flow->client_next++;
        flow->client_fin = 1;
        (void)shutdown(flow->fd, SHUT_WR);
    }
    result = send_tcp_packet(flow, flow->server_next, flow->client_next,
                             0x10u, NULL, 0u, emit, emit_context);
    if (payload_len != 0u || flow->client_fin) {
        struct pollfd pollfd;
        pollfd.fd = flow->fd; pollfd.events = POLLIN; pollfd.revents = 0;
        if (poll(&pollfd, 1, 1200) > 0 && (pollfd.revents & POLLIN) != 0) {
            uint8_t data[USG_TCP_MSS];
            for (;;) {
                ssize_t n = recv(flow->fd, data, sizeof(data), MSG_DONTWAIT);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                if (!send_tcp_packet(flow, flow->server_next, flow->client_next,
                                     0x18u, data, (size_t)n, emit, emit_context)) {
                    result = 0; break;
                }
                flow->server_next += (uint32_t)n;
            }
        }
    }
    if ((flags & 0x01u) != 0u && flow->client_fin) close_flow(flow);
    pthread_mutex_unlock(&gateway->lock);
    return result;
}

int bowie_android_userspace_gateway_new(bowie_android_userspace_gateway_t **out)
{
    bowie_android_userspace_gateway_t *gateway;
    if (out == NULL) return 0;
    *out = NULL;
    gateway = calloc(1u, sizeof(*gateway));
    if (gateway == NULL) return 0;
    if (pthread_mutex_init(&gateway->lock, NULL) != 0) { free(gateway); return 0; }
    gateway->next_isn = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)gateway;
    for (size_t i = 0u; i < USG_FLOW_COUNT; ++i) gateway->flows[i].fd = -1;
    *out = gateway;
    return 1;
}

void bowie_android_userspace_gateway_free(bowie_android_userspace_gateway_t *gateway)
{
    if (gateway == NULL) return;
    pthread_mutex_lock(&gateway->lock);
    for (size_t i = 0u; i < USG_FLOW_COUNT; ++i)
        if (gateway->flows[i].active) close_flow(&gateway->flows[i]);
    pthread_mutex_unlock(&gateway->lock);
    pthread_mutex_destroy(&gateway->lock);
    free(gateway);
}

int bowie_android_userspace_gateway_process(void *context,
        const uint8_t *packet, size_t packet_len,
        bowie_gateway_emit_fn emit, void *emit_context)
{
    bowie_android_userspace_gateway_t *gateway = context;
    size_t ip_header, ip_len;
    if (gateway == NULL || packet == NULL || emit == NULL || packet_len < 20u ||
        (packet[0] >> 4) != 4u) return 0;
    ip_header = (size_t)(packet[0] & 0x0fu) * 4u;
    ip_len = ((size_t)packet[2] << 8) | packet[3];
    if (ip_header < 20u || ip_header > packet_len || ip_len > packet_len ||
        ip_len < ip_header || (packet[6] & 0x3fu) != 0u) return 0;
    if (packet[9] == 6u)
        return process_tcp(gateway, packet, ip_len, ip_header, emit, emit_context);
    if (packet[9] == 17u) {
        struct sockaddr_in destination;
        uint8_t payload[USG_PACKET_MAX];
        size_t udp_len;
        ssize_t received;
        int fd;
        struct pollfd pollfd;
        if (ip_len < ip_header + 8u) return 0;
        udp_len = ((size_t)packet[ip_header + 4u] << 8) | packet[ip_header + 5u];
        if (udp_len < 8u || udp_len > ip_len - ip_header) return 0;
        memset(&destination, 0, sizeof(destination));
        destination.sin_family = AF_INET;
        memcpy(&destination.sin_addr.s_addr, packet + 16u, 4u);
        memcpy(&destination.sin_port, packet + ip_header + 2u, 2u);
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return 0;
        if (connect(fd, (struct sockaddr *)&destination, sizeof(destination)) != 0 ||
            send(fd, packet + ip_header + 8u, udp_len - 8u, 0) < 0) {
            close(fd); return 0;
        }
        pollfd.fd = fd; pollfd.events = POLLIN; pollfd.revents = 0;
        if (poll(&pollfd, 1, 1200) > 0 && (pollfd.revents & POLLIN) != 0) {
            received = recv(fd, payload, sizeof(payload), 0);
            if (received > 0)
                (void)emit_udp_reply(packet, ip_len, payload, (size_t)received,
                                     emit, emit_context);
        }
        close(fd);
        return 1;
    }
    return 0;
}
