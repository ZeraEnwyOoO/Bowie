#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "engine/engine.h"
#include "tunnel/tun.h"

typedef struct accept_job {
    bowie_engine_t *engine;
    bowie_peer_id_t expected_peer;
    bowie_error_t result;
} accept_job_t;

static void *accept_peer(void *arg)
{
    accept_job_t *job = (accept_job_t *)arg;
    job->result = bowie_engine_accept_from(job->engine, &job->expected_peer, 12000u);
    return NULL;
}

static int wait_packet(int fd, const uint8_t *expected, size_t expected_len)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    uint8_t packet[1500];
    int ready = poll(&pfd, 1, 8000);
    if (ready <= 0 || !(pfd.revents & POLLIN)) return 0;
    ssize_t len = recv(fd, packet, sizeof(packet), 0);
    return len == (ssize_t)expected_len && memcmp(packet, expected, expected_len) == 0;
}

int main(void)
{
    int a_pair[2] = { -1, -1 }, b_pair[2] = { -1, -1 };
    bowie_tun_t *a_tun = NULL, *b_tun = NULL;
    bowie_engine_t *a = NULL, *b = NULL;
    bowie_peer_id_t a_id, b_id;
    bowie_grant_t owner_grant;
    bowie_addr_t a_signal;
    bowie_engine_config_t config;
    accept_job_t accept_job;
    pthread_t accept_thread;
    int accept_thread_started = 0;
    int result = 1;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, a_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, b_pair) != 0) {
        perror("socketpair");
        goto done;
    }
    bowie_error_t setup_rc = bowie_tun_wrap_fd(&a_tun, a_pair[0], 1);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "wrap A tunnel failed: %d\n", setup_rc); goto done; }
    a_pair[0] = -1;
    setup_rc = bowie_tun_wrap_fd(&b_tun, b_pair[0], 1);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "wrap B tunnel failed: %d\n", setup_rc); goto done; }
    b_pair[0] = -1;

    bowie_engine_default_config(&config);
    setup_rc = bowie_engine_new(&config, &a);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "create A engine failed: %d\n", setup_rc); goto done; }
    setup_rc = bowie_engine_new(&config, &b);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "create B engine failed: %d\n", setup_rc); goto done; }
    setup_rc = bowie_engine_start(a, a_tun);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "start A engine failed: %d\n", setup_rc); goto done; }
    setup_rc = bowie_engine_start(b, b_tun);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "start B engine failed: %d\n", setup_rc); goto done; }

    bowie_engine_peer_id(a, &a_id);
    bowie_engine_peer_id(b, &b_id);
    if (bowie_engine_issue_grant(a, &b_id, BOWIE_GRANT_INTERNET_USE,
                                 86400000u, &owner_grant) != BOWIE_OK ||
        bowie_engine_set_grant(b, &owner_grant) != BOWIE_OK) {
        fprintf(stderr, "could not install the owner grant for the loopback peer\n");
        goto done;
    }
    memset(&a_signal, 0, sizeof(a_signal));
    a_signal.family = BOWIE_AF_INET;
    a_signal.addr[0] = 127u;
    a_signal.addr[3] = 1u;
    a_signal.port = bowie_engine_signal_port(a);

    memset(&accept_job, 0, sizeof(accept_job));
    accept_job.engine = a;
    accept_job.expected_peer = b_id;
    if (pthread_create(&accept_thread, NULL, accept_peer, &accept_job) != 0) goto done;
    accept_thread_started = 1;

    bowie_error_t connect_rc = bowie_engine_connect_direct(b, &a_id, &a_signal, 12000u);
    pthread_join(accept_thread, NULL);
    accept_thread_started = 0;
    if (connect_rc != BOWIE_OK || accept_job.result != BOWIE_OK) {
        fprintf(stderr, "authenticated connect failed: client=%d listener=%d\n",
                connect_rc, accept_job.result);
        goto done;
    }

    uint8_t packet_a_to_b[1500] = { 0x45, 0x00, 0x05, 0xdc, 0x12, 0x34,
        0x00, 0x00, 64, 1, 0, 0, 10, 77, 0, 1, 8, 8, 8, 8 };
    uint8_t packet_b_to_a[1500] = { 0x45, 0x00, 0x05, 0xdc, 0x56, 0x78,
        0x00, 0x00, 64, 1, 0, 0, 10, 77, 0, 2, 1, 1, 1, 1 };
    for (size_t i = 20; i < sizeof(packet_a_to_b); ++i) {
        packet_a_to_b[i] = (uint8_t)(i * 31u + 7u);
        packet_b_to_a[i] = (uint8_t)(i * 17u + 11u);
    }

    if (send(a_pair[1], packet_a_to_b, sizeof(packet_a_to_b), 0) != sizeof(packet_a_to_b) ||
        !wait_packet(b_pair[1], packet_a_to_b, sizeof(packet_a_to_b))) {
        fprintf(stderr, "packet did not cross A-to-B gateway path\n");
        goto done;
    }
    if (send(b_pair[1], packet_b_to_a, sizeof(packet_b_to_a), 0) != sizeof(packet_b_to_a) ||
        !wait_packet(a_pair[1], packet_b_to_a, sizeof(packet_b_to_a))) {
        fprintf(stderr, "packet did not cross B-to-A gateway path\n");
        goto done;
    }

    printf("PASS: authenticated ICE session carried IP packets both directions through the encrypted gateways\n");
    result = 0;

done:
    if (accept_thread_started) pthread_join(accept_thread, NULL);
    if (b != NULL) bowie_engine_free(b);
    if (a != NULL) bowie_engine_free(a);
    if (b_tun != NULL) bowie_tun_close(b_tun);
    if (a_tun != NULL) bowie_tun_close(a_tun);
    if (b_pair[0] >= 0) close(b_pair[0]);
    if (b_pair[1] >= 0) close(b_pair[1]);
    if (a_pair[0] >= 0) close(a_pair[0]);
    if (a_pair[1] >= 0) close(a_pair[1]);
    return result;
}
