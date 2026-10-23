#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "engine/engine.h"
#include "dht/dht.h"
#include "crypto/hash.h"

typedef struct local_bootstrap {
    int fd;
    pthread_t thread;
    pthread_mutex_t lock;
    int running;
    int has_peer;
    bowie_dht_info_hash_t hash;
    bowie_addr_t peer;
} local_bootstrap_t;

typedef struct authorization_expectation {
    bowie_peer_id_t expected;
    int called;
} authorization_expectation_t;

typedef struct accept_worker {
    bowie_engine_t *engine;
    bowie_error_t result;
    bowie_peer_id_t expected_peer;
    int pinned;
} accept_worker_t;

static int authorize_expected_peer(void *arg, const bowie_peer_id_t *peer)
{
    authorization_expectation_t *expected = (authorization_expectation_t *)arg;
    expected->called++;
    return bowie_peer_id_equal(&expected->expected, peer);
}

static void *accept_discovered_main(void *arg)
{
    accept_worker_t *worker = (accept_worker_t *)arg;
    worker->result = worker->pinned
        ? bowie_engine_accept_from(worker->engine, &worker->expected_peer, 20000u)
        : bowie_engine_accept_discovered(worker->engine, 20000u);
    return NULL;
}

static void *bootstrap_main(void *arg)
{
    local_bootstrap_t *server = (local_bootstrap_t *)arg;
    uint8_t packet[1500], output[1500];
    bowie_bencode_value_t values[512];
    bowie_bencode_dict_entry_t entries[256];
    bowie_dht_compact_node_t nodes[64];
    bowie_dht_compact_peer_t peers[64];
    bowie_dht_node_id_t server_id;
    memset(&server_id, 0, sizeof(server_id));
    server_id.bytes[0] = 0xf0u;

    while (server->running) {
        struct pollfd pfd = { .fd = server->fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, 100) <= 0 || !(pfd.revents & POLLIN)) continue;

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t len = recvfrom(server->fd, packet, sizeof(packet), 0,
                               (struct sockaddr *)&from, &from_len);
        if (len <= 0) continue;

        bowie_bencode_arena_t benc = {
            .values = values, .values_cap = 512u,
            .entries = entries, .entries_cap = 256u
        };
        bowie_dht_message_arena_t arena = {
            .nodes = nodes, .nodes_cap = 64u,
            .peers = peers, .peers_cap = 64u
        };
        bowie_dht_message_t request, response;
        bowie_span_t input = { packet, (size_t)len };
        if (bowie_dht_message_parse(input, &benc, &arena, &request) != BOWIE_OK ||
            request.type != BOWIE_DHT_MSG_QUERY) continue;

        memset(&response, 0, sizeof(response));
        response.type = BOWIE_DHT_MSG_RESPONSE;
        response.sender_id = server_id;
        memcpy(response.tid, request.tid, request.tid_len);
        response.tid_len = request.tid_len;

        if (request.query_type == BOWIE_DHT_QUERY_GET_PEERS) {
            response.token.len = 8u;
            memcpy(response.token.bytes, "localtok", 8u);
            pthread_mutex_lock(&server->lock);
            if (server->has_peer &&
                memcmp(server->hash.bytes, request.info_hash.bytes,
                       sizeof(server->hash.bytes)) == 0) {
                peers[0].addr = server->peer;
                response.peers = peers;
                response.peers_count = 1u;
            }
            pthread_mutex_unlock(&server->lock);
        } else if (request.query_type == BOWIE_DHT_QUERY_ANNOUNCE_PEER) {
            pthread_mutex_lock(&server->lock);
            server->hash = request.info_hash;
            server->peer.family = BOWIE_AF_INET;
            memcpy(server->peer.addr, &from.sin_addr, 4u);
            server->peer.port = request.implied_port ? ntohs(from.sin_port) : request.port;
            server->has_peer = server->peer.port != 0u;
            pthread_mutex_unlock(&server->lock);
        } else if (request.query_type != BOWIE_DHT_QUERY_PING) {
            continue;
        }

        bowie_bencode_writer_t writer;
        bowie_bencode_writer_init(&writer, output, sizeof(output));
        if (bowie_dht_message_serialize(&response, &writer) == BOWIE_OK) {
            (void)sendto(server->fd, output, writer.pos, 0,
                         (struct sockaddr *)&from, from_len);
        }
    }
    return NULL;
}

int main(void)
{
    local_bootstrap_t server;
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    bowie_engine_t *engine = NULL;
    bowie_engine_t *engine2 = NULL;
    bowie_engine_t *engine3 = NULL;
    bowie_engine_t *engine4 = NULL;
    bowie_engine_t *engine5 = NULL;
    bowie_engine_t *engine6 = NULL;
    bowie_engine_config_t config;
    bowie_engine_config_t config2;
    bowie_engine_config_t config3;
    bowie_engine_config_t config4;
    bowie_engine_config_t config5;
    bowie_engine_config_t config6;
    bowie_peer_id_t own_id;
    bowie_peer_id_t second_id;
    bowie_grant_t owner_grant;
    bowie_dht_node_t found;
    bowie_hash_sha1_t room_digest;
    bowie_dht_info_hash_t room_hash;
    int mutex_ready = 0;
    int thread_started = 0;
    int accept_thread_started = 0;
    pthread_t accept_thread;
    accept_worker_t accept_job;
    authorization_expectation_t authorize_first = {0};
    authorization_expectation_t authorize_second = {0};
    authorization_expectation_t authorize_third = {0};
    authorization_expectation_t authorize_fourth = {0};
    int result = 1;

    memset(&server, 0, sizeof(server));
    server.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server.fd < 0) goto done;
    if (pthread_mutex_init(&server.lock, NULL) != 0) goto done;
    mutex_ready = 1;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server.fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0 ||
        getsockname(server.fd, (struct sockaddr *)&server_addr, &server_len) != 0) goto done;

    server.running = 1;
    if (pthread_create(&server.thread, NULL, bootstrap_main, &server) != 0) goto done;
    thread_started = 1;

    bowie_engine_default_config(&config);
    config.authorize_discovered_peer = authorize_expected_peer;
    config.authorize_discovered_peer_context = &authorize_first;
    bowie_error_t setup_rc = bowie_engine_new(&config, &engine);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "create engine failed: %d\n", setup_rc); goto stop_server; }
    setup_rc = bowie_engine_add_bootstrap(engine, "127.0.0.1", ntohs(server_addr.sin_port));
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "add bootstrap failed: %d\n", setup_rc); goto stop_server; }
    setup_rc = bowie_engine_start(engine, NULL);
    if (setup_rc != BOWIE_OK) { fprintf(stderr, "start engine failed: %d\n", setup_rc); goto stop_server; }

    bowie_engine_peer_id(engine, &own_id);
    for (unsigned attempt = 0u; attempt < 60u; attempt++) {
        int registered;
        pthread_mutex_lock(&server.lock);
        registered = server.has_peer;
        pthread_mutex_unlock(&server.lock);
        if (registered) break;
        struct timespec pause = { 0, 50000000L };
        nanosleep(&pause, NULL);
    }
    if (bowie_engine_search_peer(engine, &own_id, &found, 5000u) != BOWIE_OK) {
        fprintf(stderr, "DHT peer lookup did not return the announced endpoint\n");
        goto stop_server;
    }
    if (found.addr.family != BOWIE_AF_INET || found.addr.addr[0] != 127u ||
        found.addr.addr[3] != 1u || found.addr.port != bowie_engine_signal_port(engine)) {
        fprintf(stderr, "DHT returned the wrong signaling endpoint\n");
        goto stop_server;
    }

    printf("PASS: bootstrap token exchange announced and resolved peer signaling endpoint %u\n",
           (unsigned)found.addr.port);

    if (bowie_hash_sha1("bowie-e2e-room", strlen("bowie-e2e-room"),
                        &room_digest) != BOWIE_OK) goto stop_server;
    memcpy(room_hash.bytes, room_digest.bytes, sizeof(room_hash.bytes));
    if (bowie_engine_announce_room(engine, "bowie-e2e-room") != BOWIE_OK) goto stop_server;
    bowie_engine_default_config(&config2);
    config2.authorize_discovered_peer = authorize_expected_peer;
    config2.authorize_discovered_peer_context = &authorize_second;
    config2.allow_ungranted_peers = 1;
    if (bowie_engine_new(&config2, &engine2) != BOWIE_OK ||
        bowie_engine_add_bootstrap(engine2, "127.0.0.1", ntohs(server_addr.sin_port)) != BOWIE_OK ||
        bowie_engine_start(engine2, NULL) != BOWIE_OK ||
        bowie_engine_announce_room(engine2, "bowie-e2e-room") != BOWIE_OK) {
        fprintf(stderr, "second DHT room peer setup failed\n");
        goto stop_server;
    }
    bowie_engine_peer_id(engine2, &second_id);
    if (bowie_engine_issue_grant(engine, &second_id,
                                 BOWIE_GRANT_INTERNET_USE, 86400000u,
                                 &owner_grant) != BOWIE_OK ||
        bowie_engine_set_grant(engine2, &owner_grant) != BOWIE_OK) {
        fprintf(stderr, "could not create/install the owner's room grant\n");
        goto stop_server;
    }
    authorize_first.expected = second_id;
    authorize_second.expected = own_id;
    for (unsigned attempt = 0u; attempt < 100u; attempt++) {
        int published;
        pthread_mutex_lock(&server.lock);
        published = server.has_peer && server.peer.port == bowie_engine_signal_port(engine2) &&
            memcmp(server.hash.bytes, room_hash.bytes, sizeof(room_hash.bytes)) == 0;
        pthread_mutex_unlock(&server.lock);
        if (published) break;
        struct timespec pause = { 0, 50000000L };
        nanosleep(&pause, NULL);
    }
    if (bowie_engine_discover_room(engine, "bowie-e2e-room", &found, 5000u) != BOWIE_OK ||
        found.addr.port != bowie_engine_signal_port(engine2)) {
        fprintf(stderr, "DHT room lookup did not discover the other peer endpoint\n");
        goto stop_server;
    }
    printf("PASS: shared DHT room discovered a second peer endpoint %u without its peer ID\n",
           (unsigned)found.addr.port);

    accept_job.engine = engine;
    accept_job.pinned = 0;
    accept_job.result = BOWIE_ERR_INTERNAL;
    if (pthread_create(&accept_thread, NULL, accept_discovered_main, &accept_job) != 0) {
        fprintf(stderr, "could not start discovered-peer acceptor\n");
        goto stop_server;
    }
    accept_thread_started = 1;
    if (bowie_engine_connect_room(engine2, "bowie-e2e-room", 20000u) != BOWIE_OK) {
        fprintf(stderr, "room-based authenticated connection failed\n");
        goto stop_server;
    }
    pthread_join(accept_thread, NULL);
    accept_thread_started = 0;
    if (accept_job.result != BOWIE_OK || authorize_first.called != 1 ||
        authorize_second.called != 1) {
        fprintf(stderr, "discovered peer authorization was not enforced on both sides\n");
        goto stop_server;
    }
    printf("PASS: room connection authenticated and authorized both signed peer identities\n");

    bowie_engine_default_config(&config3);
    config3.authorize_discovered_peer = authorize_expected_peer;
    config3.authorize_discovered_peer_context = &authorize_third;
    bowie_engine_default_config(&config4);
    config4.authorize_discovered_peer = authorize_expected_peer;
    config4.authorize_discovered_peer_context = &authorize_fourth;
    if (bowie_engine_new(&config3, &engine3) != BOWIE_OK ||
        bowie_engine_add_bootstrap(engine3, "127.0.0.1", ntohs(server_addr.sin_port)) != BOWIE_OK ||
        bowie_engine_start(engine3, NULL) != BOWIE_OK ||
        bowie_engine_announce_room(engine3, "bowie-e2e-room") != BOWIE_OK ||
        bowie_engine_new(&config4, &engine4) != BOWIE_OK ||
        bowie_engine_add_bootstrap(engine4, "127.0.0.1", ntohs(server_addr.sin_port)) != BOWIE_OK ||
        bowie_engine_start(engine4, NULL) != BOWIE_OK ||
        bowie_engine_announce_room(engine4, "bowie-e2e-room") != BOWIE_OK) {
        fprintf(stderr, "rejection-test peer setup failed\n");
        goto stop_server;
    }
    bowie_peer_id_t fourth_id;
    bowie_engine_peer_id(engine4, &fourth_id);
    if (bowie_engine_issue_grant(engine3, &fourth_id,
                                 BOWIE_GRANT_INTERNET_USE, 86400000u,
                                 &owner_grant) != BOWIE_OK ||
        bowie_engine_set_grant(engine4, &owner_grant) != BOWIE_OK) {
        fprintf(stderr, "could not create/install rejection-test owner grant\n");
        goto stop_server;
    }
    authorize_third.expected = fourth_id;
    authorize_fourth.expected = fourth_id; /* Deliberately reject engine3. */
    for (unsigned attempt = 0u; attempt < 100u; attempt++) {
        int published;
        pthread_mutex_lock(&server.lock);
        published = server.has_peer && server.peer.port == bowie_engine_signal_port(engine4) &&
            memcmp(server.hash.bytes, room_hash.bytes, sizeof(room_hash.bytes)) == 0;
        pthread_mutex_unlock(&server.lock);
        if (published) break;
        struct timespec pause = { 0, 50000000L };
        nanosleep(&pause, NULL);
    }
    accept_job.engine = engine3;
    accept_job.pinned = 0;
    accept_job.result = BOWIE_OK;
    if (pthread_create(&accept_thread, NULL, accept_discovered_main, &accept_job) != 0) {
        fprintf(stderr, "could not start authorization rejection acceptor\n");
        goto stop_server;
    }
    accept_thread_started = 1;
    bowie_error_t denied_rc = bowie_engine_connect_room(engine4,
                                                         "bowie-e2e-room", 5000u);
    pthread_join(accept_thread, NULL);
    accept_thread_started = 0;
    if (denied_rc != BOWIE_ERR_PERMISSION ||
        accept_job.result != BOWIE_ERR_PERMISSION ||
        authorize_third.called != 1 || authorize_fourth.called != 1) {
        fprintf(stderr, "a peer rejected by either authorization callback was not blocked\n");
        goto stop_server;
    }
    printf("PASS: rejecting a discovered identity on either side blocks session setup\n");

    bowie_engine_default_config(&config5);
    bowie_engine_default_config(&config6);
    config6.allow_ungranted_peers = 1;
    if (bowie_engine_new(&config5, &engine5) != BOWIE_OK ||
        bowie_engine_start(engine5, NULL) != BOWIE_OK ||
        bowie_engine_new(&config6, &engine6) != BOWIE_OK ||
        bowie_engine_start(engine6, NULL) != BOWIE_OK) {
        fprintf(stderr, "missing-grant peer setup failed\n");
        goto stop_server;
    }
    bowie_peer_id_t fifth_id, sixth_id;
    bowie_engine_peer_id(engine5, &fifth_id);
    bowie_engine_peer_id(engine6, &sixth_id);
    accept_job.engine = engine5;
    accept_job.expected_peer = sixth_id;
    accept_job.pinned = 1;
    accept_job.result = BOWIE_OK;
    if (pthread_create(&accept_thread, NULL, accept_discovered_main, &accept_job) != 0) {
        fprintf(stderr, "could not start source for missing-grant check\n");
        goto stop_server;
    }
    accept_thread_started = 1;
    bowie_addr_t source_signal;
    memset(&source_signal, 0, sizeof(source_signal));
    source_signal.family = BOWIE_AF_INET;
    source_signal.addr[0] = 127u;
    source_signal.addr[3] = 1u;
    source_signal.port = bowie_engine_signal_port(engine5);
    bowie_error_t missing_grant_rc = bowie_engine_connect_direct(
        engine6, &fifth_id, &source_signal, 10000u);
    pthread_join(accept_thread, NULL);
    accept_thread_started = 0;
    if (missing_grant_rc != BOWIE_ERR_PERMISSION ||
        accept_job.result != BOWIE_ERR_PERMISSION) {
        fprintf(stderr, "source accepted a correctly signed peer with no owner grant\n");
        goto stop_server;
    }
    printf("PASS: source rejected a signed peer that presented no owner grant\n");
    result = 0;

stop_server:
    if (accept_thread_started) pthread_join(accept_thread, NULL);
    server.running = 0;
    pthread_join(server.thread, NULL);
    thread_started = 0;
done:
    if (thread_started) {
        server.running = 0;
        pthread_join(server.thread, NULL);
    }
    if (engine != NULL) bowie_engine_free(engine);
    if (engine2 != NULL) bowie_engine_free(engine2);
    if (engine3 != NULL) bowie_engine_free(engine3);
    if (engine4 != NULL) bowie_engine_free(engine4);
    if (engine5 != NULL) bowie_engine_free(engine5);
    if (engine6 != NULL) bowie_engine_free(engine6);
    if (server.fd >= 0) close(server.fd);
    if (mutex_ready) pthread_mutex_destroy(&server.lock);
    return result;
}
