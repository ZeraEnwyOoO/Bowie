#include <libwebsockets.h>
#include <jansson.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(BOWIE_PLATFORM_ANDROID)
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "engine/isrg_root_x1_pem.h"
#endif

#include "engine/signal_metered.h"
#include "engine/internal/diag.h"

#define METERED_MAX_FRAME 65536u
#define METERED_MAX_PEERS 64u
#define METERED_RX_TIMEOUT_MS 60000u
#define METERED_MAX_RECONNECT_MS 30000u

typedef struct metered_outgoing {
    uint8_t peer_id[20];
    uint8_t *payload;
    size_t payload_len;
    struct metered_outgoing *next;
} metered_outgoing_t;

typedef struct metered_peer {
    char metered_id[129];
    uint8_t bowie_id[20];
    int has_bowie_id;
    int present;
} metered_peer_t;

struct bowie_metered {
    struct lws_context *context;
    struct lws *wsi;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t ice_ready_cond;
    int ice_ready;
    atomic_int stopping;
    atomic_int permanent_close;
    int connected;
    int welcomed;
    int subscribed;
    int need_subscribe;
    int identity_pending;
    uint64_t last_rx_ms;
    uint64_t reconnect_at_ms;
    uint64_t reconnect_delay_ms;
    uint64_t next_request_id;
    char *key;
    char *channel;
    uint8_t local_peer_id[20];
    bowie_metered_message_fn on_message;
    bowie_metered_turn_fn on_turn_server;
    bowie_metered_presence_fn on_presence;
    void *callback_context;
    metered_outgoing_t *head;
    metered_outgoing_t *tail;
    metered_peer_t peers[METERED_MAX_PEERS];
    size_t peer_count;
    unsigned char *rx;
    size_t rx_len;
};

static const char *metered_protocol = "bowie-metered";

/* LWS supplies implementation-specific text here. Classify it locally, but
 * never emit the text itself: some versions include request details. */
static const char *connection_error_category(const char *error)
{
    if (error == NULL || error[0] == '\0') return "unspecified";
    if (strstr(error, "tls=hostname") != NULL) return "tls-hostname-mismatch";
    if (strstr(error, "tls=invalidca") != NULL) return "tls-untrusted-ca";
    if (strstr(error, "tls=expired") != NULL) return "tls-certificate-expired";
    if (strstr(error, "tls=notyetvalid") != NULL) return "tls-certificate-not-yet-valid";
    if (strstr(error, "certificate") != NULL || strstr(error, "X509") != NULL ||
        strstr(error, "verify") != NULL || strstr(error, "trust") != NULL)
        return "tls-certificate";
    if (strstr(error, "SSL") != NULL || strstr(error, "TLS") != NULL ||
        strstr(error, "ssl") != NULL || strstr(error, "tls") != NULL)
        return "tls-handshake";
    if (strstr(error, "resolve") != NULL || strstr(error, "DNS") != NULL ||
        strstr(error, "lookup") != NULL)
        return "dns";
    if (strstr(error, "connect") != NULL || strstr(error, "socket") != NULL ||
        strstr(error, "network") != NULL)
        return "network-connect";
    if (strstr(error, "HTTP") != NULL || strstr(error, "websocket") != NULL ||
        strstr(error, "WebSocket") != NULL)
        return "http-upgrade";
    return "other";
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int decode_hex_peer(const char *s, uint8_t out[20])
{
    if (s == NULL || strlen(s) != 40u) return 0;
    for (size_t i = 0; i < 20u; ++i) {
        unsigned v;
        if (sscanf(s + i * 2u, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void encode_hex_peer(const uint8_t peer[20], char out[41])
{
    for (size_t i = 0; i < 20u; ++i)
        (void)snprintf(out + i * 2u, 3u, "%02x", peer[i]);
}

static char *url_encode(const char *input)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t len = strlen(input);
    if (len > (SIZE_MAX - 1u) / 3u) return NULL;
    char *out = malloc(len * 3u + 1u);
    if (out == NULL) return NULL;
    char *p = out;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)input[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            *p++ = (char)c;
        } else {
            *p++ = '%'; *p++ = hex[c >> 4]; *p++ = hex[c & 15u];
        }
    }
    *p = '\0';
    return out;
}

static void peer_departed(bowie_metered_t *c, const char *id)
{
    for (size_t i = 0; i < c->peer_count; ++i) {
        if (strcmp(c->peers[i].metered_id, id) == 0) {
            c->peers[i].present = 0;
            c->peers[i].has_bowie_id = 0;
        }
    }
}

static metered_peer_t *peer_for_metered(bowie_metered_t *c, const char *id)
{
    for (size_t i = 0; i < c->peer_count; ++i) {
        if (strcmp(c->peers[i].metered_id, id) == 0) {
            c->peers[i].present = 1;
            return &c->peers[i];
        }
    }
    if (c->peer_count == METERED_MAX_PEERS || strlen(id) > 128u) return NULL;
    metered_peer_t *p = &c->peers[c->peer_count++];
    memset(p, 0, sizeof(*p));
    (void)snprintf(p->metered_id, sizeof(p->metered_id), "%s", id);
    p->present = 1;
    return p;
}

static const char *metered_for_bowie(bowie_metered_t *c, const uint8_t id[20])
{
    for (size_t i = 0; i < c->peer_count; ++i)
        if (c->peers[i].present && c->peers[i].has_bowie_id &&
            memcmp(c->peers[i].bowie_id, id, 20u) == 0)
            return c->peers[i].metered_id;
    return NULL;
}

static int send_json(struct lws *wsi, json_t *message)
{
    char *serialized = json_dumps(message, JSON_COMPACT | JSON_ENSURE_ASCII);
    if (serialized == NULL) return -1;
    size_t len = strlen(serialized);
    unsigned char *buf = malloc(LWS_PRE + len);
    if (buf == NULL) { free(serialized); return -1; }
    memcpy(buf + LWS_PRE, serialized, len);
    int result = lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_TEXT);
    free(buf);
    free(serialized);
    return result < 0 || (size_t)result != len ? -1 : 0;
}

static json_t *request_id(bowie_metered_t *c, const char *type)
{
    char id[40];
    (void)snprintf(id, sizeof(id), "bowie-%llu",
                   (unsigned long long)++c->next_request_id);
    return json_pack("{s:s,s:s}", "type", type, "requestId", id);
}

static int send_subscribe(bowie_metered_t *c, struct lws *wsi)
{
    json_t *msg = request_id(c, "subscribe");
    if (msg == NULL) return -1;
    json_object_set_new(msg, "channel", json_string(c->channel));
    json_object_set_new(msg, "includeSenderMetadata", json_false());
    int rc = send_json(wsi, msg);
    json_decref(msg);
    return rc;
}

static int send_identity_announcement(bowie_metered_t *c, struct lws *wsi)
{
    char local[41];
    encode_hex_peer(c->local_peer_id, local);
    json_t *msg = request_id(c, "publish");
    if (msg == NULL) return -1;
    json_object_set_new(msg, "channel", json_string(c->channel));
    json_object_set_new(msg, "data", json_pack("{s:s,s:s}",
        "kind", "bowie-identity", "bowiePeerId", local));
    int rc = send_json(wsi, msg);
    json_decref(msg);
    if (rc == 0) {
        c->identity_pending = 0;
        bowie_engine_diag("Metered", "channel identity announcement sent");
    }
    return rc;
}

static int send_direct(bowie_metered_t *c, struct lws *wsi,
                       metered_outgoing_t *item)
{
    const char *metered_id = metered_for_bowie(c, item->peer_id);
    if (metered_id == NULL) {
        bowie_engine_diag("Metered", "waiting for target peer identity before direct send");
        return 1; /* keep queued until identity is discovered */
    }
    char *sdp = malloc(item->payload_len + 1u);
    if (sdp == NULL) return -1;
    memcpy(sdp, item->payload, item->payload_len);
    sdp[item->payload_len] = '\0';
    json_t *msg = request_id(c, "send");
    if (msg == NULL) { free(sdp); return -1; }
    json_object_set_new(msg, "to", json_string(metered_id));
    json_object_set_new(msg, "data", json_pack("{s:s,s:s}", "kind", "offer", "sdp", sdp));
    free(sdp);
    int rc = send_json(wsi, msg);
    json_decref(msg);
    if (rc == 0) bowie_engine_diag("Metered", "direct signaling message sent");
    return rc;
}

static void handle_ice_servers(bowie_metered_t *c, json_t *root)
{
    json_t *metadata = json_object_get(root, "metadata");
    json_t *servers = json_object_get(metadata, "iceServers");
    if (!json_is_array(servers) || c->on_turn_server == NULL) {
        bowie_engine_diag("Metered", "welcome ICE metadata unavailable (servers=%s, handler=%s)",
                          json_is_array(servers) ? "present" : "absent",
                          c->on_turn_server == NULL ? "absent" : "present");
        return;
    }
    size_t turn_udp_count = 0u;
    size_t turn_other_count = 0u;
    size_t i;
    json_t *server;
    json_array_foreach(servers, i, server) {
        json_t *urls = json_object_get(server, "urls");
        json_t *username_j = json_object_get(server, "username");
        json_t *credential_j = json_object_get(server, "credential");
        const char *username = json_string_value(username_j);
        const char *credential = json_string_value(credential_j);
        size_t ucount = json_is_array(urls) ? json_array_size(urls) : 1u;
        for (size_t j = 0; j < ucount; ++j) {
            json_t *url_j = json_is_array(urls) ? json_array_get(urls, j) : urls;
            const char *url = json_string_value(url_j);
            if (url == NULL) continue;
            if (strncmp(url, "turn:", 5u) != 0) {
                if (strncmp(url, "turns:", 6u) == 0) ++turn_other_count;
                continue;
            }
            if (strstr(url, "?transport=tcp") != NULL) {
                ++turn_other_count;
                continue;
            }
            if (username == NULL || credential == NULL) continue;
            const char *authority = url + 5u;
            const char *query = strchr(authority, '?');
            size_t n = query == NULL ? strlen(authority) : (size_t)(query - authority);
            char host[256];
            if (n == 0u || n >= sizeof(host)) continue;
            memcpy(host, authority, n); host[n] = '\0';
            uint16_t port = 3478u;
            char *colon = strrchr(host, ':');
            if (colon != NULL && strchr(host, ']') == NULL) {
                char *end = NULL;
                unsigned long p = strtoul(colon + 1, &end, 10);
                if (end != colon + 1 && *end == '\0' && p > 0u && p <= 65535u) {
                    *colon = '\0'; port = (uint16_t)p;
                }
            }
            if (host[0] != '\0') {
                c->on_turn_server(c->callback_context, host,
                                  port, username, credential);
                ++turn_udp_count;
            }
        }
    }
    bowie_engine_diag("Metered", "welcome ICE metadata parsed (servers=%zu, udp_turn=%zu, tcp_or_tls_turn=%zu)",
                      json_array_size(servers), turn_udp_count, turn_other_count);
}

static void handle_presence(bowie_metered_t *c, json_t *root)
{
    json_t *joined = json_object_get(root, "joined");
    json_t *left = json_object_get(root, "left");
    size_t i;
    json_t *entry;
    if (json_is_array(left)) {
        json_array_foreach(left, i, entry) {
            const char *id = json_string_value(json_object_get(entry, "peerId"));
            if (id != NULL) peer_departed(c, id);
        }
    }
    if (json_is_array(joined)) {
        json_array_foreach(joined, i, entry) {
            const char *id = json_string_value(json_object_get(entry, "peerId"));
            if (id != NULL) (void)peer_for_metered(c, id);
        }
        /* A peer may have published its identity before this client joined.
         * Reannounce on a non-empty presence snapshot so both join orders work. */
        if (json_array_size(joined) != 0u && c->subscribed)
            c->identity_pending = 1;
    }
    if (c->on_presence != NULL) c->on_presence(c->callback_context,
        json_is_array(joined) ? json_array_size(joined) : 0u);
    if (c->wsi != NULL) lws_callback_on_writable(c->wsi);
}

static void handle_message(bowie_metered_t *c, json_t *root)
{
    const char *type = json_string_value(json_object_get(root, "type"));
    if (type == NULL) return;
    if (strcmp(type, "welcome") == 0) {
        bowie_engine_diag("Metered", "WebSocket welcome received");
        c->welcomed = 1;
        c->subscribed = 0;
        c->need_subscribe = 1;
        c->identity_pending = 0;
        for (size_t i = 0; i < c->peer_count; ++i) {
            c->peers[i].present = 0;
            c->peers[i].has_bowie_id = 0;
        }
        handle_ice_servers(c, root);
        pthread_mutex_lock(&c->lock);
        c->ice_ready = 1;
        pthread_cond_broadcast(&c->ice_ready_cond);
        pthread_mutex_unlock(&c->lock);
        if (c->wsi != NULL) lws_callback_on_writable(c->wsi);
    } else if (strcmp(type, "ack") == 0) {
        const char *id = json_string_value(json_object_get(root, "requestId"));
        bowie_engine_diag("Metered", "request acknowledged%s%s",
                          id == NULL ? "" : ": ", id == NULL ? "" : id);
        if (id != NULL && strstr(id, "bowie-") != NULL && c->welcomed &&
            !c->subscribed && !c->need_subscribe) {
            c->subscribed = 1;
            c->identity_pending = 1;
            if (c->wsi != NULL) lws_callback_on_writable(c->wsi);
        } else if (id != NULL && c->welcomed && !c->subscribed) {
            c->subscribed = 1;
            c->identity_pending = 1;
            if (c->wsi != NULL) lws_callback_on_writable(c->wsi);
        }
    } else if (strcmp(type, "presence") == 0) {
        const char *channel = json_string_value(json_object_get(root, "channel"));
        if (channel != NULL && strcmp(channel, c->channel) == 0) handle_presence(c, root);
    } else if (strcmp(type, "message") == 0) {
        const char *channel = json_string_value(json_object_get(root, "channel"));
        const char *from = json_string_value(json_object_get(root, "from"));
        json_t *data = json_object_get(root, "data");
        const char *kind = json_string_value(json_object_get(data, "kind"));
        if (channel == NULL || strcmp(channel, c->channel) != 0 || from == NULL || kind == NULL) return;
        metered_peer_t *peer = peer_for_metered(c, from);
        if (peer == NULL) return;
        if (strcmp(kind, "bowie-identity") == 0) {
            const char *id = json_string_value(json_object_get(data, "bowiePeerId"));
            if (decode_hex_peer(id, peer->bowie_id)) {
                peer->has_bowie_id = 1;
                bowie_engine_diag("Metered", "peer identity announcement received");
            }
            if (c->wsi != NULL) lws_callback_on_writable(c->wsi);
        }
    } else if (strcmp(type, "direct") == 0) {
        const char *from = json_string_value(json_object_get(root, "from"));
        json_t *data = json_object_get(root, "data");
        const char *sdp = json_string_value(json_object_get(data, "sdp"));
        metered_peer_t *peer = from == NULL ? NULL : peer_for_metered(c, from);
        if (peer != NULL && peer->has_bowie_id && sdp != NULL && c->on_message != NULL) {
            bowie_engine_diag("Metered", "direct signaling message received");
            c->on_message(c->callback_context, peer->bowie_id,
                          (const uint8_t *)sdp, strlen(sdp));
        }
    } else if (strcmp(type, "error") == 0) {
        const char *code = json_string_value(json_object_get(root, "code"));
        bowie_engine_diag("Metered", "server rejected a request: %s",
                          code == NULL ? "unknown" : code);
    }
}

static int metered_callback(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len)
{
    bowie_metered_t *c = lws_context_user(lws_get_context(wsi));
    if (c == NULL) return 0;
#if defined(BOWIE_PLATFORM_ANDROID)
    if (reason == LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS) {
        SSL_CTX *ssl_context = (SSL_CTX *)user;
        int system_store_loaded = ssl_context != NULL && SSL_CTX_load_verify_locations(
            ssl_context, NULL, "/system/etc/security/cacerts");
        int fallback_added = 0;
        if (ssl_context != NULL) {
            BIO *bio = BIO_new_mem_buf(bowie_isrg_root_x1_pem, -1);
            X509 *root = bio == NULL ? NULL : PEM_read_bio_X509(bio, NULL, NULL, NULL);
            X509_STORE *store = SSL_CTX_get_cert_store(ssl_context);
            if (root != NULL && store != NULL)
                fallback_added = X509_STORE_add_cert(store, root);
            X509_free(root);
            BIO_free(bio);
        }
        bowie_engine_diag("Metered", "Android TLS trust loaded (system_ca=%s, isrg_root_x1=%s)",
                          system_store_loaded ? "yes" : "no",
                          fallback_added ? "added" : "unavailable");
        return 0;
    }
#else
    (void)user;
#endif
    if (reason == LWS_CALLBACK_CLIENT_ESTABLISHED) {
        bowie_engine_diag("Metered", "WebSocket connected");
        c->wsi = wsi; c->connected = 1; c->welcomed = 0;
        c->subscribed = 0; c->need_subscribe = 0; c->rx_len = 0u;
        c->last_rx_ms = monotonic_ms(); c->reconnect_delay_ms = 1000u;
    } else if (reason == LWS_CALLBACK_CLIENT_RECEIVE) {
        if (len > METERED_MAX_FRAME || c->rx_len > METERED_MAX_FRAME - len) return -1;
        unsigned char *next = realloc(c->rx, c->rx_len + len + 1u);
        if (next == NULL) return -1;
        c->rx = next; memcpy(c->rx + c->rx_len, in, len); c->rx_len += len;
        c->rx[c->rx_len] = '\0'; c->last_rx_ms = monotonic_ms();
        if (lws_is_final_fragment(wsi) && lws_remaining_packet_payload(wsi) == 0u) {
            json_error_t error;
            json_t *root = json_loadb((const char *)c->rx, c->rx_len, 0, &error);
            c->rx_len = 0u;
            if (root != NULL) { handle_message(c, root); json_decref(root); }
        }
    } else if (reason == LWS_CALLBACK_CLIENT_WRITEABLE) {
        if (c->need_subscribe) {
            c->need_subscribe = 0;
            if (send_subscribe(c, wsi) != 0) return -1;
            return 0;
        }
        if (c->identity_pending) {
            if (send_identity_announcement(c, wsi) != 0) return -1;
            return 0;
        }
        if (!c->subscribed) return 0;
        pthread_mutex_lock(&c->lock);
        metered_outgoing_t *item = c->head;
        pthread_mutex_unlock(&c->lock);
        if (item != NULL) {
            int rc = send_direct(c, wsi, item);
            if (rc < 0) return -1;
            if (rc == 0) {
                pthread_mutex_lock(&c->lock);
                if (c->head == item) {
                    c->head = item->next;
                    if (c->head == NULL) c->tail = NULL;
                }
                pthread_mutex_unlock(&c->lock);
                free(item->payload); free(item);
            }
        }
        pthread_mutex_lock(&c->lock);
        int queued = c->head != NULL;
        pthread_mutex_unlock(&c->lock);
        if (queued && metered_for_bowie(c, c->head->peer_id) != NULL)
            lws_callback_on_writable(wsi);
    } else if (reason == LWS_CALLBACK_EVENT_WAIT_CANCELLED) {
        pthread_mutex_lock(&c->lock);
        struct lws *active = c->wsi;
        int queued = c->head != NULL;
        pthread_mutex_unlock(&c->lock);
        if (active != NULL && (queued || c->need_subscribe || c->identity_pending))
            lws_callback_on_writable(active);
    } else if (reason == LWS_CALLBACK_WS_PEER_INITIATED_CLOSE) {
        if (len >= 2u) {
            unsigned code = ((const unsigned char *)in)[0] * 256u + ((const unsigned char *)in)[1];
            if (code == 4001u || code == 4003u || code == 4012u || code == 4020u)
                atomic_store(&c->permanent_close, 1);
        }
    } else if (reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR) {
        const char *connection_error = (const char *)in;
        const char *verify_marker = connection_error == NULL ? NULL :
            strstr(connection_error, "X509_V_ERR = ");
        if (verify_marker != NULL) {
            char *end = NULL;
            long verify_code = strtol(verify_marker + sizeof("X509_V_ERR = ") - 1u,
                                      &end, 10);
            if (end != verify_marker + sizeof("X509_V_ERR = ") - 1u && end != NULL) {
                bowie_engine_diag("Metered", "WebSocket connection failed (category=%s, verify_code=%ld); reconnect scheduled",
                                  connection_error_category(connection_error), verify_code);
            } else {
                bowie_engine_diag("Metered", "WebSocket connection failed (category=%s); reconnect scheduled",
                                  connection_error_category(connection_error));
            }
        } else {
            bowie_engine_diag("Metered", "WebSocket connection failed (category=%s); reconnect scheduled",
                              connection_error_category(connection_error));
        }
        c->connected = 0; c->welcomed = 0; c->subscribed = 0;
        c->wsi = NULL; c->rx_len = 0u;
        c->reconnect_at_ms = monotonic_ms() + c->reconnect_delay_ms;
        if (c->reconnect_delay_ms < METERED_MAX_RECONNECT_MS)
            c->reconnect_delay_ms *= 2u;
    } else if (reason == LWS_CALLBACK_CLIENT_CLOSED) {
        bowie_engine_diag("Metered", "WebSocket closed after connection; reconnect scheduled");
        c->connected = 0; c->welcomed = 0; c->subscribed = 0;
        c->wsi = NULL; c->rx_len = 0u;
        c->reconnect_at_ms = monotonic_ms() + c->reconnect_delay_ms;
        if (c->reconnect_delay_ms < METERED_MAX_RECONNECT_MS)
            c->reconnect_delay_ms *= 2u;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "bowie-metered", metered_callback, 0, METERED_MAX_FRAME, 0, NULL, 0 },
    LWS_PROTOCOL_LIST_TERM
};

static void *metered_thread(void *arg)
{
    bowie_metered_t *c = arg;
    while (!atomic_load(&c->stopping)) {
        uint64_t now = monotonic_ms();
        if (!atomic_load(&c->permanent_close) && c->wsi == NULL &&
            now >= c->reconnect_at_ms) {
            char *encoded = url_encode(c->key);
            char *path = NULL;
            if (encoded != NULL) {
                size_t n = strlen(encoded) + 16u;
                path = malloc(n);
                if (path != NULL) (void)snprintf(path, n, "/v1?key=%s", encoded);
            }
            free(encoded);
            if (path != NULL) {
                struct lws_client_connect_info info;
                memset(&info, 0, sizeof(info));
                info.context = c->context; info.address = "rms.metered.ca";
                info.port = 443; info.path = path; info.host = info.address;
                info.origin = info.address; info.protocol = metered_protocol;
                info.ssl_connection = LCCSCF_USE_SSL; info.local_protocol_name = metered_protocol;
                info.pwsi = &c->wsi;
                if (lws_client_connect_via_info(&info) == NULL) {
                    c->reconnect_at_ms = now + c->reconnect_delay_ms;
                    if (c->reconnect_delay_ms < METERED_MAX_RECONNECT_MS)
                        c->reconnect_delay_ms *= 2u;
                }
                free(path);
            }
        }
        if (c->connected && now - c->last_rx_ms >= METERED_RX_TIMEOUT_MS && c->wsi != NULL)
            lws_set_timeout(c->wsi, PENDING_TIMEOUT_CLOSE_SEND, LWS_TO_KILL_ASYNC);
        (void)lws_service(c->context, 250);
    }
    return NULL;
}

int bowie_metered_start(const bowie_metered_config_t *cfg, bowie_metered_t **out)
{
    if (cfg == NULL || out == NULL || cfg->publishable_key == NULL ||
        cfg->channel == NULL || cfg->publishable_key[0] == '\0' || cfg->channel[0] == '\0')
        return -1;
    *out = NULL;
    bowie_metered_t *c = calloc(1u, sizeof(*c));
    if (c == NULL) return -1;
    c->key = strdup(cfg->publishable_key); c->channel = strdup(cfg->channel);
    memcpy(c->local_peer_id, cfg->local_peer_id, sizeof(c->local_peer_id));
    c->on_message = cfg->on_message; c->on_turn_server = cfg->on_turn_server;
    c->on_presence = cfg->on_presence; c->callback_context = cfg->context;
    c->reconnect_delay_ms = 1000u; c->reconnect_at_ms = monotonic_ms();
    if (c->key == NULL || c->channel == NULL || pthread_mutex_init(&c->lock, NULL) != 0)
        goto fail;
    if (pthread_cond_init(&c->ice_ready_cond, NULL) != 0) {
        pthread_mutex_destroy(&c->lock);
        goto fail;
    }
    struct lws_context_creation_info ci;
    memset(&ci, 0, sizeof(ci)); ci.port = CONTEXT_PORT_NO_LISTEN;
    ci.protocols = protocols; ci.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT; ci.user = c;
    c->context = lws_create_context(&ci);
    if (c->context == NULL || pthread_create(&c->thread, NULL, metered_thread, c) != 0)
        goto fail_mutex;
    *out = c;
    return 0;
fail_mutex:
    if (c->context != NULL) lws_context_destroy(c->context);
    pthread_cond_destroy(&c->ice_ready_cond);
    pthread_mutex_destroy(&c->lock);
fail:
    free(c->key); free(c->channel); free(c); return -1;
}

int bowie_metered_publish(bowie_metered_t *c, const uint8_t *peer_id,
                          const void *payload, size_t payload_len)
{
    if (c == NULL || peer_id == NULL || payload == NULL || payload_len == 0u ||
        payload_len > METERED_MAX_FRAME) return -1;
    metered_outgoing_t *item = calloc(1u, sizeof(*item));
    if (item == NULL) return -1;
    item->payload = malloc(payload_len);
    if (item->payload == NULL) { free(item); return -1; }
    memcpy(item->payload, payload, payload_len); memcpy(item->peer_id, peer_id, 20u);
    item->payload_len = payload_len;
    pthread_mutex_lock(&c->lock);
    if (c->tail != NULL) c->tail->next = item; else c->head = item;
    c->tail = item;
    pthread_mutex_unlock(&c->lock);
    lws_cancel_service(c->context);
    return 0;
}

int bowie_metered_wait_ice_servers(bowie_metered_t *c, uint32_t timeout_ms)
{
    struct timespec deadline;
    int rc = 0;
    if (c == NULL || timeout_ms == 0u) return -1;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return -1;
    deadline.tv_sec += (time_t)(timeout_ms / 1000u);
    deadline.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&c->lock);
    while (!c->ice_ready && !atomic_load(&c->stopping)) {
        rc = pthread_cond_timedwait(&c->ice_ready_cond, &c->lock, &deadline);
        if (rc != 0) break;
    }
    int ready = c->ice_ready;
    pthread_mutex_unlock(&c->lock);
    return ready ? 0 : -1;
}

void bowie_metered_stop(bowie_metered_t *c)
{
    if (c == NULL) return;
    atomic_store(&c->stopping, 1); lws_cancel_service(c->context);
    pthread_mutex_lock(&c->lock);
    pthread_cond_broadcast(&c->ice_ready_cond);
    pthread_mutex_unlock(&c->lock);
    pthread_join(c->thread, NULL); lws_context_destroy(c->context);
    metered_outgoing_t *item = c->head;
    while (item != NULL) {
        metered_outgoing_t *next = item->next;
        free(item->payload); free(item); item = next;
    }
    free(c->rx); pthread_cond_destroy(&c->ice_ready_cond);
    pthread_mutex_destroy(&c->lock);
    free(c->key); free(c->channel); free(c);
}
