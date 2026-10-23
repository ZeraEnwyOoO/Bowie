#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "bowie/err.h"
#include "engine/engine.h"
#include "security/sign.h"
#include "tunnel/tun_linux.h"
#include "egress.h"
#include "quota_store.h"

static volatile sig_atomic_t running = 1;

static int prepare_underlay_route(void *context, int family,
                                  const uint8_t *address, size_t address_len)
{
    return bowie_linux_client_routes_add((bowie_linux_client_routes_t *)context,
                                        family, address, address_len);
}

static int load_or_create_identity(uint8_t seed[BOWIE_SIGN_SEED_LEN],
                                   char path[PATH_MAX])
{
    const char *root = getenv("XDG_CONFIG_HOME");
    if (root == NULL || root[0] == '\0') {
        const char *home = getenv("HOME");
        if (home == NULL || home[0] == '\0') return 0;
        if (snprintf(path, PATH_MAX, "%s/.config", home) >= PATH_MAX ||
            (mkdir(path, 0700) != 0 && errno != EEXIST)) return 0;
        root = path;
    } else if (mkdir(root, 0700) != 0 && errno != EEXIST) {
        return 0;
    }
    if (snprintf(path, PATH_MAX, "%s/bowie", root) >= PATH_MAX ||
        (mkdir(path, 0700) != 0 && errno != EEXIST)) return 0;
    char key_path[PATH_MAX];
    if (snprintf(key_path, sizeof(key_path), "%s/identity.key", path) >= (int)sizeof(key_path)) return 0;

    int fd = open(key_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        uint8_t extra;
        int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                 (st.st_mode & 077u) == 0u && st.st_size == BOWIE_SIGN_SEED_LEN &&
                 read(fd, seed, BOWIE_SIGN_SEED_LEN) == BOWIE_SIGN_SEED_LEN &&
                 read(fd, &extra, 1u) == 0;
        close(fd);
        return ok;
    }
    bowie_sign_private_t generated;
    bowie_sign_public_t generated_public;
    if (errno != ENOENT ||
        bowie_security_sign_generate(&generated_public, &generated) != BOWIE_OK)
        return 0;
    fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        memset(&generated, 0, sizeof(generated));
        return errno == EEXIST && load_or_create_identity(seed, path);
    }
    size_t written = 0u;
    while (written < BOWIE_SIGN_SEED_LEN) {
        ssize_t n = write(fd, generated.bytes + written, BOWIE_SIGN_SEED_LEN - written);
        if (n <= 0) break;
        written += (size_t)n;
    }
    int ok = written == BOWIE_SIGN_SEED_LEN && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) {
        unlink(key_path);
        memset(&generated, 0, sizeof(generated));
    } else {
        memcpy(seed, generated.bytes, BOWIE_SIGN_SEED_LEN);
    }
    memset(&generated, 0, sizeof(generated));
    return ok;
}

static void stop_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int parse_peer_id(const char *hex, bowie_peer_id_t *out)
{
    if (hex == NULL || strcspn(hex, "\r\n") != BOWIE_PEER_ID_LEN * 2u) return 0;
    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) {
        unsigned value = 0u;
        for (size_t j = 0u; j < 2u; j++) {
            char c = hex[i * 2u + j];
            unsigned nibble;
            if (c >= '0' && c <= '9') nibble = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') nibble = (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') nibble = (unsigned)(c - 'A' + 10);
            else return 0;
            value = (value << 4) | nibble;
        }
        out->bytes[i] = (uint8_t)value;
    }
    return 1;
}

static void print_peer_id(const bowie_peer_id_t *id)
{
    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) printf("%02x", id->bytes[i]);
}

static void print_stable_name(const bowie_peer_id_t *id)
{
    printf("bowie-");
    for (size_t i = 0u; i < 5u; i++) printf("%02x", id->bytes[i]);
}

static int write_grant_file(const char *path, const bowie_grant_t *grant)
{
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    long fields = bowie_grant_serialize(grant, wire, sizeof(wire));
    if (fields != (long)(sizeof(wire) - sizeof(grant->signature))) return 0;
    memcpy(wire + fields, grant->signature, sizeof(grant->signature));
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    struct stat st;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
             fchmod(fd, 0600) == 0;
    size_t written = 0u;
    while (ok && written < sizeof(wire)) {
        ssize_t n = write(fd, wire + written, sizeof(wire) - written);
        if (n <= 0) { ok = 0; break; }
        written += (size_t)n;
    }
    if (ok && fsync(fd) != 0) ok = 0;
    if (close(fd) != 0) ok = 0;
    memset(wire, 0, sizeof(wire));
    return ok;
}

static void print_grant_hex(const bowie_grant_t *grant)
{
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    static const char hex[] = "0123456789abcdef";
    long fields = bowie_grant_serialize(grant, wire, sizeof(wire));
    if (fields != (long)(sizeof(wire) - sizeof(grant->signature))) return;
    memcpy(wire + fields, grant->signature, sizeof(grant->signature));
    fputs("ANDROID_GRANT_HEX=", stdout);
    for (size_t i = 0u; i < sizeof(wire); i++) {
        putchar(hex[wire[i] >> 4]);
        putchar(hex[wire[i] & 0x0fu]);
    }
    putchar('\n');
    memset(wire, 0, sizeof(wire));
}

static int read_grant_file(const char *path, bowie_grant_t *grant)
{
    uint8_t wire[BOWIE_GRANT_WIRE_LEN], extra;
    size_t received = 0u;
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
             (st.st_mode & 077u) == 0u && st.st_size == (off_t)sizeof(wire);
    while (ok && received < sizeof(wire)) {
        ssize_t n = read(fd, wire + received, sizeof(wire) - received);
        if (n <= 0) { ok = 0; break; }
        received += (size_t)n;
    }
    if (ok && read(fd, &extra, 1u) != 0) ok = 0;
    close(fd);
    if (ok) ok = bowie_grant_deserialize(wire, sizeof(wire), grant) == BOWIE_OK;
    memset(wire, 0, sizeof(wire));
    return ok;
}

static int parse_grant_ttl(const char *text, uint64_t *ttl_ms)
{
    char *end = NULL;
    unsigned long long value;
    uint64_t multiplier;
    if (text == NULL || ttl_ms == NULL || *text == '\0') return 0;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || value == 0u) return 0;
    if (strcmp(end, "m") == 0) multiplier = 60ull * 1000ull;
    else if (strcmp(end, "h") == 0) multiplier = 60ull * 60ull * 1000ull;
    else if (strcmp(end, "d") == 0) multiplier = 24ull * 60ull * 60ull * 1000ull;
    else return 0;
    if (value > (30ull * 24ull * 60ull * 60ull * 1000ull) / multiplier) return 0;
    *ttl_ms = (uint64_t)value * multiplier;
    return 1;
}

static int parse_grant_data_limit(const char *text, uint64_t *bytes)
{
    char *end = NULL;
    unsigned long long value;
    uint64_t multiplier;
    if (text == NULL || bytes == NULL || *text == '\0') return 0;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || value == 0u) return 0;
    if (strcmp(end, "MB") == 0) multiplier = UINT64_C(1000000);
    else if (strcmp(end, "GB") == 0) multiplier = UINT64_C(1000000000);
    else return 0;
    if ((uint64_t)value > UINT64_MAX / multiplier) return 0;
    *bytes = (uint64_t)value * multiplier;
    return 1;
}

static int issue_grant_command(const char *peer_text, const char *path,
                               int allow_relay, uint64_t ttl_ms,
                               const char *ttl_label, uint64_t data_limit_bytes,
                               const char *data_limit_label)
{
    bowie_peer_id_t subject;
    bowie_grant_t grant;
    bowie_engine_config_t cfg;
    bowie_engine_t *engine = NULL;
    uint8_t seed[BOWIE_SIGN_SEED_LEN] = {0};
    char identity_path[PATH_MAX];
    bowie_error_t rc;
    if (!parse_peer_id(peer_text, &subject) || !load_or_create_identity(seed, identity_path)) {
        fprintf(stderr, "Invalid peer ID or could not load the owner identity.\n");
        return EXIT_FAILURE;
    }
    bowie_engine_default_config(&cfg);
    cfg.identity_seed = seed;
    rc = bowie_engine_new(&cfg, &engine);
    memset(seed, 0, sizeof(seed));
    if (rc == BOWIE_OK) {
        uint32_t permissions = BOWIE_GRANT_INTERNET_USE;
        if (allow_relay) permissions |= BOWIE_GRANT_INTERNET_RELAY;
        rc = bowie_engine_issue_limited_grant(engine, &subject, permissions,
                ttl_ms, data_limit_bytes, &grant);
    }
    if (rc != BOWIE_OK || !write_grant_file(path, &grant)) {
        fprintf(stderr, "Could not issue or save the owner grant.\n");
        bowie_engine_free(engine);
        memset(&grant, 0, sizeof(grant));
        return EXIT_FAILURE;
    }
    printf("Owner grant saved to %s (valid for %s, data limit %s%s).\n",
           path, ttl_label, data_limit_label,
           allow_relay ? ", internet relay permitted" : "");
    print_grant_hex(&grant);
    bowie_engine_free(engine);
    memset(&grant, 0, sizeof(grant));
    return EXIT_SUCCESS;
}

static int print_identity_command(void)
{
    bowie_engine_config_t cfg;
    bowie_engine_t *engine = NULL;
    uint8_t seed[BOWIE_SIGN_SEED_LEN] = {0};
    char identity_path[PATH_MAX];
    bowie_peer_id_t peer;
    if (!load_or_create_identity(seed, identity_path)) {
        fprintf(stderr, "Could not load or create the local Bowie identity.\n");
        return EXIT_FAILURE;
    }
    bowie_engine_default_config(&cfg);
    cfg.identity_seed = seed;
    bowie_error_t rc = bowie_engine_new(&cfg, &engine);
    memset(seed, 0, sizeof(seed));
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Could not initialize the local identity: %s (%d)\n",
                bowie_err_strerror(rc), rc);
        return EXIT_FAILURE;
    }
    bowie_engine_peer_id(engine, &peer);
    print_peer_id(&peer);
    putchar('\n');
    bowie_engine_free(engine);
    return EXIT_SUCCESS;
}

static int parse_overlay(const char *input, char address[INET_ADDRSTRLEN], uint8_t *prefix)
{
    const char *slash = strchr(input, '/');
    if (slash == NULL || (size_t)(slash - input) >= INET_ADDRSTRLEN) return 0;
    memcpy(address, input, (size_t)(slash - input));
    address[slash - input] = '\0';
    char *end = NULL;
    long bits = strtol(slash + 1, &end, 10);
    struct in_addr parsed;
    if (*end != '\0' || bits < 1 || bits > 32 || inet_pton(AF_INET, address, &parsed) != 1) return 0;
    *prefix = (uint8_t)bits;
    return 1;
}

static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (*text == '\0' || *end != '\0' || value == 0 || value > 65535u) return 0;
    *port = (uint16_t)value;
    return 1;
}

typedef struct server_options {
    const char *ice_bind_address;
    const char *stun_host;
    uint16_t stun_port;
    const char *turn_host;
    uint16_t turn_port;
    const char *signal_relay_host;
    uint16_t signal_relay_port;
    const char *metered_api_key;
    const char *metered_channel;
    int has_stun;
    int has_turn;
    int has_signal_relay;
    int has_signal_metered;
    int has_ice_bind_address;
    const char *room;
    int has_room;
    const char *grant_file;
    int has_grant_file;
    int full_tunnel;
    const char *dns_server;
    int has_dns_server;
} server_options_t;

static int parse_server_options(int argc, char **argv, int *index,
                                server_options_t *options)
{
    while (*index < argc) {
        const char *option = argv[*index];
        if (strcmp(option, "--ice-bind") == 0) {
            struct in_addr address;
            if (options->has_ice_bind_address || *index + 1 >= argc ||
                inet_pton(AF_INET, argv[*index + 1], &address) != 1) return 0;
            options->ice_bind_address = argv[*index + 1];
            options->has_ice_bind_address = 1;
            *index += 2;
        } else if (strcmp(option, "--stun") == 0) {
            if (options->has_stun || *index + 2 >= argc ||
                argv[*index + 1][0] == '\0' ||
                !parse_port(argv[*index + 2], &options->stun_port)) return 0;
            options->stun_host = argv[*index + 1];
            options->has_stun = 1;
            *index += 3;
        } else if (strcmp(option, "--turn") == 0) {
            if (options->has_turn || *index + 2 >= argc ||
                argv[*index + 1][0] == '\0' ||
                !parse_port(argv[*index + 2], &options->turn_port)) return 0;
            options->turn_host = argv[*index + 1];
            options->has_turn = 1;
            *index += 3;
        } else if (strcmp(option, "--signal-relay") == 0) {
            if (options->has_signal_relay || *index + 2 >= argc ||
                argv[*index + 1][0] == '\0' ||
                !parse_port(argv[*index + 2], &options->signal_relay_port)) return 0;
            options->signal_relay_host = argv[*index + 1];
            options->has_signal_relay = 1;
            *index += 3;
        } else if (strcmp(option, "--signal-metered") == 0) {
            if (options->has_signal_metered || *index + 2 >= argc ||
                argv[*index + 1][0] == '\0' || argv[*index + 2][0] == '\0') return 0;
            options->metered_api_key = argv[*index + 1];
            options->metered_channel = argv[*index + 2];
            options->has_signal_metered = 1;
            *index += 3;
        } else if (strcmp(option, "--room") == 0) {
            if (options->has_room || *index + 1 >= argc || argv[*index + 1][0] == '\0') return 0;
            options->room = argv[*index + 1];
            options->has_room = 1;
            *index += 2;
        } else if (strcmp(option, "--grant-file") == 0) {
            if (options->has_grant_file || *index + 1 >= argc || argv[*index + 1][0] == '\0') return 0;
            options->grant_file = argv[*index + 1];
            options->has_grant_file = 1;
            *index += 2;
        } else if (strcmp(option, "--full-tunnel") == 0) {
            if (options->full_tunnel) return 0;
            options->full_tunnel = 1;
            ++*index;
        } else if (strcmp(option, "--dns") == 0) {
            struct in_addr parsed;
            if (options->has_dns_server || *index + 1 >= argc ||
                inet_pton(AF_INET, argv[*index + 1], &parsed) != 1) return 0;
            options->dns_server = argv[*index + 1];
            options->has_dns_server = 1;
            *index += 2;
        } else {
            return 0;
        }
    }
    return 1;
}

static int read_secret_line(const char *prompt, char *buffer, size_t capacity)
{
    struct termios original, hidden;
    if (buffer == NULL || capacity < 2u) return 0;
    if (!isatty(STDIN_FILENO)) {
        fputs(prompt, stderr);
        fflush(stderr);
        if (fgets(buffer, (int)capacity, stdin) == NULL) {
            memset(buffer, 0, capacity);
            return 0;
        }
    } else {
        if (tcgetattr(STDIN_FILENO, &original) != 0) return 0;

        hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        fputs(prompt, stderr);
        fflush(stderr);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) return 0;
        char *read_result = fgets(buffer, (int)capacity, stdin);
        int restore_rc = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        fputc('\n', stderr);
        if (read_result == NULL || restore_rc != 0) {
            memset(buffer, 0, capacity);
            return 0;
        }
    }

    size_t length = strcspn(buffer, "\r\n");
    if (buffer[length] == '\0' && length == capacity - 1u) {
        memset(buffer, 0, capacity);
        return 0;
    }
    buffer[length] = '\0';
    return length != 0u;
}

static void clear_secret(char *secret, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)secret;
    while (length-- != 0u) *p++ = 0u;
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s listen <tun-name|-> <overlay-ip/prefix|-> [bootstrap-host bootstrap-port] [--room ROOM] [--signal-relay host port | --signal-metered api_key channel] [--stun host port] [--turn host port] [--ice-bind ipv4]\n"
        "  %s connect <tun-name|-> <overlay-ip/prefix|-> <peer-lan-ip> <signal-port> <peer-id-hex> [bootstrap-host bootstrap-port] [--signal-relay host port | --signal-metered api_key channel] [--stun host port] [--turn host port] [--ice-bind ipv4] [--full-tunnel --dns ipv4]\n"
        "  %s connect-dht <tun-name|-> <overlay-ip/prefix|-> <peer-id-hex> <bootstrap-host> <bootstrap-port> [--signal-relay host port | --signal-metered api_key channel] [--stun host port] [--turn host port] [--ice-bind ipv4]\n"
        "  %s connect-room <tun-name|-> <overlay-ip/prefix|-> <room> <bootstrap-host> <bootstrap-port> [options]\n"
        "  %s grant <peer-id-hex> <grant-file> [--relay] [--ttl 1h] [--data-limit 100MB]\n"
        "  %s identity\n"
        "\n"
        "The listener prints its peer ID and signal port, then asks for the\n"
        "connector's peer ID unless --room is configured. Both sides need CAP_NET_ADMIN for TUN setup.\n"
        "--room announces into a shared DHT room; connecting peers must present the owner's grant.\n"
        "--grant-file presents an owner-signed grant. Create one with: %s grant <peer-id-hex> <grant-file> [--relay] [--ttl 1h] [--data-limit 100MB]\n"
        "--turn prompts for username and password without echoing them.\n"
        "--signal-relay sends SDP signaling through a shared UDP relay; configure it on both peers.\n"
        "--signal-metered sends SDP signaling through Metered Realtime Messaging; configure it on both peers.\n"
        "--ice-bind limits ICE UDP sockets to the named local IPv4 address.\n"
        "The current backend supports one TURN endpoint over UDP.\n",
        program, program, program, program, program, program, program);
}

int main(int argc, char **argv)
{
    int listen_mode;
    int dht_connect_mode;
    int room_connect_mode;
    int use_tun;
    char overlay_ip[INET_ADDRSTRLEN];
    uint8_t prefix;
    uint16_t bootstrap_port = 0u;
    bowie_peer_id_t expected_peer;
    bowie_addr_t remote_addr;
    bowie_tun_t *tun = NULL;
    bowie_linux_egress_t egress = {0};
    bowie_linux_client_routes_t client_routes = {0};
    bowie_engine_t *engine = NULL;
    bowie_linux_quota_store_t quota_store = {0};
    char quota_db_path[PATH_MAX];
    bowie_engine_config_t cfg;
    uint8_t identity_seed[BOWIE_SIGN_SEED_LEN] = {0};
    char identity_path[PATH_MAX];
    bowie_error_t rc;
    server_options_t server_opts = {0};
    const char *bootstrap_host = NULL;
    const char *underlay_hosts[BOWIE_LINUX_ROUTE_HOST_MAX];
    size_t underlay_host_count = 0u;
    int has_bootstrap = 0;
    char turn_username[256] = {0};
    char turn_password[512] = {0};
    int option_index;

    if (argc >= 2 && strcmp(argv[1], "grant") == 0) {
        int allow_relay = 0;
        int saw_ttl = 0;
        int saw_data_limit = 0;
        uint64_t ttl_ms = 30ull * 24ull * 60ull * 60ull * 1000ull;
        uint64_t data_limit_bytes = 0u;
        const char *ttl_label = "30 days";
        const char *data_limit_label = "unlimited";
        int i;
        if (argc < 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        for (i = 4; i < argc; ++i) {
            if (strcmp(argv[i], "--relay") == 0 && !allow_relay) allow_relay = 1;
            else if (strcmp(argv[i], "--ttl") == 0 && !saw_ttl && i + 1 < argc) {
                ttl_label = argv[++i];
                if (!parse_grant_ttl(ttl_label, &ttl_ms)) {
                    fprintf(stderr, "Invalid grant lifetime; use a value such as 1h, 30m, or 7d (maximum 30d).\n");
                    return EXIT_FAILURE;
                }
                saw_ttl = 1;
            } else if (strcmp(argv[i], "--data-limit") == 0 &&
                       !saw_data_limit && i + 1 < argc) {
                data_limit_label = argv[++i];
                if (!parse_grant_data_limit(data_limit_label, &data_limit_bytes)) {
                    fprintf(stderr, "Invalid data limit; use a value such as 100MB, 500MB, or 1GB.\n");
                    return EXIT_FAILURE;
                }
                saw_data_limit = 1;
            } else {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        return issue_grant_command(argv[2], argv[3], allow_relay, ttl_ms,
                                   ttl_label, data_limit_bytes, data_limit_label);
    }
    if (argc == 2 && strcmp(argv[1], "identity") == 0)
        return print_identity_command();

    if (argc < 4 || (strcmp(argv[1], "listen") != 0 &&
                      strcmp(argv[1], "connect") != 0 &&
                      strcmp(argv[1], "connect-dht") != 0 &&
                      strcmp(argv[1], "connect-room") != 0)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    listen_mode = strcmp(argv[1], "listen") == 0;
    dht_connect_mode = strcmp(argv[1], "connect-dht") == 0;
    room_connect_mode = strcmp(argv[1], "connect-room") == 0;
    use_tun = strcmp(argv[2], "-") != 0;
    if ((use_tun && !parse_overlay(argv[3], overlay_ip, &prefix)) ||
        (!use_tun && strcmp(argv[3], "-") != 0)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (listen_mode) {
        option_index = 4;
    } else if (dht_connect_mode || room_connect_mode) {
        if (argc < 7) { usage(argv[0]); return EXIT_FAILURE; }
        bootstrap_host = argv[5];
        if (bootstrap_host[0] == '\0' || !parse_port(argv[6], &bootstrap_port)) {
            fprintf(stderr, "Invalid bootstrap host or port.\n");
            return EXIT_FAILURE;
        }
        has_bootstrap = 1;
        option_index = 7;
    } else {
        if (argc < 7) { usage(argv[0]); return EXIT_FAILURE; }
        option_index = 7;
    }

    if ((listen_mode || (!dht_connect_mode && argc > 7)) &&
        option_index < argc && argv[option_index][0] != '-') {
        if (option_index + 1 >= argc || argv[option_index][0] == '\0' ||
            !parse_port(argv[option_index + 1], &bootstrap_port)) {
            fprintf(stderr, "Invalid bootstrap host or port.\n");
            return EXIT_FAILURE;
        }
        bootstrap_host = argv[option_index];
        has_bootstrap = 1;
        option_index += 2;
    }
    if (!parse_server_options(argc, argv, &option_index, &server_opts)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (server_opts.full_tunnel) {
        struct in_addr endpoint;
        if (!use_tun || listen_mode || server_opts.has_signal_metered ||
            !server_opts.has_dns_server ||
            (!dht_connect_mode && !room_connect_mode && inet_pton(AF_INET, argv[4], &endpoint) != 1)) {
            fprintf(stderr, "--full-tunnel needs a client TUN, --dns, and non-metered signaling.\n");
            return EXIT_FAILURE;
        }
        if (!dht_connect_mode && !room_connect_mode)
            underlay_hosts[underlay_host_count++] = argv[4];
        if (has_bootstrap) {
            if (underlay_host_count >= BOWIE_LINUX_ROUTE_HOST_MAX ||
                inet_pton(AF_INET, bootstrap_host, &endpoint) != 1) {
                fprintf(stderr, "--full-tunnel requires a numeric IPv4 DHT bootstrap endpoint.\n");
                return EXIT_FAILURE;
            }
            underlay_hosts[underlay_host_count++] = bootstrap_host;
        }
        const char *configured_hosts[] = {
            server_opts.has_signal_relay ? server_opts.signal_relay_host : NULL,
            server_opts.has_stun ? server_opts.stun_host : NULL,
            server_opts.has_turn ? server_opts.turn_host : NULL
        };
        for (size_t i = 0u; i < sizeof(configured_hosts) / sizeof(configured_hosts[0]); ++i) {
            struct in_addr parsed;
            if (configured_hosts[i] == NULL) continue;
            if (inet_pton(AF_INET, configured_hosts[i], &parsed) != 1) {
                fprintf(stderr, "--full-tunnel needs numeric IPv4 signaling/STUN/TURN endpoints so DNS stays in the tunnel.\n");
                return EXIT_FAILURE;
            }
            underlay_hosts[underlay_host_count++] = configured_hosts[i];
        }
    } else if (server_opts.has_dns_server) {
        fprintf(stderr, "--dns is only valid with --full-tunnel.\n");
        return EXIT_FAILURE;
    }
    if (server_opts.has_signal_relay && server_opts.has_signal_metered) {
        fprintf(stderr, "Choose only one signaling relay backend.\n");
        return EXIT_FAILURE;
    }
    if (server_opts.has_room && (listen_mode == 0 || !has_bootstrap)) {
        fprintf(stderr, "--room is only valid for listen mode and requires a bootstrap endpoint.\n");
        return EXIT_FAILURE;
    }
    if (server_opts.has_grant_file && listen_mode) {
        fprintf(stderr, "--grant-file is for a connector; issue grants on the source peer.\n");
        return EXIT_FAILURE;
    }
    if (!listen_mode && !server_opts.has_grant_file) {
        fprintf(stderr, "Every connector needs its owner-issued --grant-file.\n");
        return EXIT_FAILURE;
    }

    memset(&expected_peer, 0, sizeof(expected_peer));
    memset(&remote_addr, 0, sizeof(remote_addr));
    if (!listen_mode && !room_connect_mode) {
        const char *peer_id_arg = dht_connect_mode ? argv[4] : argv[6];
        if (!parse_peer_id(peer_id_arg, &expected_peer)) {
            fprintf(stderr, "Invalid peer ID.\n");
            return EXIT_FAILURE;
        }
        if (!dht_connect_mode &&
            (!parse_port(argv[5], &remote_addr.port) ||
             inet_pton(AF_INET, argv[4], remote_addr.addr) != 1)) {
            fprintf(stderr, "Invalid peer ID, signal port, or IPv4 address.\n");
            return EXIT_FAILURE;
        }
        if (!dht_connect_mode) remote_addr.family = BOWIE_AF_INET;
    }

    if (server_opts.has_turn &&
        (!read_secret_line("TURN username: ", turn_username, sizeof(turn_username)) ||
         !read_secret_line("TURN password: ", turn_password, sizeof(turn_password)))) {
        fprintf(stderr, "Could not read TURN credentials from terminal.\n");
        clear_secret(turn_username, sizeof(turn_username));
        clear_secret(turn_password, sizeof(turn_password));
        return EXIT_FAILURE;
    }

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    if (use_tun) {
        rc = bowie_tun_open(&tun, argv[2], 0u);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "TUN open failed: %s (%d)\n", bowie_err_strerror(rc), rc);
            goto fail;
        }
        rc = bowie_tun_configure_ipv4(tun, overlay_ip, prefix);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "TUN configuration failed: %s (%d)\n", bowie_err_strerror(rc), rc);
            goto fail;
        }
        if (listen_mode) {
            int egress_rc = bowie_linux_egress_start(&egress, bowie_tun_name(tun),
                                                     overlay_ip, prefix);
            if (egress_rc == 0) {
                fprintf(stderr, "Could not configure IPv4 Internet egress. Check the default route, nftables, and CAP_NET_ADMIN.\n");
                goto fail;
            }
            if (egress_rc == 2)
                fprintf(stderr, "No IPv4 default route found; running overlay-only without Internet egress.\n");
            else
                printf("IPv4 egress enabled through the owner's default uplink; IPv6 egress is disabled.\n");
        } else if (server_opts.full_tunnel) {
            if (!bowie_linux_client_routes_start(&client_routes,
                    bowie_tun_name(tun), underlay_hosts, underlay_host_count,
                    server_opts.dns_server)) {
                fprintf(stderr, "Could not install full-tunnel routes or DNS. Check iproute2, resolvectl, CAP_NET_ADMIN, and existing policy rules.\n");
                goto fail;
            }
            printf("IPv4 full tunnel enabled with DNS %s; IPv6 is fail-closed. Known Bowie transport endpoints bypass the TUN.\n",
                   server_opts.dns_server);
        } else {
            fprintf(stderr,
                    "Linux client is overlay-only by default; direct IPv4 connect can opt in with --full-tunnel --dns <IPv4>.\n");
        }
    }

    bowie_engine_default_config(&cfg);
    if (server_opts.has_stun || server_opts.has_turn) cfg.allow_server = 1;
    cfg.stun_host = server_opts.stun_host;
    cfg.stun_port = server_opts.stun_port;
    cfg.turn_host = server_opts.turn_host;
    cfg.turn_port = server_opts.turn_port;
    cfg.turn_user = server_opts.has_turn ? turn_username : NULL;
    cfg.turn_pass = server_opts.has_turn ? turn_password : NULL;
    cfg.nat_bind_address = server_opts.ice_bind_address;
    if (server_opts.full_tunnel) {
        cfg.prepare_underlay_address = prepare_underlay_route;
        cfg.underlay_context = &client_routes;
    }
    cfg.signal_relay_host = server_opts.signal_relay_host;
    cfg.signal_relay_port = server_opts.signal_relay_port;
    if (server_opts.has_signal_metered) {
        cfg.signal_backend = BOWIE_SIGNAL_BACKEND_METERED;
        cfg.signal_metered_api_key = server_opts.metered_api_key;
        cfg.signal_metered_channel = server_opts.metered_channel;
    }
    if (!load_or_create_identity(identity_seed, identity_path)) {
        fprintf(stderr, "Could not load or create private Bowie identity in user config.\n");
        goto fail;
    }
    if (snprintf(quota_db_path, sizeof(quota_db_path), "%s/grant-usage.sqlite3",
                 identity_path) >= (int)sizeof(quota_db_path) ||
        !bowie_linux_quota_store_open(&quota_store, quota_db_path)) {
        fprintf(stderr, "Could not open durable per-grant quota database; refusing to start without it.\n");
        goto fail;
    }
    cfg.grant_usage_load = bowie_linux_quota_store_load;
    cfg.grant_usage_save = bowie_linux_quota_store_save;
    cfg.grant_usage_context = &quota_store;
    cfg.identity_seed = identity_seed;
    rc = bowie_engine_new(&cfg, &engine);
    memset(identity_seed, 0, sizeof(identity_seed));
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Engine creation failed: %s (%d)\n", bowie_err_strerror(rc), rc);
        goto fail;
    }
    if (server_opts.has_grant_file) {
        bowie_grant_t grant;
        if (!read_grant_file(server_opts.grant_file, &grant) ||
            bowie_engine_set_grant(engine, &grant) != BOWIE_OK) {
            fprintf(stderr, "Owner grant is invalid, expired, or issued to another peer.\n");
            memset(&grant, 0, sizeof(grant));
            goto fail;
        }
        memset(&grant, 0, sizeof(grant));
    }
    if (has_bootstrap) {
        rc = bowie_engine_add_bootstrap(engine, bootstrap_host, bootstrap_port);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "Bootstrap configuration failed: %s (%d)\n",
                    bowie_err_strerror(rc), rc);
            goto fail;
        }
    }
    rc = bowie_engine_start(engine, tun);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Engine start failed: %s (%d)\n", bowie_err_strerror(rc), rc);
        goto fail;
    }

    if (server_opts.has_room) {
        rc = bowie_engine_announce_room(engine, server_opts.room);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "DHT room announce failed: %s (%d)\n", bowie_err_strerror(rc), rc);
            goto fail;
        }
    }

    bowie_peer_id_t own_peer;
    bowie_engine_peer_id(engine, &own_peer);
    printf("NAME="); print_stable_name(&own_peer); printf("\nPEER_ID=");
    print_peer_id(&own_peer); printf("\n");
    printf("SIGNAL_PORT=%u\n", (unsigned)bowie_engine_signal_port(engine));
    if (tun != NULL) printf("TUN=%s OVERLAY=%s/%u\n", bowie_tun_name(tun), overlay_ip, (unsigned)prefix);
    else printf("TRANSPORT_ONLY (no TUN packet forwarding)\n");
    fflush(stdout);

    if (listen_mode) {
        if (server_opts.has_room) {
            printf("Discoverable room active; only peers with valid owner grants can connect.\n");
            rc = bowie_engine_accept_discovered(engine, 120000u);
            goto connection_result;
        }
        char peer_hex[BOWIE_PEER_ID_LEN * 2u + 2u];
        printf("Enter authorized connector peer ID (40 hex characters): ");
        fflush(stdout);
        if (fgets(peer_hex, sizeof(peer_hex), stdin) == NULL ||
            !parse_peer_id(peer_hex, &expected_peer)) {
            fprintf(stderr, "Invalid connector peer ID.\n");
            goto fail;
        }
        printf("Waiting for authenticated peer...\n");
        rc = bowie_engine_accept_from(engine, &expected_peer, 120000u);
    } else if (room_connect_mode) {
        printf("Searching DHT room and connecting to a discovered peer...\n");
        rc = bowie_engine_connect_room(engine, argv[4], 120000u);
    } else {
        char line[8];
        printf("Verify the expected peer ID, then press Enter to connect...\n");
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) goto fail;
        rc = dht_connect_mode
            ? bowie_engine_connect(engine, &expected_peer, 120000u)
            : bowie_engine_connect_direct(engine, &expected_peer, &remote_addr, 120000u);
    }
connection_result:
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Connection failed: %s (%d)\n", bowie_err_strerror(rc), rc);
        goto fail;
    }

    if (tun != NULL) {
        printf("CONNECTED. Test with: ping %s\n",
               listen_mode ? "<connector-overlay-ip>" : "<listener-overlay-ip>");
    } else {
        printf("CONNECTED (transport and identity verified; no TUN packet test).\n");
    }
    printf("Ctrl-C disconnects.\n");
    fflush(stdout);
    while (running) {
        sleep(5u);
        if (running && tun != NULL) {
            bowie_gateway_stats_t stats;
            bowie_engine_gateway_stats(engine, &stats);
            printf("GATEWAY packets_out=%llu bytes_out=%llu packets_in=%llu bytes_in=%llu dropped=%llu\n",
                   (unsigned long long)stats.packets_out,
                   (unsigned long long)stats.bytes_out,
                   (unsigned long long)stats.packets_in,
                   (unsigned long long)stats.bytes_in,
                   (unsigned long long)stats.packets_dropped);
            fflush(stdout);
        }
    }

    bowie_engine_stop(engine);
    bowie_engine_free(engine);
    bowie_linux_quota_store_close(&quota_store);
    bowie_linux_client_routes_stop(&client_routes);
    bowie_linux_egress_stop(&egress);
    bowie_tun_close(tun);
    clear_secret(turn_username, sizeof(turn_username));
    clear_secret(turn_password, sizeof(turn_password));
    return EXIT_SUCCESS;

fail:
    if (engine != NULL) bowie_engine_free(engine);
    bowie_linux_quota_store_close(&quota_store);
    bowie_linux_client_routes_stop(&client_routes);
    bowie_linux_egress_stop(&egress);
    if (tun != NULL) bowie_tun_close(tun);
    clear_secret(turn_username, sizeof(turn_username));
    clear_secret(turn_password, sizeof(turn_password));
    return EXIT_FAILURE;
}
