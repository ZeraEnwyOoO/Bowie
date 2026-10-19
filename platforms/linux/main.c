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
 * BOWIE — LINUX ENTRY POINT (CLI)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <zlog.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "engine/engine.h"
#include "tunnel/tun_linux.h"

static volatile sig_atomic_t g_running = 1;
static zlog_category_t *g_log_cat = NULL;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_peer_id(const bowie_peer_id_t *id) {
    for (int i = 0; i < BOWIE_PEER_ID_LEN; i++) {
        printf("%02x", id->bytes[i]);
    }
}

static int parse_peer_id(const char *hex, bowie_peer_id_t *out) {
    if (strlen(hex) != BOWIE_PEER_ID_LEN * 2) return -1;
    for (int i = 0; i < BOWIE_PEER_ID_LEN; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) return -1;
        out->bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static void bowie_log_hook(bowie_log_level_t level, const char *line, void *userdata) {
    (void)userdata;
    if (g_log_cat == NULL) return;

    switch (level) {
    case BOWIE_LOG_ERROR: zlog_error(g_log_cat, "%s", line); break;
    case BOWIE_LOG_WARN:  zlog_warn(g_log_cat, "%s", line);  break;
    case BOWIE_LOG_INFO:  zlog_info(g_log_cat, "%s", line);  break;
    case BOWIE_LOG_DEBUG: zlog_debug(g_log_cat, "%s", line); break;
    case BOWIE_LOG_TRACE: zlog_debug(g_log_cat, "[TRACE] %s", line); break;
    default: break;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  start             Start the engine\n");
        fprintf(stderr, "  connect <peer_id> Connect to a peer (hex ID)\n");
        fprintf(stderr, "  bootstrap <ip> <port>  Add a bootstrap node\n");
        fprintf(stderr, "  status            Show engine status\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);

    /* 1. ចាប់ផ្តើម zlog */
    int rc_zlog = zlog_init("zlog.conf");
    if (rc_zlog != 0) {
        fprintf(stderr, "zlog_init failed. Is zlog.conf in the current directory?\n");
        return 1;
    }

    g_log_cat = zlog_get_category("bowie.engine");
    if (g_log_cat == NULL) {
        fprintf(stderr, "zlog_get_category failed\n");
        zlog_fini();
        return 1;
    }

    /* 2. បង្កើត Engine */
    bowie_engine_config_t cfg;
    bowie_engine_default_config(&cfg);
    cfg.log_level = BOWIE_LOG_DEBUG;
    cfg.dht_port = 0;
    cfg.nat_port = 0;

    bowie_engine_t *engine = NULL;
    bowie_error_t rc = bowie_engine_new(&cfg, &engine);
    if (rc != BOWIE_OK) {
        zlog_error(g_log_cat, "Failed to create engine: %s", bowie_err_strerror(rc));
        zlog_fini();
        return 1;
    }

    /* 3. ដំឡើង Hook */
    bowie_hooks_t hooks;
    bowie_hooks_clear(&hooks);
    hooks.log = bowie_log_hook;

    rc = bowie_engine_set_hooks(engine, &hooks);
    if (rc != BOWIE_OK) {
        zlog_error(g_log_cat, "Failed to set hooks: %s", bowie_err_strerror(rc));
        bowie_engine_free(engine);
        zlog_fini();
        return 1;
    }

    /* 4. បើក TUN Device */
    bowie_tun_t *tun = NULL;
    rc = bowie_tun_open(&tun, NULL, 0);
    if (rc != BOWIE_OK) {
        zlog_error(g_log_cat, "Failed to open TUN device: %s", bowie_err_strerror(rc));
        zlog_error(g_log_cat, "Hint: Are you running as root? (CAP_NET_ADMIN required)");
        bowie_engine_free(engine);
        zlog_fini();
        return 1;
    }

    /* 5. ចាប់ផ្តើម Engine */
    rc = bowie_engine_start(engine, tun);
    if (rc != BOWIE_OK) {
        zlog_error(g_log_cat, "Failed to start engine: %s", bowie_err_strerror(rc));
        bowie_tun_close(tun);
        bowie_engine_free(engine);
        zlog_fini();
        return 1;
    }

    /* 6. ដំណើរការតាម Command */
    if (strcmp(argv[1], "start") == 0) {
        zlog_info(g_log_cat, "Waiting for peers... Press Ctrl+C to stop.");
        while (g_running) sleep(1);
    } 
    else if (strcmp(argv[1], "connect") == 0) {
        if (argc < 3) goto cleanup;
        bowie_peer_id_t peer_id;
        if (parse_peer_id(argv[2], &peer_id) != 0) {
            zlog_error(g_log_cat, "Invalid peer ID format.");
            goto cleanup;
        }
        zlog_info(g_log_cat, "Connecting to peer...");
        rc = bowie_engine_connect(engine, &peer_id, 30000);
        if (rc != BOWIE_OK) {
            zlog_error(g_log_cat, "Connection failed: %s", bowie_err_strerror(rc));
            goto cleanup;
        }
        zlog_info(g_log_cat, "Connected! Waiting...");
        while (g_running) sleep(1);
    } 
    else if (strcmp(argv[1], "bootstrap") == 0) {
        if (argc < 4) goto cleanup;
        const char *ip = argv[2];
        uint16_t port = (uint16_t)atoi(argv[3]);
        zlog_info(g_log_cat, "Bootstrapping DHT to %s:%u...", ip, port);
        rc = bowie_engine_add_bootstrap(engine, ip, port);
        if (rc != BOWIE_OK) {
            zlog_error(g_log_cat, "Bootstrap failed: %s", bowie_err_strerror(rc));
            goto cleanup;
        }
        zlog_info(g_log_cat, "Bootstrap successful! Waiting...");
        while (g_running) sleep(1);
    }    
    else if (strcmp(argv[1], "status") == 0) {
        bowie_peer_id_t peer_id;
        bowie_engine_peer_id(engine, &peer_id);
        
        // បង្ហាញព័ត៌មានជា JSON តាមរយៈ zlog ផ្ទាល់
        zlog_info(g_log_cat, "Engine Status: %s", bowie_engine_state_name(bowie_engine_get_state(engine)));
        zlog_info(g_log_cat, "DHT Port: %u", bowie_engine_dht_port(engine));
        zlog_info(g_log_cat, "Signal Port: %u", bowie_engine_signal_port(engine));
        zlog_info(g_log_cat, "DHT Nodes: %zu", bowie_engine_dht_node_count(engine));
    } 
    else {
        zlog_error(g_log_cat, "Unknown command: %s", argv[1]);
    }

cleanup:
    bowie_engine_stop(engine);
    bowie_engine_free(engine);
    bowie_tun_close(tun);
    zlog_fini(); // បិទ zlog

    return 0;
}
