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
 * BOWIE — LINUX ENTRY POINT (TUN TEST)
 * ============================================================================
 *
 * This is a minimal entry point for testing the TUN device
 * and the engine lifecycle. It opens the TUN device, creates
 * the engine, starts it, and then waits for a signal.
 *
 * This is not the final CLI. A full CLI will be added later.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "tunnel/tun_linux.h"
#include "platforms/linux/log.h"

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

int main(void) {
    bowie_tun_t *tun = NULL;
    bowie_engine_t *engine = NULL;
    bowie_engine_config_t cfg;
    bowie_error_t rc;

    /* 1. Initialize logging */
    if (app_log_init(NULL) != 0) {
        fprintf(stderr, "Fatal: Failed to initialize logging\n");
        return EXIT_FAILURE;
    }

    /* 2. Setup signal handler */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* 3. Open TUN device */
    rc = bowie_tun_open(&tun, "tun0", 0);
    if (rc != BOWIE_OK) {
        app_log_error("Failed to open TUN device (Error %d).", rc);
        app_log_error("Hint: Are you running as root? (CAP_NET_ADMIN required)");
        return EXIT_FAILURE;
    }
    app_log_info("TUN device 'tun0' opened successfully.");

    /* 4. Create Engine */
    bowie_engine_default_config(&cfg);
    rc = bowie_engine_new(&cfg, &engine);
    if (rc != BOWIE_OK) {
        app_log_error("Failed to create engine (Error %d).", rc);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    app_log_info("Engine created.");

    /* 5. Start Engine */
    rc = bowie_engine_start(engine, tun);
    if (rc != BOWIE_OK) {
        app_log_error("Failed to start engine (Error %d).", rc);
        bowie_engine_free(engine);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    app_log_info("Engine started successfully.");
    app_log_info("DHT Port: %u, Signal Port: %u",
                 bowie_engine_dht_port(engine),
                 bowie_engine_signal_port(engine));

    /* 6. Wait for signal */
    app_log_info("Press Ctrl+C to stop.");
    while (g_running) {
        sleep(1);
    }

    /* 7. Cleanup */
    app_log_info("Shutting down...");
    bowie_engine_stop(engine);
    bowie_engine_free(engine);
    bowie_tun_close(tun);
    app_log_shutdown();

    return EXIT_SUCCESS;
} 
