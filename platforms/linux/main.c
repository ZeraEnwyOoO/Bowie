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
 * BOWIE — LINUX ENTRY POINT (MINIMAL)
 * ============================================================================
 *
 * This is a minimal entry point to test the engine and the TUN
 * device. It does not depend on log.c or config.c. It uses
 * printf directly for output.
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

    printf("Bowie Linux Client starting...\n");

    /* 1. Setup signal handler */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* 2. Open TUN device */
    rc = bowie_tun_open(&tun, "tun0", 0);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Failed to open TUN device (Error %d).\n", rc);
        fprintf(stderr, "Hint: Are you running as root? (CAP_NET_ADMIN required)\n");
        return EXIT_FAILURE;
    }
    printf("TUN device 'tun0' opened successfully.\n");

    /* 3. Create Engine */
    bowie_engine_default_config(&cfg);
    rc = bowie_engine_new(&cfg, &engine);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Failed to create engine (Error %d).\n", rc);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    printf("Engine created.\n");

    /* 4. Start Engine */
    rc = bowie_engine_start(engine, tun);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "Failed to start engine (Error %d).\n", rc);
        bowie_engine_free(engine);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    printf("Engine started successfully.\n");
    printf("DHT Port: %u, Signal Port: %u\n",
           bowie_engine_dht_port(engine),
           bowie_engine_signal_port(engine));

    /* 5. Wait for signal */
    printf("Press Ctrl+C to stop.\n");
    while (g_running) {
        sleep(1);
    }

    /* 6. Cleanup */
    printf("Shutting down...\n");
    bowie_engine_stop(engine);
    bowie_engine_free(engine);
    bowie_tun_close(tun);

    return EXIT_SUCCESS;
}
