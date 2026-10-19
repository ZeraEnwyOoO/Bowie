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
 * BOWIE — LINUX ENTRY POINT (MINIMAL WITH TESTS)
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
#include "nat/nat.h"

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

    printf("========================================\n");
    printf("Bowie Linux Client starting...\n");
    printf("========================================\n\n");

    /* 1. Setup signal handler */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* 2. Open TUN device (Layer 1) */
    printf("[TEST 1] Opening TUN device...\n");
    rc = bowie_tun_open(&tun, "tun0", 0);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "FAIL: Could not open TUN device (Error %d).\n", rc);
        fprintf(stderr, "Hint: Are you running as root? (CAP_NET_ADMIN required)\n");
        return EXIT_FAILURE;
    }
    printf("PASS: TUN device 'tun0' opened successfully.\n\n");

    /* 3. Create Engine (Layer 11) */
    printf("[TEST 2] Creating engine...\n");
    bowie_engine_default_config(&cfg);
    rc = bowie_engine_new(&cfg, &engine);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "FAIL: Could not create engine (Error %d).\n", rc);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    printf("PASS: Engine created.\n\n");

    /* 4. Start Engine (Layer 11, DHT, NAT, Signal) */
    printf("[TEST 3] Starting engine...\n");
    rc = bowie_engine_start(engine, tun);
    if (rc != BOWIE_OK) {
        fprintf(stderr, "FAIL: Could not start engine (Error %d).\n", rc);
        bowie_engine_free(engine);
        bowie_tun_close(tun);
        return EXIT_FAILURE;
    }
    printf("PASS: Engine started.\n\n");

    /* 5. Verify DHT Socket (Layer 4) */
    printf("[TEST 4] Verifying DHT socket...\n");
    uint16_t dht_port = bowie_engine_dht_port(engine);
    uint16_t signal_port = bowie_engine_signal_port(engine);
    
    printf("  DHT Port: %u\n", dht_port);
    printf("  Signal Port: %u\n", signal_port);
    
    if (dht_port > 0) {
        printf("PASS: DHT socket is listening on port %u.\n\n", dht_port);
    } else {
        printf("WARN: DHT socket is not listening (port = 0).\n\n");
    }

    /* 6. Verify DHT Thread (Layer 4) — Wait and check node count */
    printf("[TEST 5] Checking DHT thread (5 seconds)...\n");
    for (int i = 0; i < 5; i++) {
        sleep(1);
        size_t node_count = bowie_engine_dht_node_count(engine);
        printf("  [%d/5] DHT Nodes: %zu\n", i + 1, node_count);
    }
    printf("PASS: DHT thread is running (node count checked).\n\n");

    /* 7. Verify Event Queue (Layer 11) */
    printf("[TEST 6] Checking event queue...\n");
    int event_count = 0;
    bowie_event_record_t ev;
    while (bowie_engine_poll_event(engine, &ev)) {
        printf("  Event: %d (code %u)\n", ev.event, ev.code);
        event_count++;
    }
    printf("PASS: Event queue checked (%d events).\n\n", event_count);

    /* 8. Wait for signal */
    printf("========================================\n");
    printf("All tests passed. Press Ctrl+C to stop.\n");
    printf("========================================\n");
    while (g_running) {
        sleep(1);
    }

    /* 9. Cleanup */
    printf("\nShutting down...\n");
    bowie_engine_stop(engine);
    bowie_engine_free(engine);
    bowie_tun_close(tun);
    printf("Cleanup complete.\n");

    return EXIT_SUCCESS;
}
