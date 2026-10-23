#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "engine/engine.h"

#define SCALE_PEERS_DEFAULT 100u
#define SCALE_PEERS_MAX 100u

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0u;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static int requested_peer_count(size_t *count)
{
    const char *value = getenv("BOWIE_SCALE_PEERS");
    if (value == NULL || value[0] == '\0') {
        *count = SCALE_PEERS_DEFAULT;
        return 1;
    }

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed == 0u || parsed > SCALE_PEERS_MAX) return 0;
    *count = (size_t)parsed;
    return 1;
}

int main(void)
{
    size_t count = 0u;
    bowie_engine_t **engines = NULL;
    bowie_peer_id_t *ids = NULL;
    uint16_t *ports = NULL;
    bowie_engine_config_t config;
    uint64_t started_at, elapsed;
    int result = EXIT_FAILURE;

    if (!requested_peer_count(&count)) {
        fprintf(stderr, "BOWIE_SCALE_PEERS must be an integer from 1 to %u.\n",
                SCALE_PEERS_MAX);
        return EXIT_FAILURE;
    }

    engines = calloc(count, sizeof(*engines));
    ids = calloc(count, sizeof(*ids));
    ports = calloc(count, sizeof(*ports));
    if (engines == NULL || ids == NULL || ports == NULL) {
        fprintf(stderr, "Could not allocate the %zu-peer test set.\n", count);
        goto done;
    }

    bowie_engine_default_config(&config);
    started_at = monotonic_ms();
    for (size_t i = 0u; i < count; ++i) {
        bowie_error_t rc = bowie_engine_new(&config, &engines[i]);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "FAIL: create peer %zu/%zu returned %d.\n", i + 1u, count, rc);
            goto done;
        }
        rc = bowie_engine_start(engines[i], NULL);
        if (rc != BOWIE_OK) {
            fprintf(stderr, "FAIL: start peer %zu/%zu returned %d.\n", i + 1u, count, rc);
            goto done;
        }
        bowie_engine_peer_id(engines[i], &ids[i]);
        ports[i] = bowie_engine_signal_port(engines[i]);
        if (ports[i] == 0u) {
            fprintf(stderr, "FAIL: peer %zu/%zu did not get a signaling port.\n", i + 1u, count);
            goto done;
        }

        for (size_t j = 0u; j < i; ++j) {
            if (bowie_peer_id_equal(&ids[i], &ids[j])) {
                fprintf(stderr, "FAIL: peers %zu and %zu got the same peer ID.\n", j + 1u, i + 1u);
                goto done;
            }
            if (ports[i] == ports[j]) {
                fprintf(stderr, "FAIL: peers %zu and %zu got signaling port %u.\n",
                        j + 1u, i + 1u, (unsigned)ports[i]);
                goto done;
            }
        }
        if ((i + 1u) % 10u == 0u || i + 1u == count)
            printf("Started %zu/%zu independent peers\n", i + 1u, count);
    }

    elapsed = monotonic_ms() - started_at;
    printf("PASS: %zu independent peers ran concurrently with unique IDs and signaling ports (%llu ms)\n",
           count, (unsigned long long)elapsed);
    printf("LIMIT: this measures peer startup capacity; it does not create peer-to-peer sessions.\n");
    result = EXIT_SUCCESS;

done:
    if (engines != NULL)
        for (size_t i = 0u; i < count; ++i)
            if (engines[i] != NULL) bowie_engine_free(engines[i]);
    free(ports);
    free(ids);
    free(engines);
    return result;
}
