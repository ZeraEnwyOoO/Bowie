#include "engine/signal_metered.h"

int bowie_metered_start(const bowie_metered_config_t *config,
                        bowie_metered_t **out)
{
    (void)config;
    if (out != NULL) *out = NULL;
    return -1;
}

int bowie_metered_publish(bowie_metered_t *client, const uint8_t *peer_id,
                          const void *payload, size_t payload_len)
{
    (void)client;
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    return -1;
}

void bowie_metered_stop(bowie_metered_t *client)
{
    (void)client;
}

int bowie_metered_wait_ice_servers(bowie_metered_t *client,
                                   uint32_t timeout_ms)
{
    (void)client;
    (void)timeout_ms;
    return -1;
}
