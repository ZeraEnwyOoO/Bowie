#ifndef BOWIE_ENGINE_SIGNAL_METERED_H
#define BOWIE_ENGINE_SIGNAL_METERED_H

#include <stddef.h>
#include <stdint.h>

/* Raw Metered Realtime Messaging transport. Payload bytes are Bowie SDP
 * signaling blobs. The callback runs on the client's service thread. */
typedef struct bowie_metered bowie_metered_t;
typedef void (*bowie_metered_message_fn)(void *context,
                                         const uint8_t *peer_id,
                                         const uint8_t *payload,
                                         size_t payload_len);
typedef void (*bowie_metered_turn_fn)(void *context, const char *host,
                                      uint16_t port, const char *username,
                                      const char *credential);
typedef void (*bowie_metered_presence_fn)(void *context, size_t peer_count);

typedef struct bowie_metered_config {
    const char *publishable_key; /* pk_live_...; never a secret sk_ key */
    const char *channel;         /* must match the key's channelPatterns */
    uint8_t local_peer_id[20];
    bowie_metered_message_fn on_message;
    bowie_metered_turn_fn on_turn_server;
    bowie_metered_presence_fn on_presence;
    void *context;
} bowie_metered_config_t;

/* Starts an owned service thread and connects to wss://rms.metered.ca/v1. */
int bowie_metered_start(const bowie_metered_config_t *config,
                        bowie_metered_t **out);
/* Sends an SDP signaling payload directly to a discovered peer. */
int bowie_metered_publish(bowie_metered_t *client, const uint8_t *peer_id,
                          const void *payload, size_t payload_len);
void bowie_metered_stop(bowie_metered_t *client);

/* Wait until a welcome has been processed and its ICE server metadata has
 * been applied. Returns 0 when ready, -1 on timeout or shutdown. */
int bowie_metered_wait_ice_servers(bowie_metered_t *client,
                                   uint32_t timeout_ms);

#endif
