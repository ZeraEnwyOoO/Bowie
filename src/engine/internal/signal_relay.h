#ifndef BOWIE_ENGINE_INTERNAL_SIGNAL_RELAY_H
#define BOWIE_ENGINE_INTERNAL_SIGNAL_RELAY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bowie/types.h"

#define BOWIE_SIGNAL_RELAY_HEADER_LEN 48u
#define BOWIE_SIGNAL_RELAY_REGISTER 1u
#define BOWIE_SIGNAL_RELAY_DATA 2u
#define BOWIE_SIGNAL_RELAY_FORWARD 3u

typedef struct bowie_signal_relay_packet {
    uint8_t type;
    uint8_t source[BOWIE_PEER_ID_LEN];
    uint8_t target[BOWIE_PEER_ID_LEN];
    const uint8_t *payload;
    size_t payload_len;
} bowie_signal_relay_packet_t;

static inline int bowie_signal_relay_encode(uint8_t *out, size_t capacity,
                                            uint8_t type,
                                            const uint8_t *source,
                                            const uint8_t *target,
                                            const uint8_t *payload,
                                            size_t payload_len,
                                            size_t *out_len)
{
    if (out == NULL || source == NULL || out_len == NULL ||
        (payload_len != 0u && payload == NULL) ||
        payload_len > 65535u || capacity < BOWIE_SIGNAL_RELAY_HEADER_LEN + payload_len)
        return 0;
    memcpy(out, "BWSR", 4u);
    out[4] = 1u;
    out[5] = type;
    memcpy(out + 6u, source, BOWIE_PEER_ID_LEN);
    if (target != NULL) memcpy(out + 26u, target, BOWIE_PEER_ID_LEN);
    else memset(out + 26u, 0, BOWIE_PEER_ID_LEN);
    out[46] = (uint8_t)(payload_len >> 8);
    out[47] = (uint8_t)payload_len;
    if (payload_len != 0u)
        memcpy(out + BOWIE_SIGNAL_RELAY_HEADER_LEN, payload, payload_len);
    *out_len = BOWIE_SIGNAL_RELAY_HEADER_LEN + payload_len;
    return 1;
}

static inline int bowie_signal_relay_decode(const uint8_t *input, size_t input_len,
                                            bowie_signal_relay_packet_t *out)
{
    if (input == NULL || out == NULL || input_len < BOWIE_SIGNAL_RELAY_HEADER_LEN ||
        memcmp(input, "BWSR", 4u) != 0 || input[4] != 1u)
        return 0;
    size_t payload_len = ((size_t)input[46] << 8) | input[47];
    if (payload_len != input_len - BOWIE_SIGNAL_RELAY_HEADER_LEN) return 0;
    memset(out, 0, sizeof(*out));
    out->type = input[5];
    memcpy(out->source, input + 6u, BOWIE_PEER_ID_LEN);
    memcpy(out->target, input + 26u, BOWIE_PEER_ID_LEN);
    out->payload = input + BOWIE_SIGNAL_RELAY_HEADER_LEN;
    out->payload_len = payload_len;
    return 1;
}

#endif
