#ifndef BOWIE_ANDROID_USERSPACE_GATEWAY_H
#define BOWIE_ANDROID_USERSPACE_GATEWAY_H

#include <stddef.h>
#include <stdint.h>

#include "gateway/gateway.h"

typedef struct bowie_android_userspace_gateway bowie_android_userspace_gateway_t;

int bowie_android_userspace_gateway_new(bowie_android_userspace_gateway_t **out);
void bowie_android_userspace_gateway_free(bowie_android_userspace_gateway_t *gateway);
int bowie_android_userspace_gateway_process(void *context,
        const uint8_t *packet, size_t packet_len,
        bowie_gateway_emit_fn emit, void *emit_context);

#endif
