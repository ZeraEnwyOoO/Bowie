#include <string.h>
#include <stdatomic.h>

#include "platform/platform.h"

static atomic_int vpn_fd_established = 0;

void bowie_android_set_vpn_authorized(int authorized)
{
    atomic_store_explicit(&vpn_fd_established, authorized ? 1 : 0, memory_order_release);
}

bowie_error_t bowie_platform_check_permission(const char *name)
{
    if (name == NULL) return BOWIE_ERR_NULL_ARG;
    if (strcmp(name, "internet") == 0) return BOWIE_OK;
    if (strcmp(name, "vpn") == 0) {
        return atomic_load_explicit(&vpn_fd_established, memory_order_acquire)
            ? BOWIE_OK : BOWIE_ERR_PERMISSION;
    }
    return BOWIE_ERR_NOT_SUPPORTED;
}
