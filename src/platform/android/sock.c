#include "platform/platform.h"

bowie_error_t bowie_platform_sock_set_dontfrag(bowie_platform_sock_t fd)
{
    if (fd == BOWIE_PLATFORM_SOCK_INVALID) return BOWIE_ERR_INVAL;
    return BOWIE_ERR_NOT_SUPPORTED;
}

bowie_error_t bowie_platform_sock_bind_iface(bowie_platform_sock_t fd,
                                             const char *name)
{
    if (fd == BOWIE_PLATFORM_SOCK_INVALID) return BOWIE_ERR_INVAL;
    if (name == NULL) return BOWIE_ERR_NULL_ARG;
    return BOWIE_ERR_NOT_SUPPORTED;
}
