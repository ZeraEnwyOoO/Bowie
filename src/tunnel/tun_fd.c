#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "tunnel/tun.h"
#include "tunnel/tun_internal.h"

bowie_error_t bowie_tun_wrap_fd(bowie_tun_t **out, int fd, int take_ownership)
{
    bowie_tun_t *tun;
    if (out == NULL || fd < 0) return BOWIE_ERR_INVAL;
    *out = NULL;
    tun = (bowie_tun_t *)calloc(1u, sizeof(*tun));
    if (tun == NULL) return BOWIE_ERR_NOMEM;
    tun->fd = fd;
    tun->owns_fd = take_ownership ? 1 : 0;
    memcpy(tun->name, "packet-fd", sizeof("packet-fd"));
    *out = tun;
    return BOWIE_OK;
}

bowie_error_t bowie_tun_replace_fd(bowie_tun_t *tun, int fd)
{
    if (tun == NULL || fd < 0) return BOWIE_ERR_INVAL;
    if (tun->fd >= 0 && tun->owns_fd) close(tun->fd);
    tun->fd = fd;
    tun->owns_fd = 1;
    return BOWIE_OK;
}

void bowie_tun_set_name(bowie_tun_t *tun, const char *name)
{
    if (tun == NULL || name == NULL) return;
    strncpy(tun->name, name, sizeof(tun->name) - 1u);
    tun->name[sizeof(tun->name) - 1u] = '\0';
}

void bowie_tun_close(bowie_tun_t *tun)
{
    if (tun == NULL) return;
    if (tun->fd >= 0 && tun->owns_fd) close(tun->fd);
    free(tun);
}

int bowie_tun_fd(const bowie_tun_t *tun)
{
    return tun == NULL ? -1 : tun->fd;
}

const char *bowie_tun_name(const bowie_tun_t *tun)
{
    return tun == NULL ? NULL : tun->name;
}

long bowie_tun_read(bowie_tun_t *tun, void *buf, size_t cap)
{
    if (tun == NULL || buf == NULL) return BOWIE_ERR_NULL_ARG;
    if (cap == 0u) return BOWIE_ERR_TOO_SMALL;
    ssize_t n = read(tun->fd, buf, cap);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return BOWIE_ERR_AGAIN;
        return BOWIE_ERR_NETWORK;
    }
    return (long)n;
}

long bowie_tun_write(bowie_tun_t *tun, const void *buf, size_t len)
{
    if (tun == NULL || buf == NULL) return BOWIE_ERR_NULL_ARG;
    if (len == 0u) return BOWIE_ERR_INVAL;
    ssize_t n = write(tun->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return BOWIE_ERR_AGAIN;
        return BOWIE_ERR_NETWORK;
    }
    return (long)n;
}
