#ifndef BOWIE_TUNNEL_TUN_H
#define BOWIE_TUNNEL_TUN_H

#include <stddef.h>
#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Common packet-tunnel handle operations. Platform code creates the fd. */
bowie_error_t bowie_tun_wrap_fd(bowie_tun_t **out, int fd, int take_ownership);
/* Replace the descriptor owned by a wrapped TUN object. Takes ownership of fd. */
bowie_error_t bowie_tun_replace_fd(bowie_tun_t *tun, int fd);
void bowie_tun_close(bowie_tun_t *tun);
int bowie_tun_fd(const bowie_tun_t *tun);
const char *bowie_tun_name(const bowie_tun_t *tun);
long bowie_tun_read(bowie_tun_t *tun, void *buf, size_t cap);
long bowie_tun_write(bowie_tun_t *tun, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
