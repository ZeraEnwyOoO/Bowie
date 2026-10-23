#ifndef BOWIE_TUNNEL_TUN_INTERNAL_H
#define BOWIE_TUNNEL_TUN_INTERNAL_H

#include "bowie/types.h"

struct bowie_tun {
    int fd;
    int owns_fd;
    char name[64];
};

void bowie_tun_set_name(bowie_tun_t *tun, const char *name);

#endif
