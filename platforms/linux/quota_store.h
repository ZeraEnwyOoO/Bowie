#ifndef BOWIE_LINUX_QUOTA_STORE_H
#define BOWIE_LINUX_QUOTA_STORE_H

#include <sqlite3.h>
#include "bowie/types.h"

typedef struct bowie_linux_quota_store { sqlite3 *db; } bowie_linux_quota_store_t;
int bowie_linux_quota_store_open(bowie_linux_quota_store_t *store, const char *path);
void bowie_linux_quota_store_close(bowie_linux_quota_store_t *store);
int bowie_linux_quota_store_load(void *context, const bowie_grant_id_t *id,
                                 uint64_t limit, uint64_t *used);
int bowie_linux_quota_store_save(void *context, const bowie_grant_id_t *id,
                                 uint64_t limit, uint64_t used);
#endif
