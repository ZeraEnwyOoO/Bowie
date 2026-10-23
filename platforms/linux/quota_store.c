#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include "quota_store.h"

int bowie_linux_quota_store_open(bowie_linux_quota_store_t *store, const char *path)
{
    if (store == NULL || path == NULL) return 0;
    memset(store, 0, sizeof(*store));
    if (sqlite3_open_v2(path, &store->db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            NULL) != SQLITE_OK) goto fail;
    (void)chmod(path, 0600);
    if (sqlite3_exec(store->db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
            "CREATE TABLE IF NOT EXISTS grant_usage ("
            "grant_id BLOB PRIMARY KEY NOT NULL CHECK(length(grant_id)=16),"
            "byte_limit INTEGER NOT NULL, bytes_used INTEGER NOT NULL);",
            NULL, NULL, NULL) != SQLITE_OK) goto fail;
    return 1;
fail:
    if (store->db != NULL) sqlite3_close(store->db);
    store->db = NULL;
    return 0;
}

void bowie_linux_quota_store_close(bowie_linux_quota_store_t *store)
{
    if (store != NULL && store->db != NULL) sqlite3_close(store->db);
    if (store != NULL) store->db = NULL;
}

int bowie_linux_quota_store_load(void *context, const bowie_grant_id_t *id,
                                 uint64_t limit, uint64_t *used)
{
    bowie_linux_quota_store_t *store = context;
    sqlite3_stmt *stmt = NULL;
    int result = -1;
    if (store == NULL || store->db == NULL || id == NULL || used == NULL ||
        sqlite3_prepare_v2(store->db, "SELECT byte_limit,bytes_used FROM grant_usage WHERE grant_id=?1",
                           -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, id->bytes, BOWIE_GRANT_ID_LEN, SQLITE_STATIC);
    int step = sqlite3_step(stmt);
    if (step == SQLITE_DONE) result = 0;
    else if (step == SQLITE_ROW && (uint64_t)sqlite3_column_int64(stmt, 0) == limit &&
             sqlite3_column_int64(stmt, 1) >= 0) {
        *used = (uint64_t)sqlite3_column_int64(stmt, 1);
        result = 1;
    }
    sqlite3_finalize(stmt);
    return result;
}

int bowie_linux_quota_store_save(void *context, const bowie_grant_id_t *id,
                                 uint64_t limit, uint64_t used)
{
    bowie_linux_quota_store_t *store = context;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    if (store == NULL || store->db == NULL || id == NULL || limit > INT64_MAX ||
        used > INT64_MAX || sqlite3_prepare_v2(store->db,
        "INSERT INTO grant_usage(grant_id,byte_limit,bytes_used) VALUES(?1,?2,?3) "
        "ON CONFLICT(grant_id) DO UPDATE SET bytes_used=max(bytes_used,excluded.bytes_used) "
        "WHERE byte_limit=excluded.byte_limit", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_blob(stmt, 1, id->bytes, BOWIE_GRANT_ID_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)limit);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)used);
    ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(store->db) == 1;
    sqlite3_finalize(stmt);
    return ok;
}
