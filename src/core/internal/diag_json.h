#ifndef BOWIE_CORE_INTERNAL_DIAG_JSON_H
#define BOWIE_CORE_INTERNAL_DIAG_JSON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

static inline int bowie_diag_bytes_contain(const uint8_t *data, size_t len,
                                           const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len == 0u || needle_len > len) return 0;
    for (size_t i = 0u; i + needle_len <= len; ++i)
        if (memcmp(data + i, needle, needle_len) == 0) return 1;
    return 0;
}

static inline const char *bowie_diag_sdp_event(const uint8_t *data, size_t len)
{
    if (bowie_diag_bytes_contain(data, len, "a=setup:actpass")) return "SIGNAL_OFFER";
    if (bowie_diag_bytes_contain(data, len, "a=setup:active") ||
        bowie_diag_bytes_contain(data, len, "a=setup:passive")) return "SIGNAL_ANSWER";
    return "SIGNAL_DESCRIPTION";
}

static inline size_t bowie_diag_candidate_count(const uint8_t *data, size_t len)
{
    static const char marker[] = "a=candidate:";
    size_t count = 0u;
    for (size_t i = 0u; i + sizeof(marker) - 1u <= len; ++i)
        if (memcmp(data + i, marker, sizeof(marker) - 1u) == 0) count++;
    return count;
}

static inline void bowie_diag_hex(const uint8_t *data, size_t len,
                                  char *out, size_t capacity)
{
    static const char hex[] = "0123456789abcdef";
    size_t take = capacity > 0u ? (capacity - 1u) / 2u : 0u;
    if (take > len) take = len;
    for (size_t i = 0u; i < take; ++i) {
        out[i * 2u] = hex[data[i] >> 4];
        out[i * 2u + 1u] = hex[data[i] & 0x0fu];
    }
    if (capacity > 0u) out[take * 2u] = '\0';
}

static inline size_t bowie_diag_json_quote(char *out, size_t capacity,
                                           const char *value)
{
    static const char hex[] = "0123456789abcdef";
    size_t used = 0u;
    if (capacity == 0u) return 0u;
    out[used++] = '"';
    for (const unsigned char *p = (const unsigned char *)(value ? value : "");
         *p != 0u && used + 7u < capacity; ++p) {
        if (*p == '"' || *p == '\\') {
            out[used++] = '\\'; out[used++] = (char)*p;
        } else if (*p < 0x20u) {
            out[used++] = '\\'; out[used++] = 'u'; out[used++] = '0';
            out[used++] = '0'; out[used++] = hex[*p >> 4];
            out[used++] = hex[*p & 0x0fu];
        } else {
            out[used++] = (char)*p;
        }
    }
    if (used < capacity) out[used++] = '"';
    return used;
}

static inline void bowie_diag_json_emit(const char *level, const char *module,
                                        const char *event, const char *peer,
                                        const char *details_json)
{
    char line[2048];
    struct timespec now;
    size_t used = 0u;
    (void)clock_gettime(CLOCK_REALTIME, &now);
    used += (size_t)snprintf(line + used, sizeof(line) - used,
                             "{\"ts\":%lld,\"level\":",
                             (long long)now.tv_sec);
    used += bowie_diag_json_quote(line + used, sizeof(line) - used, level);
    used += (size_t)snprintf(line + used, sizeof(line) - used, ",\"module\":");
    used += bowie_diag_json_quote(line + used, sizeof(line) - used, module);
    used += (size_t)snprintf(line + used, sizeof(line) - used, ",\"event\":");
    used += bowie_diag_json_quote(line + used, sizeof(line) - used, event);
    if (peer != NULL) {
        used += (size_t)snprintf(line + used, sizeof(line) - used, ",\"peer\":");
        used += bowie_diag_json_quote(line + used, sizeof(line) - used, peer);
    }
    used += (size_t)snprintf(line + used, sizeof(line) - used, ",\"details\":%s}\n",
                             details_json ? details_json : "{}");
    if (used >= sizeof(line)) return;
#if defined(__ANDROID__)
    int priority = strcmp(level, "ERROR") == 0 ? ANDROID_LOG_ERROR :
                  strcmp(level, "WARN") == 0 ? ANDROID_LOG_WARN :
                  strcmp(level, "DEBUG") == 0 || strcmp(level, "TRACE") == 0
                      ? ANDROID_LOG_DEBUG : ANDROID_LOG_INFO;
    __android_log_write(priority, "BowieJSON", line);
#else
    (void)fwrite(line, 1u, used, stderr);
    (void)fflush(stderr);
#endif
}

static inline void bowie_diag_json_message(const char *level, const char *module,
                                           const char *event, const char *format,
                                           va_list args)
{
    char message[1024], quoted[2048], details[2100];
    (void)vsnprintf(message, sizeof(message), format, args);
    size_t qlen = bowie_diag_json_quote(quoted, sizeof(quoted), message);
    if (qlen >= sizeof(quoted)) return;
    quoted[qlen] = '\0';
    (void)snprintf(details, sizeof(details), "{\"message\":%s}", quoted);
    bowie_diag_json_emit(level, module, event, NULL, details);
}

#endif
