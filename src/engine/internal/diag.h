#ifndef BOWIE_ENGINE_INTERNAL_DIAG_H
#define BOWIE_ENGINE_INTERNAL_DIAG_H

#include "core/internal/diag_json.h"

static inline const char *bowie_diag_level_name(int level)
{
    switch (level) {
    case 1: return "ERROR";
    case 2: return "WARN";
    case 4: return "DEBUG";
    case 5: return "TRACE";
    default: return "INFO";
    }
}

static inline void bowie_engine_diag_level(const char *module, int level,
                                           const char *format, ...)
{
    va_list args;
    va_start(args, format);
    bowie_diag_json_message(bowie_diag_level_name(level), module,
                            "DIAGNOSTIC", format, args);
    va_end(args);
}

static inline void bowie_engine_diag(const char *module, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    bowie_diag_json_message("INFO", module, "DIAGNOSTIC", format, args);
    va_end(args);
}

#endif
