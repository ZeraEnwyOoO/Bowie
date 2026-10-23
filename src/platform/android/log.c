#include <android/log.h>
#include "platform/platform.h"

void bowie_platform_log_write(int level, const char *line)
{
    int priority;
    if (line == NULL) return;
    switch (level) {
    case BOWIE_PLATFORM_LOG_ERROR: priority = ANDROID_LOG_ERROR; break;
    case BOWIE_PLATFORM_LOG_WARN:  priority = ANDROID_LOG_WARN; break;
    case BOWIE_PLATFORM_LOG_INFO:  priority = ANDROID_LOG_INFO; break;
    case BOWIE_PLATFORM_LOG_TRACE:
    case BOWIE_PLATFORM_LOG_DEBUG: priority = ANDROID_LOG_DEBUG; break;
    case BOWIE_PLATFORM_LOG_NONE:
    default: return;
    }
    __android_log_write(priority, "Bowie", line);
}
