#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "platform/platform.h"

long bowie_platform_entropy(void *buf, size_t n)
{
    if (buf == NULL && n != 0u) return -1;
    if (n == 0u) return 0;

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t *cursor = (uint8_t *)buf;
    size_t remaining = n;
    while (remaining != 0u) {
        ssize_t got = read(fd, cursor, remaining);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            close(fd);
            return -1;
        }
        cursor += (size_t)got;
        remaining -= (size_t)got;
    }
    close(fd);
    return (long)n;
}
