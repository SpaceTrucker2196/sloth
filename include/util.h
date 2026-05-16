#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdio.h>

static inline const char *fmt_rate(double bps, char *buf, int len) {
    if (bps >= 1e9)      snprintf(buf, (size_t)len, "%.1fGB/s", bps / 1e9);
    else if (bps >= 1e6) snprintf(buf, (size_t)len, "%.1fMB/s", bps / 1e6);
    else if (bps >= 1e3) snprintf(buf, (size_t)len, "%.1fKB/s", bps / 1e3);
    else                 snprintf(buf, (size_t)len, "%.0fB/s",   bps);
    return buf;
}

static inline const char *fmt_bytes(uint64_t b, char *buf, int len) {
    if (b >= (uint64_t)1000000000ULL) snprintf(buf, (size_t)len, "%.1fGB", b / 1e9);
    else if (b >= 1000000ULL)         snprintf(buf, (size_t)len, "%.1fMB", b / 1e6);
    else if (b >= 1000ULL)            snprintf(buf, (size_t)len, "%.1fKB", b / 1e3);
    else                              snprintf(buf, (size_t)len, "%lluB", (unsigned long long)b);
    return buf;
}

#endif /* UTIL_H */
