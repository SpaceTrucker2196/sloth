/* Loaded-library versions and the runtime sqlite floor (#142). The
 * libpcap half is src/libver_pcap.c (#213): src/db.c needs the floor
 * below, and a daemon with a database and no capture must not link
 * libpcap to get it. */

#include "libver.h"

#include <stdio.h>

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

static int g_sqlite_override;

const char *libver_sqlite(void) {
#ifdef WITH_SQLITE
    const char *v = sqlite3_libversion();
    return v ? v : "unknown";
#else
    return "none";
#endif
}

int libver_format_libs(char *buf, size_t n, const char *pcap) {
    if (!buf || n == 0) return 0;
    return snprintf(buf, n, "pcap: %s; sqlite: %s",
                    pcap ? pcap : "none", libver_sqlite());
}

int libver_sqlite_floor_ok(int version_number) {
    return version_number >= LIBVER_SQLITE_FLOOR_NUM;
}

int libver_sqlite_loaded(void) {
    if (g_sqlite_override) return g_sqlite_override;
#ifdef WITH_SQLITE
    return sqlite3_libversion_number();
#else
    return 0;
#endif
}

int libver_sqlite_refuse(char *err, size_t n) {
    const int v = libver_sqlite_loaded();
    if (libver_sqlite_floor_ok(v)) return 0;
    /* Decoded from the number rather than libver_sqlite()'s string, so
     * the message names the version that was actually compared — under
     * the test seam the two differ. */
    if (err && n)
        snprintf(err, n, "loaded sqlite %d.%d.%d is below the %s floor",
                 v / 1000000, (v / 1000) % 1000, v % 1000,
                 LIBVER_SQLITE_FLOOR_STR);
    return -1;
}

void libver_sqlite_override_for_test(int v) {
    g_sqlite_override = v;
}
