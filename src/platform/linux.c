#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ntop.h"
#include "platform/linux_parse.h"

/* ── Rate tracking across polls ─────────────────────────── */

typedef struct {
    char     name[16];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    struct timespec ts;
} prev_iface_t;

static prev_iface_t g_prev[MAX_IFACES];
static int          g_prev_n = 0;

static double elapsed_sec(const struct timespec *a, const struct timespec *b) {
    return (double)(b->tv_sec - a->tv_sec)
         + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

/* ── Interface stats ────────────────────────────────────── */

int linux_get_ifaces(iface_stat_t *out, int max) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    int n = parse_proc_ifaces(f, out, max);
    fclose(f);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < g_prev_n; j++) {
            if (strncmp(g_prev[j].name, out[i].name, 16) != 0) continue;
            double dt = elapsed_sec(&g_prev[j].ts, &now);
            if (dt > 0.001) {
                out[i].rx_rate = (double)(out[i].rx_bytes - g_prev[j].rx_bytes) / dt;
                out[i].tx_rate = (double)(out[i].tx_bytes - g_prev[j].tx_bytes) / dt;
            }
            break;
        }
    }

    g_prev_n = n;
    for (int i = 0; i < n; i++) {
        memcpy(g_prev[i].name, out[i].name, sizeof(g_prev[i].name));
        g_prev[i].rx_bytes = out[i].rx_bytes;
        g_prev[i].tx_bytes = out[i].tx_bytes;
        g_prev[i].ts = now;
    }
    return n;
}

/* ── Connections ────────────────────────────────────────── */

int linux_get_conns(conn_t *out, int max) {
    int n = 0;
    FILE *f;
    if ((f = fopen("/proc/net/tcp", "r")) != NULL) {
        parse_proc_conns(f, PROTO_TCP, out, max, &n);
        fclose(f);
    }
    if ((f = fopen("/proc/net/udp", "r")) != NULL) {
        parse_proc_conns(f, PROTO_UDP, out, max, &n);
        fclose(f);
    }
    return n;
}

/* ── WiFi scan — Week 4: nl80211 ────────────────────────── */

int linux_wifi_scan(wifi_ap_t *out, int max) {
    (void)out; (void)max;
    return 0;
}

static void linux_init(void)    {}
static void linux_cleanup(void) {}

platform_ops_t g_platform = {
    linux_get_ifaces,
    linux_get_conns,
    linux_wifi_scan,
    linux_init,
    linux_cleanup,
};

#endif /* PLATFORM_LINUX */
