#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ntop.h"
#include "platform/linux_parse.h"
#include "platform/linux_pid.h"
#include "platform/linux_wifi.h"

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
    if ((f = fopen("/proc/net/tcp",  "r")) != NULL) { parse_proc_conns(f,  PROTO_TCP, out, max, &n); fclose(f); }
    if ((f = fopen("/proc/net/tcp6", "r")) != NULL) { parse_proc_conns6(f, PROTO_TCP, out, max, &n); fclose(f); }
    if ((f = fopen("/proc/net/udp",  "r")) != NULL) { parse_proc_conns(f,  PROTO_UDP, out, max, &n); fclose(f); }
    if ((f = fopen("/proc/net/udp6", "r")) != NULL) { parse_proc_conns6(f, PROTO_UDP, out, max, &n); fclose(f); }
    resolve_pids(out, n);
    return n;
}

/* ── WiFi scan — real impl in linux_wifi.c when WITH_WIFI=1 ── */
#ifndef WITH_WIFI
int linux_wifi_scan(wifi_ap_t *out, int max) {
    (void)out; (void)max;
    return 0;
}
#endif

/* ── ARP neighbor table ────────────────────────────────── */

static int linux_get_arp(arp_entry_t *out, int max) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return 0;
    char line[256];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }  /* skip header */
    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char ip[46], hw[10], flags_str[10], mac_str[20], mask[10], iface[16];
        if (sscanf(line, "%45s %9s %9s %19s %9s %15s",
                   ip, hw, flags_str, mac_str, mask, iface) != 6)
            continue;
        unsigned m0,m1,m2,m3,m4,m5;
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                   &m0,&m1,&m2,&m3,&m4,&m5) != 6)
            continue;
        /* skip incomplete entries (all-zero MAC) */
        if (m0==0 && m1==0 && m2==0 && m3==0 && m4==0 && m5==0)
            continue;
        snprintf(out[n].ip, sizeof(out[n].ip), "%s", ip);
        out[n].mac[0]=(uint8_t)m0; out[n].mac[1]=(uint8_t)m1;
        out[n].mac[2]=(uint8_t)m2; out[n].mac[3]=(uint8_t)m3;
        out[n].mac[4]=(uint8_t)m4; out[n].mac[5]=(uint8_t)m5;
        snprintf(out[n].iface, sizeof(out[n].iface), "%s", iface);
        n++;
    }
    fclose(f);
    return n;
}

static void linux_init(void)    {}
static void linux_cleanup(void) {}

platform_ops_t g_platform = {
    linux_get_ifaces,
    linux_get_conns,
    linux_wifi_scan,
    linux_get_arp,
    linux_init,
    linux_cleanup,
};

#endif /* PLATFORM_LINUX */
