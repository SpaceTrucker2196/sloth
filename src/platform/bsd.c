#ifdef PLATFORM_BSD

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>   /* struct if_data — BSD/macOS */

#include "sloth.h"

/* ── Rate tracking ───────────────────────────────────────── */

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

/* ── Interface stats via getifaddrs ─────────────────────── */

int bsd_get_ifaces(iface_stat_t *out, int max) {
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    int n = 0;
    for (struct ifaddrs *ifa = ifap; ifa && n < max; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK)
            continue;
        if (!ifa->ifa_data) continue;

        struct if_data *ifd = (struct if_data *)ifa->ifa_data;

        iface_stat_t *s = &out[n];
        memset(s, 0, sizeof(*s));

        size_t nl = strlen(ifa->ifa_name);
        if (nl >= sizeof(s->name)) nl = sizeof(s->name) - 1;
        memcpy(s->name, ifa->ifa_name, nl);
        s->name[nl] = '\0';

        s->rx_bytes   = (uint64_t)ifd->ifi_ibytes;
        s->tx_bytes   = (uint64_t)ifd->ifi_obytes;
        s->rx_packets = (uint64_t)ifd->ifi_ipackets;
        s->tx_packets = (uint64_t)ifd->ifi_opackets;

        /* MAC from sockaddr_dl. Only valid when sdl_alen == 6. */
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (sdl->sdl_alen == 6) {
            const uint8_t *hw = (const uint8_t *)LLADDR(sdl);
            memcpy(s->mac, hw, 6);
        }
        /* Mode classification via ifi_type (IFT_ETHER, IFT_IEEE80211).
         * BSD monitor-mode detection needs a media ioctl (SIOCGIFMEDIA
         * with IFM_IEEE80211_MONITOR) — deferred, so we keep MONITOR
         * as an unset default here. Follow-up for a dedicated PR. */
        if (ifd->ifi_type == 6 /* IFT_ETHER */)
            s->mode = IFACE_MODE_ETHER;
        else if (ifd->ifi_type == 71 /* IFT_IEEE80211 */)
            s->mode = IFACE_MODE_WIFI;

        for (int j = 0; j < g_prev_n; j++) {
            if (strncmp(g_prev[j].name, s->name, 16) != 0) continue;
            double dt = elapsed_sec(&g_prev[j].ts, &now);
            if (dt > 0.001) {
                s->rx_rate = (double)(s->rx_bytes - g_prev[j].rx_bytes) / dt;
                s->tx_rate = (double)(s->tx_bytes - g_prev[j].tx_bytes) / dt;
            }
            break;
        }
        n++;
    }
    freeifaddrs(ifap);

    g_prev_n = n;
    for (int i = 0; i < n; i++) {
        memcpy(g_prev[i].name, out[i].name, sizeof(g_prev[i].name));
        g_prev[i].rx_bytes = out[i].rx_bytes;
        g_prev[i].tx_bytes = out[i].tx_bytes;
        g_prev[i].ts = now;
    }
    return n;
}

/* ── Connections — Week 3: sysctl(KERN_FILE) ────────────── */

int bsd_get_conns(conn_t *out, int max) { (void)out; (void)max; return 0; }

/* ── WiFi scan — Week 4: CoreWLAN / net80211 ────────────── */

int bsd_wifi_scan(wifi_ap_t *out, int max)          { (void)out; (void)max; return 0; }
int bsd_get_wifi_stations(wifi_sta_t *out, int max) { (void)out; (void)max; return 0; }
int bsd_get_arp(arp_entry_t *out, int max)          { (void)out; (void)max; return 0; }
int bsd_get_dhcp(dhcp_lease_t *out, int max) { (void)out; (void)max; return 0; }

static void bsd_init(void)    {}
static void bsd_cleanup(void) {}

platform_ops_t g_platform = {
    bsd_get_ifaces,
    bsd_get_conns,
    bsd_wifi_scan,
    bsd_get_wifi_stations,
    bsd_get_arp,
    bsd_get_dhcp,
    bsd_init,
    bsd_cleanup,
};

#endif /* PLATFORM_BSD */
