#ifdef PLATFORM_BSD

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>     /* struct if_data — BSD/macOS */
#include <net/if_media.h>  /* SIOCGIFMEDIA / IFM_IEEE80211_MONITOR */

#include "sloth.h"

/* ── Monitor-mode probe (SIOCGIFMEDIA) ─────────────────────
 * On BSD / macOS, monitor-mode is a mediaopt on the WiFi driver.
 * Query it via SIOCGIFMEDIA and check ifm_current for the monitor
 * bit. Returns 1 if monitor-mode is currently set, 0 otherwise
 * (including the "not a WiFi iface" case). Silent on failure —
 * we don't have IFM_IEEE80211_MONITOR available on every BSD, so
 * a compile guard picks the right constant. */
static int bsd_iface_is_monitor(int sock, const char *ifname) {
    struct ifmediareq ifmr;
    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name) - 1);
    if (ioctl(sock, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
        return 0;
    /* IFM_IEEE80211_MONITOR isn't in every BSD's headers; on macOS
     * it lives as 0x0000000000100000ULL. Feature-test with the ifdef
     * so the file stays portable. */
#ifdef IFM_IEEE80211_MONITOR
    if ((ifmr.ifm_current & IFM_IEEE80211_MONITOR) != 0)
        return 1;
#else
    (void)ifmr;
#endif
    return 0;
}

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

    /* Single AF_INET UDP socket for all SIOCGIFMEDIA lookups this
     * poll. Cheap to open once, closed at the end. If open fails,
     * mon_sock stays -1 and monitor-mode detection quietly reports
     * "not monitor" — behaviour matches pre-detection code path. */
    int mon_sock = socket(AF_INET, SOCK_DGRAM, 0);

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
        /* Mode classification via ifi_type (IFT_ETHER, IFT_IEEE80211)
         * with a SIOCGIFMEDIA probe for the WiFi-in-monitor-mode case
         * (matches the Linux /sys/class/net/<if>/type == 803 detection
         * in linux.c so NO_MONITOR_MODE fires identically on both
         * platforms). */
        if (ifd->ifi_type == 6 /* IFT_ETHER */) {
            s->mode = IFACE_MODE_ETHER;
        } else if (ifd->ifi_type == 71 /* IFT_IEEE80211 */) {
            if (mon_sock >= 0 && bsd_iface_is_monitor(mon_sock, s->name))
                s->mode = IFACE_MODE_MONITOR;
            else
                s->mode = IFACE_MODE_WIFI;
        }

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
    if (mon_sock >= 0) close(mon_sock);

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
