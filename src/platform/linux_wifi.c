#ifdef PLATFORM_LINUX
#ifdef WITH_WIFI

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>

#include "sloth.h"
#include "beacon_snoop.h"
#include "observe.h"
#include "platform/linux_wifi.h"
#include "platform/linux_self.h"
#include "sloth_clock.h"
#include "wifi_freq.h"

/* ── Netlink attribute helpers ───────────────────────────── */

#define NA_HDRLEN   4u
#define NA_ALIGN(n) (((unsigned)(n)+3u)&~3u)
#define NA_DATA(a)  ((void *)((char *)(a) + NA_HDRLEN))
#define NA_TYPE(a)  ((int)((a)->nla_type & 0x3fffu))  /* strip nested/byteorder flags */

static int na_ok(const struct nlattr *a, int rem) {
    return rem >= (int)NA_HDRLEN
        && (unsigned)a->nla_len >= NA_HDRLEN
        && (int)a->nla_len <= rem;
}

static struct nlattr *na_next(struct nlattr *a, int *rem) {
    int n = (int)NA_ALIGN(a->nla_len);
    *rem -= n;
    return (struct nlattr *)((char *)a + n);
}

/* ── Wireless interface discovery via /proc/net/wireless ─── */

static int find_wlan_ifaces(char names[][16], int max) {
    FILE *f = fopen("/proc/net/wireless", "r");
    if (!f) return 0;
    char line[256];
    if (!fgets(line, sizeof(line), f) ||   /* header 1 */
        !fgets(line, sizeof(line), f)) {   /* header 2 */
        fclose(f);
        return 0;
    }
    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ') p++;
        char *col = strchr(p, ':');
        if (!col) continue;
        *col = '\0';
        size_t l = strlen(p);
        if (l == 0 || l >= 16) continue;
        memcpy(names[n++], p, l + 1);
    }
    fclose(f);
    return n;
}

/* ── Resolve nl80211 generic netlink family ID ───────────── */

static int get_nl80211_id(int fd) {
    static const char fname[] = "nl80211";
    const size_t attr_sz  = NA_HDRLEN + sizeof(fname);
    const size_t msg_sz   = NLMSG_HDRLEN + GENL_HDRLEN + NA_ALIGN(attr_sz);

    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr  *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    struct nlattr     *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);

    nlh->nlmsg_len   = (uint32_t)msg_sz;
    nlh->nlmsg_type  = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = 1;
    gh->cmd          = CTRL_CMD_GETFAMILY;
    gh->version      = 1;
    na->nla_type     = CTRL_ATTR_FAMILY_NAME;
    na->nla_len      = (uint16_t)attr_sz;
    memcpy(NA_DATA(na), fname, sizeof(fname));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, buf, msg_sz, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;

    uint8_t rbuf[1024];
    ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
    if (r < (ssize_t)NLMSG_HDRLEN) return -1;

    nlh = (struct nlmsghdr *)rbuf;
    if (nlh->nlmsg_type == NLMSG_ERROR) return -1;

    gh  = (struct genlmsghdr *)NLMSG_DATA(nlh);
    int rem = (int)(nlh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
    na  = (struct nlattr *)((char *)gh + GENL_HDRLEN);

    while (na_ok(na, rem)) {
        if (NA_TYPE(na) == CTRL_ATTR_FAMILY_ID)
            return (int)(*(uint16_t *)NA_DATA(na));
        na = na_next(na, &rem);
    }
    return -1;
}

/* ── 802.11 IE parsing: delegated to the shared parser ───── *
 *
 * Roadmap B3b. This file used to carry its own IE walker yielding an
 * SSID plus three booleans, so an AP seen in managed mode reported far
 * less than the same AP seen in monitor mode — RSN ciphers, AKM, MFP,
 * WPS state, vendor and PHY tier were all available in the beacon IEs
 * and simply not read. beacon_parse_ies() is now the single source of
 * truth for both paths.
 *
 * The output conventions differ between the two and are preserved
 * rather than unified, because `enc` and `ssid` reach the JSONL
 * wifi_ap record and changing their spelling would be a wire-format
 * change, not a refactor:
 *
 *   hidden SSID   beacon parser ""      → this path "<hidden>"
 *   open network  beacon parser "OPEN"  → this path "Open"
 *
 * Worth unifying, but as a deliberate schema decision rather than a
 * side effect of sharing a parser. */

static void parse_ies(const uint8_t *ies, int len, uint16_t cap,
                      wifi_ap_t *ap) {
    beacon_rsn_t rsn;
    memset(&rsn, 0, sizeof(rsn));   /* parser zeroes it too; belt and braces */
    char   enc[10]  = "";
    char   ssid[33] = "";
    int    channel  = 0;

    beacon_parse_ies(ies, len, (cap >> 4) & 1, 0,
                     ssid, &channel, enc, &rsn, NULL);

    /* Map the beacon parser's conventions onto this path's. */
    if (ssid[0]) snprintf(ap->ssid, sizeof(ap->ssid), "%s", ssid);
    else         memcpy(ap->ssid, "<hidden>", 9);

    if (strcmp(enc, "OPEN") == 0) memcpy(ap->enc, "Open", 5);
    else snprintf(ap->enc, sizeof(ap->enc), "%s", enc);

    /* The IE-derived channel is more reliable than the frequency when
     * present, but nl80211 already gave us a frequency and the DS Param
     * IE is absent on many 6 GHz APs — so only take it as a fallback. */
    if (ap->channel == 0 && channel > 0) ap->channel = channel;

    snprintf(ap->pairwise, sizeof(ap->pairwise), "%s", rsn.pairwise);
    snprintf(ap->group,    sizeof(ap->group),    "%s", rsn.group);
    snprintf(ap->akm,      sizeof(ap->akm),      "%s", rsn.akm);
    snprintf(ap->vendor,   sizeof(ap->vendor),   "%s", rsn.vendor);
    snprintf(ap->phy,      sizeof(ap->phy),      "%s", rsn.phy);
    ap->mfp            = rsn.mfp;
    ap->has_wps        = rsn.has_wps;
    ap->wps_state      = rsn.wps_state;
    ap->wps_locked     = rsn.wps_locked;
    ap->has_qbss       = rsn.has_qbss;
    ap->qbss_stations  = rsn.qbss_stations;
    ap->qbss_chan_util = rsn.qbss_chan_util;
}

/* ── Parse one NL80211_CMD_NEW_SCAN_RESULTS message ─────── */

static int parse_scan_msg(const struct nlmsghdr *nlh,
                          wifi_ap_t *out, int max, int n) {
    if (n >= max) return n;

    const struct genlmsghdr *gh = (const struct genlmsghdr *)NLMSG_DATA(nlh);
    if (gh->cmd != NL80211_CMD_NEW_SCAN_RESULTS) return n;

    int rem = (int)(nlh->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
    struct nlattr *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);

    while (na_ok(na, rem)) {
        if (NA_TYPE(na) != NL80211_ATTR_BSS) { na = na_next(na, &rem); continue; }

        /* walk the nested BSS attributes */
        int brem = (int)na->nla_len - (int)NA_HDRLEN;
        struct nlattr *ba = (struct nlattr *)NA_DATA(na);

        uint8_t        mac[6] = {0};
        int32_t        sig_mbm  = -9000;   /* -90.00 dBm default */
        uint32_t       freq     = 0;
        uint16_t       cap      = 0;
        const uint8_t *ies      = NULL;
        int            ies_len  = 0;
        int            bss_status = WIFI_STATUS_NONE;

        while (na_ok(ba, brem)) {
            int t = NA_TYPE(ba);
            if      (t == NL80211_BSS_BSSID)
                memcpy(mac, NA_DATA(ba), 6);
            else if (t == NL80211_BSS_SIGNAL_MBM)
                sig_mbm = *(const int32_t *)NA_DATA(ba);
            else if (t == NL80211_BSS_FREQUENCY)
                freq = *(const uint32_t *)NA_DATA(ba);
            else if (t == NL80211_BSS_INFORMATION_ELEMENTS) {
                ies     = (const uint8_t *)NA_DATA(ba);
                ies_len = (int)(ba->nla_len - NA_HDRLEN);
            } else if (t == NL80211_BSS_CAPABILITY)
                cap = *(const uint16_t *)NA_DATA(ba);
            else if (t == NL80211_BSS_STATUS)
                bss_status = (int)(*(const uint32_t *)NA_DATA(ba));
            ba = na_next(ba, &brem);
        }

        wifi_ap_t *ap = &out[n++];
        memset(ap, 0, sizeof(*ap));
        ap->status = bss_status;
        snprintf(ap->bssid, sizeof(ap->bssid),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        ap->signal_dbm = sig_mbm / 100;
        /* #167: this path carried its own copy of the converter that
         * accepted 5180..5900 where the monitor path accepted
         * 5160..5895, so the same AP could be channel 0 to a managed
         * scan and a channel to a capture. One converter now. */
        ap->channel    = wifi_freq_channel((int)freq, NULL);

        if (ies && ies_len > 0)
            parse_ies(ies, ies_len, cap, ap);
        else {
            memcpy(ap->ssid, "<no-ie>", 8);
            if (cap & 0x10) memcpy(ap->enc, "WEP",  4);
            else            memcpy(ap->enc, "Open", 5);
        }
        break;  /* one BSS per NLMSG */
    }
    return n;
}

/* ── AP sort comparator: strongest signal first ──────────── */

static int ap_cmp(const void *a, const void *b) {
    return ((const wifi_ap_t *)b)->signal_dbm
         - ((const wifi_ap_t *)a)->signal_dbm;
}

/* ── Public API ──────────────────────────────────────────── */

/* ── Scan-trigger policy, limiter and instrumentation (#84) ── */

/* The old comment here promised per-interface rate limiting and the code
 * delivered one function-static timestamp shared by every interface, so
 * on a multi-radio sensor the first radio find_wlan_ifaces() enumerated
 * consumed the whole budget and the others were triggered only when it
 * happened to be quiet. Made genuinely per-interface rather than
 * documented as global: the interfaces are enumerated in a fixed order,
 * so "global" does not mean "fair", it means one radio is preferred and
 * the rest are starved — and a WiFi sensor with a dedicated monitor
 * radio alongside an uplink is the deployment this tool targets.
 * find_wlan_ifaces() caps at WIFI_SCAN_TRIGGER_MAX_IFACES, so a fixed
 * table of that size gives every enumerated radio a slot with no
 * allocation and no unbounded growth. */
static struct {
    unsigned ifidx;   /* 0 = free; if_nametoindex() never returns 0 */
    time_t   last;
} g_trigger_slots[WIFI_SCAN_TRIGGER_MAX_IFACES];

static wifi_scan_trigger_stats_t g_trigger_stats;

/* Is `ifidx` due for a trigger at `now`? Marks the slot when it is. */
static int trigger_slot_due(unsigned ifidx, time_t now) {
    int free_slot = -1, oldest = 0;

    for (int i = 0; i < WIFI_SCAN_TRIGGER_MAX_IFACES; i++) {
        if (g_trigger_slots[i].ifidx == ifidx) {
            if (now - g_trigger_slots[i].last
                    < WIFI_SCAN_TRIGGER_MIN_INTERVAL_SEC)
                return 0;
            g_trigger_slots[i].last = now;
            return 1;
        }
        if (free_slot < 0 && g_trigger_slots[i].ifidx == 0) free_slot = i;
        if (g_trigger_slots[i].last < g_trigger_slots[oldest].last) oldest = i;
    }

    /* Unknown interface: take a free slot, else evict the least recently
     * triggered one. Unreachable while the enumerator caps at the table
     * size, but a silently wrong limiter is what this fix is about. */
    int idx = free_slot >= 0 ? free_slot : oldest;
    g_trigger_slots[idx].ifidx = ifidx;
    g_trigger_slots[idx].last  = now;
    return 1;
}

size_t linux_wifi_prepare_scan_trigger(uint8_t *buf, size_t sz, int family,
                                       unsigned ifidx, time_t now) {
    const size_t msg_sz = NLMSG_HDRLEN + GENL_HDRLEN
                        + NA_ALIGN(NA_HDRLEN + sizeof(uint32_t));

    if (!buf || sz < msg_sz || ifidx == 0 || family < 0) return 0;

    g_trigger_stats.considered++;

    /* Strict observation refuses the request before it exists. */
    if (!observe_active_allowed()) {
        g_trigger_stats.suppressed_policy++;
        return 0;
    }

    if (!trigger_slot_due(ifidx, now)) {
        g_trigger_stats.suppressed_rate++;
        return 0;
    }

    memset(buf, 0, msg_sz);

    struct nlmsghdr  *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    struct nlattr     *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);

    nlh->nlmsg_len   = (uint32_t)msg_sz;
    nlh->nlmsg_type  = (uint16_t)family;
    nlh->nlmsg_flags = NLM_F_REQUEST;   /* no ACK: success is silent */
    nlh->nlmsg_seq   = 99;
    gh->cmd          = NL80211_CMD_TRIGGER_SCAN;
    /* IFINDEX and nothing else. Omitting NL80211_ATTR_SCAN_SSIDS is what
     * keeps this a passive scan: with an SSID list the kernel transmits
     * directed probe requests, which MISSION §2 forbids outright. */
    na->nla_type     = NL80211_ATTR_IFINDEX;
    na->nla_len      = (uint16_t)(NA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)NA_DATA(na) = ifidx;

    g_trigger_stats.requests_built++;
    return msg_sz;
}

void linux_wifi_scan_trigger_stats(wifi_scan_trigger_stats_t *out) {
    if (out) *out = g_trigger_stats;
}

void linux_wifi_scan_trigger_reset(void) {
    memset(g_trigger_slots, 0, sizeof(g_trigger_slots));
    memset(&g_trigger_stats, 0, sizeof(g_trigger_stats));
}

/* Fire NL80211_CMD_TRIGGER_SCAN on a disposable fd and close immediately.
   Rate-limited to once per WIFI_SCAN_TRIGGER_MIN_INTERVAL_SEC per interface,
   and suppressed entirely unless --allow-active permitted it.  Errors
   (EBUSY = scan already in progress, EPERM = no CAP_NET_ADMIN) are silently
   discarded — the GET_SCAN below returns whatever cached results the kernel
   holds either way, which is also what a strict run relies on. */
static void trigger_scan_async(int family, unsigned ifidx) {
    uint8_t sbuf[64];
    size_t msg_sz = linux_wifi_prepare_scan_trigger(sbuf, sizeof(sbuf),
                                                    family, ifidx, sloth_wall());
    if (msg_sz == 0) return;   /* no socket is opened when nothing was built */

    int tfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (tfd < 0) return;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sendto(tfd, sbuf, msg_sz, 0, (struct sockaddr *)&sa, sizeof(sa));
    close(tfd);
}

size_t linux_wifi_prepare_get_scan(uint8_t *buf, size_t sz, int family,
                                   unsigned ifidx) {
    const size_t msg_sz = NLMSG_HDRLEN + GENL_HDRLEN
                        + NA_ALIGN(NA_HDRLEN + sizeof(uint32_t));

    if (!buf || sz < msg_sz || ifidx == 0 || family < 0) return 0;

    /* Deliberately NOT consulting observe_active_allowed(): a GET_SCAN
     * dump reads the kernel's cached BSS table and changes nothing, and
     * that cache is all a strict run has for the WiFi view. Strict stops
     * sloth asking the kernel to scan, not reading what it already holds. */
    memset(buf, 0, msg_sz);

    struct nlmsghdr  *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    struct nlattr     *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);

    nlh->nlmsg_len   = (uint32_t)msg_sz;
    nlh->nlmsg_type  = (uint16_t)family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq   = 2;
    gh->cmd          = NL80211_CMD_GET_SCAN;
    na->nla_type     = NL80211_ATTR_IFINDEX;
    na->nla_len      = (uint16_t)(NA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)NA_DATA(na) = ifidx;

    return msg_sz;
}

size_t linux_wifi_prepare_scan_pass(uint8_t *get_buf, size_t get_sz,
                                    int family, unsigned ifidx) {
    /* kick a background scan so the cache reflects all visible APs —
     * only when --allow-active permitted it (see the trigger builder) */
    trigger_scan_async(family, ifidx);
    return linux_wifi_prepare_get_scan(get_buf, get_sz, family, ifidx);
}

int linux_wifi_scan(wifi_ap_t *out, int max) {
    char ifaces[8][16];
    int nifaces = find_wlan_ifaces(ifaces, 8);
    if (nifaces == 0) return 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return 0;

    int family = get_nl80211_id(fd);
    if (family < 0) { close(fd); return 0; }

    int n = 0;

    for (int ii = 0; ii < nifaces && n < max; ii++) {
        unsigned ifidx = if_nametoindex(ifaces[ii]);
        if (ifidx == 0) continue;

        /* Ask (policy-gated, may build nothing), then read (never gated). */
        uint8_t sbuf[64];
        size_t msg_sz = linux_wifi_prepare_scan_pass(sbuf, sizeof(sbuf),
                                                     family, ifidx);
        if (msg_sz == 0) continue;

        struct sockaddr_nl sa;
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        if (sendto(fd, sbuf, msg_sz, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            continue;

        /* receive multi-part dump */
        static uint8_t rbuf[32 * 1024];
        int done = 0;
        while (!done) {
            ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
            if (r <= 0) break;
            int len = (int)r;
            struct nlmsghdr *nlhr = (struct nlmsghdr *)rbuf;
            while (NLMSG_OK(nlhr, len)) {
                if (nlhr->nlmsg_type == NLMSG_DONE)  { done = 1; break; }
                if (nlhr->nlmsg_type == NLMSG_ERROR) { done = 1; break; }
                n = parse_scan_msg(nlhr, out, max, n);
                nlhr = NLMSG_NEXT(nlhr, len);
            }
        }
    }

    close(fd);

    if (n > 1)
        qsort(out, (size_t)n, sizeof(wifi_ap_t), ap_cmp);

    return n;
}

/* ── Station info parser for NL80211_ATTR_STA_INFO (nested) ── */

static void parse_sta_info(struct nlattr *sa, int slen, wifi_sta_t *st) {
    while (na_ok(sa, slen)) {
        int t = NA_TYPE(sa);
        switch (t) {
        case NL80211_STA_INFO_INACTIVE_TIME:
            st->inactive_ms = *(const uint32_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_RX_BYTES:
            if (st->rx_bytes == 0)
                st->rx_bytes = *(const uint32_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_TX_BYTES:
            if (st->tx_bytes == 0)
                st->tx_bytes = *(const uint32_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_RX_BYTES64:
            st->rx_bytes = *(const uint64_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_TX_BYTES64:
            st->tx_bytes = *(const uint64_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_SIGNAL:
            st->signal_dbm = *(const int8_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_CONNECTED_TIME:
            st->connected_secs = *(const uint32_t *)NA_DATA(sa);
            break;
        case NL80211_STA_INFO_TX_BITRATE:
        case NL80211_STA_INFO_RX_BITRATE: {
            uint32_t kbps = 0;
            int rrem = (int)(sa->nla_len) - (int)NA_HDRLEN;
            struct nlattr *ra = (struct nlattr *)NA_DATA(sa);
            while (na_ok(ra, rrem)) {
                int rt = NA_TYPE(ra);
                if (rt == NL80211_RATE_INFO_BITRATE32) {
                    kbps = *(const uint32_t *)NA_DATA(ra) * 100u;
                    break;
                } else if (rt == NL80211_RATE_INFO_BITRATE) {
                    kbps = (uint32_t)(*(const uint16_t *)NA_DATA(ra)) * 100u;
                }
                ra = na_next(ra, &rrem);
            }
            if (t == NL80211_STA_INFO_TX_BITRATE)
                st->tx_rate_kbps = kbps;
            else
                st->rx_rate_kbps = kbps;
            break;
        }
        default: break;
        }
        sa = na_next(sa, &slen);
    }
}

int linux_wifi_get_stations(wifi_sta_t *out, int max) {
    char ifaces[8][16];
    int nifaces = find_wlan_ifaces(ifaces, 8);
    if (nifaces == 0) return 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return 0;

    int family = get_nl80211_id(fd);
    if (family < 0) { close(fd); return 0; }

    int n = 0;

    for (int ii = 0; ii < nifaces && n < max; ii++) {
        unsigned ifidx = if_nametoindex(ifaces[ii]);
        if (ifidx == 0) continue;

        const size_t msg_sz = NLMSG_HDRLEN + GENL_HDRLEN
                            + NA_ALIGN(NA_HDRLEN + sizeof(uint32_t));
        uint8_t sbuf[64];
        memset(sbuf, 0, sizeof(sbuf));

        struct nlmsghdr  *nlh = (struct nlmsghdr *)sbuf;
        struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
        struct nlattr     *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);

        nlh->nlmsg_len   = (uint32_t)msg_sz;
        nlh->nlmsg_type  = (uint16_t)family;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nlh->nlmsg_seq   = 3;
        gh->cmd          = NL80211_CMD_GET_STATION;
        na->nla_type     = NL80211_ATTR_IFINDEX;
        na->nla_len      = (uint16_t)(NA_HDRLEN + sizeof(uint32_t));
        *(uint32_t *)NA_DATA(na) = ifidx;

        struct sockaddr_nl sa;
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        if (sendto(fd, sbuf, msg_sz, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            continue;

        static uint8_t rbuf[16 * 1024];
        int done = 0;
        while (!done) {
            ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
            if (r <= 0) break;
            int len = (int)r;
            struct nlmsghdr *nlhr = (struct nlmsghdr *)rbuf;
            while (NLMSG_OK(nlhr, len)) {
                if (nlhr->nlmsg_type == NLMSG_DONE)  { done = 1; break; }
                if (nlhr->nlmsg_type == NLMSG_ERROR) { done = 1; break; }

                const struct genlmsghdr *rgh =
                    (const struct genlmsghdr *)NLMSG_DATA(nlhr);
                if (rgh->cmd == NL80211_CMD_NEW_STATION && n < max) {
                    wifi_sta_t *st = &out[n];
                    memset(st, 0, sizeof(*st));

                    int rem = (int)(nlhr->nlmsg_len) - NLMSG_HDRLEN - GENL_HDRLEN;
                    struct nlattr *a =
                        (struct nlattr *)((char *)rgh + GENL_HDRLEN);

                    while (na_ok(a, rem)) {
                        int at = NA_TYPE(a);
                        if (at == NL80211_ATTR_MAC &&
                                (int)a->nla_len >= (int)NA_HDRLEN + 6) {
                            const uint8_t *m = (const uint8_t *)NA_DATA(a);
                            snprintf(st->mac, sizeof(st->mac),
                                     "%02x:%02x:%02x:%02x:%02x:%02x",
                                     m[0],m[1],m[2],m[3],m[4],m[5]);
                        } else if (at == NL80211_ATTR_STA_INFO) {
                            int slen = (int)(a->nla_len) - (int)NA_HDRLEN;
                            parse_sta_info((struct nlattr *)NA_DATA(a),
                                           slen, st);
                        }
                        a = na_next(a, &rem);
                    }

                    if (st->mac[0]) n++;
                }
                nlhr = NLMSG_NEXT(nlhr, len);
            }
        }
    }

    close(fd);
    return n;
}

/* ── Monitor-channel retune (NL80211_CMD_SET_CHANNEL) ────── */

/* Append a u32 nl attribute at `off` in `base`, return the new offset. */
static size_t nla_put_u32(char *base, size_t off, int type, uint32_t val) {
    struct nlattr *na = (struct nlattr *)(base + off);
    na->nla_type = (uint16_t)type;
    na->nla_len  = (uint16_t)(NA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)NA_DATA(na) = val;
    return off + NA_ALIGN(NA_HDRLEN + sizeof(uint32_t));
}

int linux_wifi_ack_result(const void *buf, long len) {
    /* The reply to an NLM_F_ACK request is one NLMSG_ERROR whose
     * `error` is 0 for an ACK or the negated errno of the refusal
     * (EPERM without CAP_NET_ADMIN, EBUSY while the device is in use,
     * EINVAL for a frequency the driver will not take). Until #91 the
     * errno was collapsed to -1 here and the reason was lost. */
    if (!buf || len < (long)(NLMSG_HDRLEN + sizeof(struct nlmsgerr)))
        return -EIO;
    const struct nlmsghdr *rh = (const struct nlmsghdr *)buf;
    if (rh->nlmsg_type != NLMSG_ERROR) return -EIO;
    if (rh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr) ||
        (long)rh->nlmsg_len > len) return -EIO;
    struct nlmsgerr e;
    memcpy(&e, NLMSG_DATA(rh), sizeof(e));
    if (e.error == 0) return 0;
    /* The kernel sends a negative errno. Anything else is not a value
     * this code can name, and must not read as success. */
    if (e.error < 0 && e.error > -4096) return e.error;
    return -EIO;
}

int linux_wifi_set_channel(const char *iface, int freq_mhz) {
    if (!iface || !iface[0] || freq_mhz <= 0) return -EINVAL;
    unsigned ifidx = if_nametoindex(iface);
    if (ifidx == 0) return -ENODEV;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return errno ? -errno : -EIO;
    int family = get_nl80211_id(fd);
    /* No nl80211 family registered: no cfg80211 driver to ask. */
    if (family < 0) { close(fd); return -EOPNOTSUPP; }

    /* Short recv timeout so a missing ACK never wedges the poll loop. */
    struct timeval tv = { 0, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr   *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh  = (struct genlmsghdr *)NLMSG_DATA(nlh);
    char *attrs = (char *)gh + GENL_HDRLEN;

    size_t off = 0;
    off = nla_put_u32(attrs, off, NL80211_ATTR_IFINDEX,             ifidx);
    off = nla_put_u32(attrs, off, NL80211_ATTR_WIPHY_FREQ,          (uint32_t)freq_mhz);
    off = nla_put_u32(attrs, off, NL80211_ATTR_WIPHY_CHANNEL_TYPE,  NL80211_CHAN_NO_HT);

    size_t msg_sz = NLMSG_HDRLEN + GENL_HDRLEN + off;
    nlh->nlmsg_len   = (uint32_t)msg_sz;
    nlh->nlmsg_type  = (uint16_t)family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 3;
    gh->cmd          = NL80211_CMD_SET_CHANNEL;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, buf, msg_sz, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = errno ? errno : EIO;
        close(fd);
        return -e;
    }

    uint8_t rbuf[256];
    ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
    int rc;
    if (r < 0) {
        /* SO_RCVTIMEO expiring is EAGAIN; say what it means. */
        int e = errno;
        rc = (e == EAGAIN || e == EWOULDBLOCK) ? -ETIMEDOUT
                                                : (e ? -e : -EIO);
    } else {
        rc = linux_wifi_ack_result(rbuf, (long)r);
    }
    close(fd);
    return rc;
}

/* ── Every wireless device's own address (#183) ──────────── */

int linux_wifi_parse_wdev_macs(const void *buf, size_t len, int family,
                               uint8_t (*out)[6], int max, int n, int *done) {
    if (!buf) return n;
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
    int rem = len > 0x7fffffff ? 0x7fffffff : (int)len;
    for (; NLMSG_OK(nlh, rem); nlh = NLMSG_NEXT(nlh, rem)) {
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            if (done) *done = 1;
            return n;
        }
        if ((int)nlh->nlmsg_type != family) continue;
        if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) continue;
        const struct genlmsghdr *gh = (const struct genlmsghdr *)NLMSG_DATA(nlh);
        if (gh->cmd != NL80211_CMD_NEW_INTERFACE) continue;
        int arem = (int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
        struct nlattr *a = (struct nlattr *)((char *)gh + GENL_HDRLEN);
        for (; na_ok(a, arem); a = na_next(a, &arem)) {
            if (NA_TYPE(a) == NL80211_ATTR_MAC &&
                (int)a->nla_len == (int)NA_HDRLEN + 6)
                n = linux_self_append(out, max, n, (const uint8_t *)NA_DATA(a));
        }
    }
    return n;
}

int linux_wifi_get_wdev_macs(uint8_t (*out)[6], int max, int n) {
    if (!out || n >= max) return n;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return n;
    int family = get_nl80211_id(fd);
    if (family < 0) { close(fd); return n; }

    struct timeval tv = { 0, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t sbuf[NLMSG_HDRLEN + GENL_HDRLEN];
    memset(sbuf, 0, sizeof(sbuf));
    struct nlmsghdr   *nlh = (struct nlmsghdr *)sbuf;
    struct genlmsghdr *gh  = (struct genlmsghdr *)NLMSG_DATA(nlh);
    nlh->nlmsg_len   = (uint32_t)sizeof(sbuf);
    nlh->nlmsg_type  = (uint16_t)family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq   = 4;
    gh->cmd          = NL80211_CMD_GET_INTERFACE;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, sbuf, sizeof(sbuf), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return n;
    }
    static uint8_t rbuf[16 * 1024];
    int done = 0;
    while (!done) {
        ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
        if (r <= 0) break;
        n = linux_wifi_parse_wdev_macs(rbuf, (size_t)r, family, out, max, n, &done);
    }
    close(fd);
    return n;
}

/* ── Two read-only GETs for --preflight (#247) ───────────── */

/* The kernel's refusal in an NLMSG_ERROR, -EIO when it is malformed. */
static int nl_err_of(const struct nlmsghdr *nlh) {
    if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr)) return -EIO;
    const struct nlmsgerr *e = (const struct nlmsgerr *)NLMSG_DATA(nlh);
    return e->error < 0 ? e->error : -EIO;
}

/* The first nl80211 message of `cmd` in buf: its attributes and their
 * length, or NULL; *err gets a kernel refusal when one comes first. */
static struct nlattr *nl_find_cmd(const void *buf, size_t len, int family,
                                  int cmd, int *arem, int *err) {
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
    int rem = len > 0x7fffffff ? 0x7fffffff : (int)len;
    *err = 0;
    for (; NLMSG_OK(nlh, rem); nlh = NLMSG_NEXT(nlh, rem)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) { *err = nl_err_of(nlh); return NULL; }
        if (nlh->nlmsg_type == NLMSG_DONE) return NULL;
        if ((int)nlh->nlmsg_type != family) continue;
        if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) continue;
        const struct genlmsghdr *gh = (const struct genlmsghdr *)NLMSG_DATA(nlh);
        if (gh->cmd != cmd) continue;
        *arem = (int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
        return (struct nlattr *)((char *)gh + GENL_HDRLEN);
    }
    return NULL;
}

int linux_wifi_parse_reg(const void *buf, size_t len, int family, char alpha2[3]) {
    int rem = 0, err = 0;
    if (!buf || !alpha2) return -EIO;
    alpha2[0] = '\0';
    struct nlattr *a = nl_find_cmd(buf, len, family, NL80211_CMD_GET_REG, &rem, &err);
    if (!a) return err ? err : 0;
    for (; na_ok(a, rem); a = na_next(a, &rem)) {
        if (NA_TYPE(a) != NL80211_ATTR_REG_ALPHA2) continue;
        const char *s = (const char *)NA_DATA(a);
        int n = (int)a->nla_len - (int)NA_HDRLEN;
        /* Two printable characters: "US", "00" (world), "99" (built
         * from the device's own rules). Anything else is not a code. */
        if (n < 2 || s[0] < 0x21 || s[0] > 0x7e || s[1] < 0x21 || s[1] > 0x7e)
            return 0;
        alpha2[0] = s[0];
        alpha2[1] = s[1];
        alpha2[2] = '\0';
        return 1;
    }
    return 0;
}

int linux_wifi_parse_iftypes(const void *buf, size_t len, int family, unsigned *mask) {
    int rem = 0, err = 0;
    if (!buf || !mask) return -EIO;
    *mask = 0;
    struct nlattr *a = nl_find_cmd(buf, len, family, NL80211_CMD_NEW_WIPHY, &rem, &err);
    if (!a) return err ? err : 0;
    for (; na_ok(a, rem); a = na_next(a, &rem)) {
        if (NA_TYPE(a) != NL80211_ATTR_SUPPORTED_IFTYPES) continue;
        /* Nested: one flag attribute per mode, its type the mode. */
        int irem = (int)a->nla_len - (int)NA_HDRLEN;
        struct nlattr *t = (struct nlattr *)NA_DATA(a);
        for (; na_ok(t, irem); t = na_next(t, &irem))
            if (NA_TYPE(t) > 0 && NA_TYPE(t) < 32) *mask |= 1u << NA_TYPE(t);
        return 1;
    }
    return 0;
}

int linux_wifi_parse_bands(const void *buf, size_t len, int family, unsigned *mask) {
    int rem = 0, err = 0;
    if (!buf || !mask) return -EIO;
    *mask = 0;
    struct nlattr *a = nl_find_cmd(buf, len, family, NL80211_CMD_NEW_WIPHY, &rem, &err);
    if (!a) return err ? err : 0;
    for (; na_ok(a, rem); a = na_next(a, &rem)) {
        if (NA_TYPE(a) != NL80211_ATTR_WIPHY_BANDS) continue;
        /* Nested: one attribute per band, its type the NL80211_BAND_*;
         * in each, NL80211_BAND_ATTR_FREQS, one nest per frequency. */
        int brem = (int)a->nla_len - (int)NA_HDRLEN;
        struct nlattr *b = (struct nlattr *)NA_DATA(a);
        for (; na_ok(b, brem); b = na_next(b, &brem)) {
            int band = NA_TYPE(b);
            if (band < 0 || band >= 32) continue;
            int frem = (int)b->nla_len - (int)NA_HDRLEN;
            struct nlattr *f = (struct nlattr *)NA_DATA(b);
            for (; na_ok(f, frem); f = na_next(f, &frem)) {
                if (NA_TYPE(f) != NL80211_BAND_ATTR_FREQS) continue;
                int qrem = (int)f->nla_len - (int)NA_HDRLEN;
                struct nlattr *q = (struct nlattr *)NA_DATA(f);
                for (; na_ok(q, qrem); q = na_next(q, &qrem)) {
                    int arem = (int)q->nla_len - (int)NA_HDRLEN;
                    struct nlattr *x = (struct nlattr *)NA_DATA(q);
                    int has_freq = 0, disabled = 0;
                    for (; na_ok(x, arem); x = na_next(x, &arem)) {
                        if (NA_TYPE(x) == NL80211_FREQUENCY_ATTR_FREQ) has_freq = 1;
                        if (NA_TYPE(x) == NL80211_FREQUENCY_ATTR_DISABLED) disabled = 1;
                    }
                    if (has_freq && !disabled) *mask |= 1u << band;
                }
            }
        }
        return 1;
    }
    return 0;
}

/* One GET (never a dump, never NLM_F_ACK) and its one reply into rbuf.
 * The request carries no attribute but the wiphy index when `wiphy` is
 * not negative. Bytes received, or a negative errno. */
static long nl_get_once(int cmd, long wiphy, uint8_t *rbuf, size_t rsz, int *family) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return -errno;
    *family = get_nl80211_id(fd);
    if (*family < 0) { close(fd); return -EOPNOTSUPP; }
    struct timeval tv = { 0, 300000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t sbuf[NLMSG_HDRLEN + GENL_HDRLEN + 8];
    memset(sbuf, 0, sizeof(sbuf));
    struct nlmsghdr   *nlh = (struct nlmsghdr *)sbuf;
    struct genlmsghdr *gh  = (struct genlmsghdr *)NLMSG_DATA(nlh);
    size_t msz = NLMSG_HDRLEN + GENL_HDRLEN;
    if (wiphy >= 0) {
        struct nlattr *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
        na->nla_type = NL80211_ATTR_WIPHY;
        na->nla_len  = (uint16_t)(NA_HDRLEN + 4);
        uint32_t v = (uint32_t)wiphy;
        memcpy(NA_DATA(na), &v, 4);
        msz += 8;
    }
    nlh->nlmsg_len   = (uint32_t)msz;
    nlh->nlmsg_type  = (uint16_t)*family;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = 5;
    gh->cmd          = (uint8_t)cmd;
    gh->version      = 1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, sbuf, msz, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    ssize_t r = recv(fd, rbuf, rsz, 0);
    int e = errno;
    close(fd);
    return r < 0 ? -e : (long)r;
}

int linux_wifi_get_reg(char alpha2[3]) {
    static uint8_t rbuf[8192];
    int family = -1;
    long r = nl_get_once(NL80211_CMD_GET_REG, -1, rbuf, sizeof(rbuf), &family);
    if (r < 0) return (int)r;
    return linux_wifi_parse_reg(rbuf, (size_t)r, family, alpha2);
}

int linux_wifi_phy_iftypes(int phy_index, unsigned *mask) {
    static uint8_t rbuf[32768];
    int family = -1;
    if (phy_index < 0) return -EINVAL;
    long r = nl_get_once(NL80211_CMD_GET_WIPHY, phy_index, rbuf, sizeof(rbuf), &family);
    if (r < 0) return (int)r;
    return linux_wifi_parse_iftypes(rbuf, (size_t)r, family, mask);
}

int linux_wifi_phy_bands(int phy_index, unsigned *mask) {
    /* A wiphy with every band and its frequencies is the largest GET
     * reply there is; a 6 GHz radio lists about 60 more frequencies. */
    static uint8_t rbuf[65536];
    int family = -1;
    if (phy_index < 0) return -EINVAL;
    long r = nl_get_once(NL80211_CMD_GET_WIPHY, phy_index, rbuf, sizeof(rbuf), &family);
    if (r < 0) return (int)r;
    return linux_wifi_parse_bands(rbuf, (size_t)r, family, mask);
}

int linux_wifi_iface_bands(const char *iface, unsigned *mask) {
    if (mask) *mask = 0;
    if (!iface || !iface[0] || strlen(iface) >= IFNAMSIZ || strchr(iface, '/') || !mask)
        return -EINVAL;
    char path[96], b[16];
    snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211/index", iface);
    FILE *f = fopen(path, "r");
    if (!f) return -ENODEV;
    char *ok = fgets(b, sizeof(b), f);
    fclose(f);
    char *end = NULL;
    long idx = ok ? strtol(b, &end, 10) : -1;
    if (!ok || end == b || idx < 0 || idx > 1000000) return -ENODEV;
    return linux_wifi_phy_bands((int)idx, mask);
}

#endif /* WITH_WIFI */
#endif /* PLATFORM_LINUX */
