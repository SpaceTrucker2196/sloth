#ifdef PLATFORM_LINUX
#ifdef WITH_WIFI

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>

#include "ntop.h"
#include "platform/linux_wifi.h"

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
    fgets(line, sizeof(line), f);  /* header 1 */
    fgets(line, sizeof(line), f);  /* header 2 */
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

/* ── Frequency → channel number ──────────────────────────── */

static int freq_to_channel(uint32_t mhz) {
    if (mhz >= 2412 && mhz <= 2472) return (int)(mhz - 2407) / 5;
    if (mhz == 2484)                 return 14;
    if (mhz >= 5180 && mhz <= 5900) return (int)(mhz - 5000) / 5;
    if (mhz >= 5955 && mhz <= 7115) return (int)(mhz - 5950) / 5;
    return 0;
}

/* ── 802.11 IE parser: SSID + encryption ─────────────────── */

static void parse_ies(const uint8_t *ies, int len, uint16_t cap,
                      char *ssid, char *enc) {
    int has_rsn = 0, has_wpa = 0;
    ssid[0] = '\0';

    for (int i = 0; i + 2 <= len; ) {
        uint8_t tag  = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) break;

        if (tag == 0 && ssid[0] == '\0') {
            /* SSID (empty = hidden network) */
            int sl = elen > 32 ? 32 : elen;
            if (sl > 0) { memcpy(ssid, &ies[i + 2], sl); ssid[sl] = '\0'; }
            else          memcpy(ssid, "<hidden>", 9);
        } else if (tag == 48) {
            /* RSN IE → WPA2/WPA3 */
            has_rsn = 1;
        } else if (tag == 221 && elen >= 4
                   && ies[i+2] == 0x00 && ies[i+3] == 0x50
                   && ies[i+4] == 0xf2 && ies[i+5] == 0x01) {
            /* WPA vendor IE (Microsoft OUI, type 0x01) */
            has_wpa = 1;
        }
        i += 2 + elen;
    }

    if (ssid[0] == '\0') memcpy(ssid, "<hidden>", 9);

    if      (has_rsn)     memcpy(enc, "WPA2", 5);
    else if (has_wpa)     memcpy(enc, "WPA",  4);
    else if (cap & 0x10)  memcpy(enc, "WEP",  4);  /* Privacy bit */
    else                  memcpy(enc, "Open", 5);
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
        ap->channel    = freq_to_channel(freq);

        if (ies && ies_len > 0)
            parse_ies(ies, ies_len, cap, ap->ssid, ap->enc);
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

        /* build NL80211_CMD_GET_SCAN dump request */
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
        nlh->nlmsg_seq   = 2;
        gh->cmd          = NL80211_CMD_GET_SCAN;
        na->nla_type     = NL80211_ATTR_IFINDEX;
        na->nla_len      = (uint16_t)(NA_HDRLEN + sizeof(uint32_t));
        *(uint32_t *)NA_DATA(na) = ifidx;

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

#endif /* WITH_WIFI */
#endif /* PLATFORM_LINUX */
