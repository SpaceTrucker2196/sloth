#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>

#include "sloth.h"
#include "sys_status.h"
#include "platform/linux_self.h"
#include "platform/linux_wifi.h"

int linux_self_append(uint8_t (*out)[6], int max, int n, const uint8_t mac[6]) {
    static const uint8_t zero[6];
    if (!out || !mac || n >= max) return n;
    /* The same two rejections ownership_self_add() makes, applied here
     * too so an all-zero loopback or a broadcast attribute does not
     * spend a slot of a bounded buffer. */
    if (memcmp(mac, zero, 6) == 0 || (mac[0] & 0x01)) return n;
    for (int i = 0; i < n; i++)
        if (memcmp(out[i], mac, 6) == 0) return n;
    memcpy(out[n], mac, 6);
    return n + 1;
}

int linux_self_parse_mac(const char *s, uint8_t mac[6]) {
    unsigned v[6];
    int used = 0;
    if (!s) return -1;
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%n",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &used) != 6)
        return -1;
    /* "aa:bb:cc:dd:ee:ff0" is not an address, it is a longer token. */
    if (s[used] != '\0' && s[used] != '\n' && s[used] != ' ' &&
        s[used] != '\r' && s[used] != '\t')
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

int linux_self_parse_links(const void *buf, size_t len, uint8_t (*out)[6],
                           int max, int n, int *done) {
    const struct nlmsghdr *nlh = buf;
    uint32_t rem = len > 0xffffffffu ? 0xffffffffu : (uint32_t)len;
    if (!buf) return n;
    for (; NLMSG_OK(nlh, rem); nlh = NLMSG_NEXT(nlh, rem)) {
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            if (done) *done = 1;
            return n;
        }
        if (nlh->nlmsg_type != RTM_NEWLINK) continue;
        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) continue;
        const struct ifinfomsg *ifi = NLMSG_DATA(nlh);
        int alen = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
        const struct rtattr *rta = (const struct rtattr *)
            ((const char *)ifi + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        for (; RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen)) {
            /* IFLA_BROADCAST is deliberately not read: it is the
             * link's broadcast address, never one the host sends from. */
            if ((rta->rta_type == IFLA_ADDRESS ||
                 rta->rta_type == IFLA_PERM_ADDRESS) &&
                RTA_PAYLOAD(rta) == 6)
                n = linux_self_append(out, max, n, RTA_DATA(rta));
        }
    }
    return n;
}

/* A phy name from the lister becomes a path component; anything that
 * is not one ("..", a slash) is skipped rather than followed. */
static int phy_name_ok(const char *s) {
    if (!s[0] || s[0] == '.') return 0;
    for (; *s; s++)
        if (*s == '/') return 0;
    return 1;
}

int linux_self_phy_macs(linux_self_read_fn rd, linux_self_list_fn ls,
                        uint8_t (*out)[6], int max, int n) {
    enum { PHY_MAX = 16, PHY_NAME = 32 };
    char names[PHY_MAX * PHY_NAME];
    if (!rd || !ls) return n;
    int np = ls("/sys/class/ieee80211", names, PHY_NAME, PHY_MAX);
    for (int p = 0; p < np && n < max; p++) {
        const char *phy = names + (size_t)p * PHY_NAME;
        if (!phy_name_ok(phy)) continue;
        static const char *const files[] = { "macaddress", "addresses" };
        for (size_t f = 0; f < sizeof(files) / sizeof(files[0]); f++) {
            char path[96], text[1024];
            snprintf(path, sizeof(path), "/sys/class/ieee80211/%.31s/%s",
                     phy, files[f]);
            int got = rd(path, text, (int)sizeof(text) - 1);
            if (got <= 0) continue;
            text[got] = '\0';
            /* One address per line; a short read may cut the last one,
             * which then fails to parse rather than parsing wrong. */
            char *save = NULL;
            for (char *line = strtok_r(text, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                uint8_t mac[6];
                if (linux_self_parse_mac(line, mac) == 0)
                    n = linux_self_append(out, max, n, mac);
            }
        }
    }
    return n;
}

static int links_fill(uint8_t (*out)[6], int max, int n) {
    if (n >= max) return n;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return n;
    /* A dump that never ends must not wedge the poll loop. */
    struct timeval tv = { 0, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
        struct rtattr    ext;
        uint32_t         ext_mask;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = (uint32_t)sizeof(req);
    req.nlh.nlmsg_type  = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.ifi.ifi_family  = AF_UNSPEC;
    /* Only the addresses are wanted: without this each message also
     * carries two copies of the interface counters. A kernel that does
     * not know the flag ignores it. */
    req.ext.rta_type    = IFLA_EXT_MASK;
    req.ext.rta_len     = (unsigned short)RTA_LENGTH(sizeof(uint32_t));
    req.ext_mask        = RTEXT_FILTER_SKIP_STATS;
    if (send(fd, &req, sizeof(req), 0) < 0) { close(fd); return n; }

    static char buf[32768];
    int done = 0;
    while (!done) {
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got <= 0) break;
        n = linux_self_parse_links(buf, (size_t)got, out, max, n, &done);
    }
    close(fd);
    return n;
}

int linux_get_self_macs(uint8_t (*out)[6], int max) {
    int n = 0;
    if (!out || max <= 0) return 0;
    n = links_fill(out, max, n);
    n = linux_self_phy_macs(sys_io_read_file, sys_io_list_dir, out, max, n);
    n = linux_wifi_get_wdev_macs(out, max, n);
    return n;
}

#endif /* PLATFORM_LINUX */
