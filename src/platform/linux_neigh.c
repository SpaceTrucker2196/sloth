#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#include "platform/linux_neigh.h"

/* States with a usable link-layer address. NUD_INCOMPLETE and
 * NUD_FAILED have none (the all-zero rows /proc/net/arp shows and the
 * IPv4 reader skips); NUD_NOARP is a pseudo-entry for a link that does
 * not resolve (loopback, point-to-point), not a neighbour. */
#define NEIGH_RESOLVED (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT)

int linux_neigh_parse(const void *buf, size_t len, arp_entry_t *out, int max,
                      int n, int *done, linux_ifname_fn ifname) {
    const struct nlmsghdr *nlh = buf;
    uint32_t rem = len > 0xffffffffu ? 0xffffffffu : (uint32_t)len;
    for (; NLMSG_OK(nlh, rem); nlh = NLMSG_NEXT(nlh, rem)) {
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            if (done) *done = 1;
            return n;
        }
        if (nlh->nlmsg_type != RTM_NEWNEIGH) continue;
        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ndmsg))) continue;
        const struct ndmsg *nd = NLMSG_DATA(nlh);
        if (nd->ndm_family != AF_INET6) continue;
        if (!(nd->ndm_state & NEIGH_RESOLVED)) continue;
        /* A proxy entry is an address this host answers for, not a
         * neighbour it has resolved. */
        if (nd->ndm_flags & NTF_PROXY) continue;

        const uint8_t *dst = NULL, *lladdr = NULL;
        int alen = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg)));
        const struct rtattr *rta = (const struct rtattr *)
            ((const char *)nd + NLMSG_ALIGN(sizeof(struct ndmsg)));
        for (; RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen)) {
            if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == 16)
                dst = RTA_DATA(rta);
            else if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6)
                lladdr = RTA_DATA(rta);
        }
        if (!dst || !lladdr) continue;
        static const uint8_t zero[6];
        if (memcmp(lladdr, zero, 6) == 0) continue;
        if (n >= max) return n;

        arp_entry_t *e = &out[n];
        memset(e, 0, sizeof(*e));
        if (!inet_ntop(AF_INET6, dst, e->ip, sizeof(e->ip))) continue;
        memcpy(e->mac, lladdr, 6);
        if (!ifname || ifname(nd->ndm_ifindex, e->iface, sizeof(e->iface)) != 0)
            e->iface[0] = '\0';
        n++;
    }
    return n;
}

static int kernel_ifname(int ifindex, char *out, size_t outsz) {
    char name[IF_NAMESIZE];
    if (ifindex <= 0 || !if_indextoname((unsigned)ifindex, name)) return -1;
    snprintf(out, outsz, "%s", name);
    return 0;
}

int linux_neigh6_fill(arp_entry_t *out, int max, int n) {
    if (n >= max) return n;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return n;

    struct {
        struct nlmsghdr nlh;
        struct ndmsg    nd;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type  = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.nd.ndm_family   = AF_INET6;
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) { close(fd); return n; }

    /* One recv() per netlink page; a dump of a large cache spans
     * several, each ending the loop only on NLMSG_DONE. */
    static char buf[32768];
    int done = 0;
    while (!done && n < max) {
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got <= 0) break;
        n = linux_neigh_parse(buf, (size_t)got, out, max, n, &done, kernel_ifname);
    }
    close(fd);
    return n;
}

#endif /* PLATFORM_LINUX */
